//! Read-only observation of stock `sol_alt_bn128_group_op` calls.
//!
//! This callback inspects LiteSVM's SBPF register trace. It never registers,
//! wraps, replaces, or reprices Agave's stock syscall.

use {
    litesvm::{InvocationInspectCallback, LiteSVM},
    serde::{Deserialize, Serialize},
    solana_program_runtime::{
        invoke_context::{Executable, InvokeContext, RegisterTrace},
        solana_sbpf::ebpf,
    },
    solana_transaction::sanitized::SanitizedTransaction,
    solana_transaction_context::{IndexOfAccount, InstructionContext},
    std::sync::{Arc, Mutex},
};

pub const GROUP_OP_SYSCALL: &str = "sol_alt_bn128_group_op";
pub const MAX_GROUP_OP_EVENTS: usize = 1_024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupOpKind {
    G1Add,
    G1Mul,
    Pairing,
}

impl GroupOpKind {
    pub fn from_raw(value: u64) -> Option<Self> {
        match value {
            0 => Some(Self::G1Add),
            2 => Some(Self::G1Mul),
            3 => Some(Self::Pairing),
            _ => None,
        }
    }

    fn expected_input_size(self, raw_input_size: u64) -> bool {
        match self {
            Self::G1Add => raw_input_size == 128,
            Self::G1Mul => raw_input_size == 96,
            Self::Pairing => raw_input_size > 0 && raw_input_size.is_multiple_of(192),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StockGroupOpEvent {
    pub program_id: String,
    pub instruction_trace_index: usize,
    pub vm_pc: u64,
    pub opcode: u8,
    pub instruction_immediate: i64,
    pub canonical_syscall_hash: u32,
    pub static_syscalls: bool,
    pub group_op: u64,
    pub kind: GroupOpKind,
    pub input_addr: u64,
    pub input_size: u64,
    pub result_addr: u64,
    pub pairing_elements: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct StockGroupOpObservation {
    pub tracing_enabled: bool,
    pub vm_trace_count: usize,
    pub events: Vec<StockGroupOpEvent>,
    pub errors: Vec<String>,
}

impl StockGroupOpObservation {
    pub fn require_valid_count(&self, expected_vm_traces: usize) -> Result<(), String> {
        if !self.tracing_enabled {
            return Err("LiteSVM register tracing was not enabled".to_owned());
        }
        if expected_vm_traces == 0 {
            return Err("expected VM trace count must be nonzero".to_owned());
        }
        if self.vm_trace_count != expected_vm_traces {
            return Err(format!(
                "expected exactly {expected_vm_traces} loaded-program VM trace(s), observed {}",
                self.vm_trace_count
            ));
        }
        if !self.errors.is_empty() {
            return Err(self.errors.join("; "));
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct StockGroupOpObserver {
    state: Arc<Mutex<StockGroupOpObservation>>,
}

impl StockGroupOpObserver {
    pub fn snapshot(&self) -> StockGroupOpObservation {
        self.state.lock().expect("observer mutex poisoned").clone()
    }

    pub fn reset(&self) {
        *self.state.lock().expect("observer mutex poisoned") = StockGroupOpObservation::default();
    }
}

fn matching_syscall_instruction(opcode: u8, immediate: i64, static_syscalls: bool) -> bool {
    let syscall_opcode = if static_syscalls {
        opcode == ebpf::SYSCALL
    } else {
        opcode == ebpf::CALL_IMM
    };
    syscall_opcode && immediate as u32 == ebpf::hash_symbol_name(GROUP_OP_SYSCALL.as_bytes())
}

fn decode_trace(
    instruction_context: InstructionContext<'_, '_>,
    executable: &Executable,
    register_trace: RegisterTrace<'_>,
    observation: &mut StockGroupOpObservation,
) {
    observation.vm_trace_count = observation.vm_trace_count.saturating_add(1);
    let program_id = match instruction_context.get_program_key() {
        Ok(program_id) => program_id.to_string(),
        Err(error) => {
            observation
                .errors
                .push(format!("cannot resolve traced program id: {error:?}"));
            return;
        }
    };
    let instruction_trace_index = instruction_context.get_index_in_trace();
    let (_, text) = executable.get_text_bytes();
    let static_syscalls = executable.get_sbpf_version().static_syscalls();
    let canonical_syscall_hash = ebpf::hash_symbol_name(GROUP_OP_SYSCALL.as_bytes());

    for registers in register_trace {
        let vm_pc = registers[11];
        let Some(byte_offset) = usize::try_from(vm_pc)
            .ok()
            .and_then(|pc| pc.checked_mul(ebpf::INSN_SIZE))
        else {
            observation
                .errors
                .push(format!("program {program_id}: VM PC {vm_pc} overflows"));
            continue;
        };
        if byte_offset.saturating_add(ebpf::INSN_SIZE) > text.len() {
            observation.errors.push(format!(
                "program {program_id}: VM PC {vm_pc} is outside text section"
            ));
            continue;
        }

        let instruction = ebpf::get_insn_unchecked(text, vm_pc as usize);
        if !matching_syscall_instruction(instruction.opc, instruction.imm, static_syscalls) {
            continue;
        }
        if observation.events.len() >= MAX_GROUP_OP_EVENTS {
            observation.errors.push(format!(
                "canonical group-op event count exceeds hard limit {MAX_GROUP_OP_EVENTS}"
            ));
            return;
        }

        let group_op = registers[1];
        let Some(kind) = GroupOpKind::from_raw(group_op) else {
            observation.errors.push(format!(
                "program {program_id} PC {vm_pc}: unsupported group-op selector {group_op}"
            ));
            continue;
        };
        let input_size = registers[3];
        if !kind.expected_input_size(input_size) {
            observation.errors.push(format!(
                "program {program_id} PC {vm_pc}: invalid {kind:?} input size {input_size}"
            ));
            continue;
        }
        observation.events.push(StockGroupOpEvent {
            program_id: program_id.clone(),
            instruction_trace_index,
            vm_pc,
            opcode: instruction.opc,
            instruction_immediate: instruction.imm,
            canonical_syscall_hash,
            static_syscalls,
            group_op,
            kind,
            input_addr: registers[2],
            input_size,
            result_addr: registers[4],
            pairing_elements: (kind == GroupOpKind::Pairing).then_some(input_size / 192),
        });
    }
}

impl InvocationInspectCallback for StockGroupOpObserver {
    fn before_invocation(
        &self,
        _svm: &LiteSVM,
        _tx: &SanitizedTransaction,
        _program_indices: &[IndexOfAccount],
        _invoke_context: &InvokeContext,
    ) {
        self.reset();
    }

    fn after_invocation(
        &self,
        _svm: &LiteSVM,
        invoke_context: &InvokeContext,
        register_tracing_enabled: bool,
    ) {
        {
            let mut observation = self.state.lock().expect("observer mutex poisoned");
            observation.tracing_enabled = register_tracing_enabled;
            if !register_tracing_enabled {
                observation
                    .errors
                    .push("callback ran without register tracing enabled".to_owned());
                return;
            }
        }
        let state = Arc::clone(&self.state);
        invoke_context.iterate_vm_traces(&|instruction_context, executable, register_trace| {
            let mut observation = state.lock().expect("observer mutex poisoned");
            decode_trace(
                instruction_context,
                executable,
                register_trace,
                &mut observation,
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_stock_group_op_shapes() {
        let hash = ebpf::hash_symbol_name(GROUP_OP_SYSCALL.as_bytes());
        assert!(matching_syscall_instruction(
            ebpf::CALL_IMM,
            i64::from(hash),
            false
        ));
        assert!(matching_syscall_instruction(
            ebpf::SYSCALL,
            i64::from(hash),
            true
        ));
        assert!(GroupOpKind::Pairing.expected_input_size(8 * 192));
        assert!(!GroupOpKind::Pairing.expected_input_size(193));
    }
}
