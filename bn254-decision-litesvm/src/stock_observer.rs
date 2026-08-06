//! Read-only observation of the stock `sol_alt_bn128_group_op`,
//! `sol_alt_bn128_compression` and hash syscalls.
//!
//! This callback inspects LiteSVM's SBPF register trace. It never registers,
//! wraps, replaces, or reprices Agave's stock syscalls. For the hash syscalls
//! it cannot: LiteSVM 0.12 builds its environment from
//! `create_program_runtime_environment_v1`, and sbpf's `register_function`
//! rejects a second entry under a name already taken, so `with_custom_syscall`
//! panics on `sol_keccak256` rather than replacing it.

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

pub const COMPRESSION_SYSCALL: &str = "sol_alt_bn128_compression";
pub const MAX_COMPRESSION_EVENTS: usize = 4_096;

/// Bit 7 of a compression selector picks the operand byte order. It changes
/// neither the operation nor the charge.
const COMPRESSION_LITTLE_ENDIAN_FLAG: u64 = 0x80;

/// Every syscall the runtime serves with `SyscallHash`. They share one charge
/// formula and one set of constants, so the campaign meters them as one class.
pub const HASH_SYSCALLS: [&str; 4] = ["sol_sha256", "sol_keccak256", "sol_blake3", "sol_sha512"];

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionOpKind {
    G1Compress,
    G1Decompress,
    G2Compress,
    G2Decompress,
}

impl CompressionOpKind {
    pub fn from_raw(value: u64) -> Option<Self> {
        match value & !COMPRESSION_LITTLE_ENDIAN_FLAG {
            0 => Some(Self::G1Compress),
            1 => Some(Self::G1Decompress),
            2 => Some(Self::G2Compress),
            3 => Some(Self::G2Decompress),
            _ => None,
        }
    }

    fn expected_input_size(self, raw_input_size: u64) -> bool {
        let expected = match self {
            Self::G1Compress => 64,
            Self::G1Decompress => 32,
            Self::G2Compress => 128,
            Self::G2Decompress => 64,
        };
        raw_input_size == expected
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressionEvent {
    pub program_id: String,
    pub instruction_trace_index: usize,
    pub vm_pc: u64,
    pub opcode: u8,
    pub instruction_immediate: i64,
    pub canonical_syscall_hash: u32,
    pub static_syscalls: bool,
    pub op: u64,
    pub kind: CompressionOpKind,
    pub input_addr: u64,
    pub input_size: u64,
    pub result_addr: u64,
}

/// One `SyscallHash` call as the register trace sees it.
///
/// The slice descriptors live in guest memory and the trace carries registers
/// only, so the per-slice byte lengths that set the charge are not here. They
/// are recovered from the metered difference between two runs whose
/// `sha256_byte_cost` differs; see `new_litesvm_charging_hash_bytes`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HashSyscallEvent {
    pub syscall: String,
    pub instruction_trace_index: usize,
    pub vm_pc: u64,
    pub slices: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct StockGroupOpObservation {
    pub tracing_enabled: bool,
    pub vm_trace_count: usize,
    pub events: Vec<StockGroupOpEvent>,
    pub compressions: Vec<CompressionEvent>,
    pub hash_syscalls: Vec<HashSyscallEvent>,
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
    is_syscall_to(opcode, immediate, static_syscalls, GROUP_OP_SYSCALL)
}

fn matching_compression_instruction(opcode: u8, immediate: i64, static_syscalls: bool) -> bool {
    is_syscall_to(opcode, immediate, static_syscalls, COMPRESSION_SYSCALL)
}

fn is_syscall_to(opcode: u8, immediate: i64, static_syscalls: bool, name: &str) -> bool {
    let syscall_opcode = if static_syscalls {
        opcode == ebpf::SYSCALL
    } else {
        opcode == ebpf::CALL_IMM
    };
    syscall_opcode && immediate as u32 == ebpf::hash_symbol_name(name.as_bytes())
}

fn hash_syscall_name(opcode: u8, immediate: i64, static_syscalls: bool) -> Option<&'static str> {
    HASH_SYSCALLS
        .into_iter()
        .find(|name| is_syscall_to(opcode, immediate, static_syscalls, name))
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
    let canonical_compression_hash = ebpf::hash_symbol_name(COMPRESSION_SYSCALL.as_bytes());

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
        if let Some(syscall) = hash_syscall_name(instruction.opc, instruction.imm, static_syscalls)
        {
            observation.hash_syscalls.push(HashSyscallEvent {
                syscall: syscall.to_owned(),
                instruction_trace_index,
                vm_pc,
                // r2, the slice count `SyscallHash` reads as `vals_len`.
                slices: registers[2],
            });
            continue;
        }
        if matching_compression_instruction(instruction.opc, instruction.imm, static_syscalls) {
            if observation.compressions.len() >= MAX_COMPRESSION_EVENTS {
                observation.errors.push(format!(
                    "compression event count exceeds hard limit {MAX_COMPRESSION_EVENTS}"
                ));
                return;
            }
            let op = registers[1];
            let Some(kind) = CompressionOpKind::from_raw(op) else {
                observation.errors.push(format!(
                    "program {program_id} PC {vm_pc}: unsupported compression selector {op}"
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
            observation.compressions.push(CompressionEvent {
                program_id: program_id.clone(),
                instruction_trace_index,
                vm_pc,
                opcode: instruction.opc,
                instruction_immediate: instruction.imm,
                canonical_syscall_hash: canonical_compression_hash,
                static_syscalls,
                op,
                kind,
                input_addr: registers[2],
                input_size,
                result_addr: registers[4],
            });
            continue;
        }
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

    #[test]
    fn recognizes_stock_compression_shapes() {
        let hash = ebpf::hash_symbol_name(COMPRESSION_SYSCALL.as_bytes());
        assert!(matching_compression_instruction(
            ebpf::CALL_IMM,
            i64::from(hash),
            false
        ));
        assert!(matching_compression_instruction(
            ebpf::SYSCALL,
            i64::from(hash),
            true
        ));
        assert_ne!(hash, ebpf::hash_symbol_name(GROUP_OP_SYSCALL.as_bytes()));
    }

    /// The selectors are the runtime's, and a wrong one silently observes no
    /// decompression at all.
    #[test]
    fn compression_selectors_match_the_runtime_encoding() {
        for (raw, kind) in [
            (0, CompressionOpKind::G1Compress),
            (1, CompressionOpKind::G1Decompress),
            (2, CompressionOpKind::G2Compress),
            (3, CompressionOpKind::G2Decompress),
        ] {
            assert_eq!(CompressionOpKind::from_raw(raw), Some(kind));
            assert_eq!(
                CompressionOpKind::from_raw(raw | COMPRESSION_LITTLE_ENDIAN_FLAG),
                Some(kind)
            );
        }
        assert_eq!(CompressionOpKind::from_raw(4), None);
        assert!(CompressionOpKind::G1Decompress.expected_input_size(32));
        assert!(CompressionOpKind::G2Decompress.expected_input_size(64));
        assert!(!CompressionOpKind::G2Decompress.expected_input_size(128));
    }
}
