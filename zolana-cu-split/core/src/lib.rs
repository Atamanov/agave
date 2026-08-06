//! Direct syscall-vs-sBPF attribution for a real zolana transaction.
//!
//! The sBPF interpreter charges exactly one compute unit per executed
//! instruction and charges syscalls separately from inside the syscall body,
//! so a full register trace of a transaction partitions its compute:
//! `total = executed_instructions + syscall_charges + fixed_runtime_overhead`.
//! Everything here rests on that identity, and [`Reconciliation`] reports the
//! residual instead of hiding it.
//!
//! The trace is taken through LiteSVM's `InvocationInspectCallback`, which
//! needs no change to the program or to the harness that boots it. Program
//! counters are resolved against the unstripped build of the same `.text`, so
//! per-function costs carry real names.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use litesvm::{InvocationInspectCallback, LiteSVM};
use solana_program_runtime::{
    invoke_context::{Executable, InvokeContext, RegisterTrace},
    solana_sbpf::ebpf,
};
use solana_transaction::sanitized::SanitizedTransaction;
use solana_transaction_context::{instruction::InstructionContext, IndexOfAccount};

pub mod elf;
pub mod report;

pub use elf::{FunctionMap, FunctionSymbol};

/// Name fragments that mark a function as BN254 verification work. A frame
/// matching one of these makes every instruction executed beneath it
/// BN254-adjacent, which is what "a syscall could absorb this" means here.
pub const BN254_ROOTS: &[&str] = &[
    "groth16_solana::",
    "ark_bn254",
    "ark_ff",
    "ark_ec",
    "ark_serialize",
    "ark_poly",
    "solana_bn254",
    "zolana_interface::verifying_keys",
];

pub fn is_bn254_name(name: &str) -> bool {
    BN254_ROOTS.iter().any(|root| name.contains(root))
}

/// One syscall dispatch, with the argument registers the VM held when the
/// `call` instruction was about to execute.
#[derive(Clone, Debug)]
pub struct SyscallEvent {
    pub name: String,
    pub pc: u64,
    /// r1..r5, the sBPF argument registers.
    pub args: [u64; 5],
    /// Innermost frame that issued the call.
    pub caller_entry_pc: u64,
    /// A BN254 frame was on the stack at the call.
    pub under_bn254_frame: bool,
}

/// Everything recorded for one program invocation (top level or CPI).
#[derive(Clone, Debug)]
pub struct InvocationTrace {
    pub program_id: [u8; 32],
    /// Virtual address the `.text` section is mapped at.
    pub text_vaddr: u64,
    pub sbpf_version: String,
    /// One entry per executed instruction; equals the invocation's sBPF CU.
    pub instructions: u64,
    /// Executed-instruction count keyed by program counter.
    pub pc_counts: BTreeMap<u64, u64>,
    pub syscalls: Vec<SyscallEvent>,
    /// Instructions attributed to the frame on top of the reconstructed call
    /// stack, keyed by that frame's entry pc.
    pub exclusive_by_entry: BTreeMap<u64, u64>,
    /// Instructions executed anywhere in a frame's dynamic extent, keyed by
    /// its entry pc. Callers and callees both see the cost, so these do not
    /// sum to the total.
    pub inclusive_by_entry: BTreeMap<u64, u64>,
    /// Instructions executed with at least one BN254 frame on the stack.
    /// Zero when the collector was built without a symbol map.
    pub bn254_subtree_instructions: u64,
    pub max_stack_depth: usize,
    /// The r10 walk exceeded the VM's call-depth limit, which invalidates the
    /// stack-derived columns but not `pc_counts`.
    pub stack_reconstruction_failed: bool,
}

/// Collects register traces for every transaction sent through the SVM.
#[derive(Clone, Default)]
pub struct TraceCollector {
    inner: Arc<Mutex<Vec<Vec<InvocationTrace>>>>,
    symbols: Option<Arc<FunctionMap>>,
}

impl TraceCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the symbol map for the program under measurement so the
    /// collector can mark BN254 frames while it walks the trace.
    pub fn with_symbols(symbols: FunctionMap) -> Self {
        Self {
            inner: Arc::default(),
            symbols: Some(Arc::new(symbols)),
        }
    }

    /// Traces of the most recent transaction that executed any program.
    pub fn last(&self) -> Option<Vec<InvocationTrace>> {
        self.inner.lock().unwrap().last().cloned()
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }

    /// Install on a debuggable SVM, replacing the file-writing default.
    pub fn install(&self, svm: &mut LiteSVM) {
        svm.set_invocation_inspect_callback(self.clone());
    }
}

impl InvocationInspectCallback for TraceCollector {
    fn before_invocation(
        &self,
        _svm: &LiteSVM,
        _tx: &SanitizedTransaction,
        _program_indices: &[IndexOfAccount],
        _invoke_context: &mut InvokeContext,
        _register_tracing_enabled: bool,
    ) {
    }

    fn after_invocation(
        &self,
        _svm: &LiteSVM,
        _tx: &SanitizedTransaction,
        _program_indices: &[IndexOfAccount],
        invoke_context: &InvokeContext,
        register_tracing_enabled: bool,
    ) {
        if !register_tracing_enabled {
            return;
        }
        let symbols = self.symbols.clone();
        let collected = Mutex::new(Vec::new());
        invoke_context.iterate_vm_traces(
            &|instruction_context: InstructionContext,
              executable: &Executable,
              register_trace: RegisterTrace| {
                if let Some(trace) = digest(
                    &instruction_context,
                    executable,
                    register_trace,
                    symbols.as_deref(),
                ) {
                    collected.lock().unwrap().push(trace);
                }
            },
        );
        let collected = collected.into_inner().unwrap();
        if !collected.is_empty() {
            self.inner.lock().unwrap().push(collected);
        }
    }
}

/// One live sBPF frame during the stack walk.
struct Frame {
    frame_pointer: u64,
    entry_pc: u64,
    is_bn254: bool,
}

fn digest(
    instruction_context: &InstructionContext,
    executable: &Executable,
    register_trace: RegisterTrace,
    symbols: Option<&FunctionMap>,
) -> Option<InvocationTrace> {
    let program_id = instruction_context.get_program_key().ok()?.to_bytes();
    let (text_vaddr, text) = executable.get_text_bytes();
    let sbpf_version = executable.get_sbpf_version();
    let static_syscalls = sbpf_version.static_syscalls();
    let loader_registry = executable.get_loader().get_function_registry();

    let mut trace = InvocationTrace {
        program_id,
        text_vaddr,
        sbpf_version: format!("{sbpf_version:?}"),
        instructions: register_trace.len() as u64,
        pc_counts: BTreeMap::new(),
        syscalls: Vec::new(),
        exclusive_by_entry: BTreeMap::new(),
        inclusive_by_entry: BTreeMap::new(),
        bn254_subtree_instructions: 0,
        max_stack_depth: 0,
        stack_reconstruction_failed: false,
    };

    let classify = |pc: u64| -> bool {
        symbols
            .and_then(|map| map.lookup(pc))
            .is_some_and(|symbol| is_bn254_name(&symbol.name))
    };

    let mut stack: Vec<Frame> = Vec::new();
    let mut bn254_depth = 0usize;
    // sBPF v0 bumps r10 upward on call; v1 and v2 leave the bump to the callee,
    // which moves it down. The first frame-pointer change in a trace is always
    // a call, because nothing can return past the entry frame, so the sign of
    // that change calibrates the direction without hard-coding a version.
    let mut call_raises_frame_pointer: Option<bool> = None;

    for regs in register_trace.iter() {
        let pc = regs[11];
        *trace.pc_counts.entry(pc).or_insert(0) += 1;

        let frame_pointer = regs[10];
        if stack.is_empty() {
            let is_bn254 = classify(pc);
            bn254_depth += usize::from(is_bn254);
            stack.push(Frame {
                frame_pointer,
                entry_pc: pc,
                is_bn254,
            });
        } else {
            let top = stack[stack.len() - 1].frame_pointer;
            if frame_pointer != top {
                let raises = *call_raises_frame_pointer.get_or_insert(frame_pointer > top);
                let deeper = |inner: u64, outer: u64| {
                    if raises {
                        inner > outer
                    } else {
                        inner < outer
                    }
                };
                if deeper(frame_pointer, top) {
                    let is_bn254 = classify(pc);
                    bn254_depth += usize::from(is_bn254);
                    stack.push(Frame {
                        frame_pointer,
                        entry_pc: pc,
                        is_bn254,
                    });
                } else {
                    while stack.len() > 1
                        && deeper(stack[stack.len() - 1].frame_pointer, frame_pointer)
                    {
                        let popped = stack.pop().expect("length checked");
                        bn254_depth -= usize::from(popped.is_bn254);
                    }
                }
            }
        }
        trace.max_stack_depth = trace.max_stack_depth.max(stack.len());
        if stack.len() > 64 {
            trace.stack_reconstruction_failed = true;
        }

        let top = stack.last().expect("stack is non-empty");
        let top_entry = top.entry_pc;
        *trace.exclusive_by_entry.entry(top_entry).or_insert(0) += 1;
        for frame in stack.iter() {
            *trace.inclusive_by_entry.entry(frame.entry_pc).or_insert(0) += 1;
        }
        if bn254_depth > 0 {
            trace.bn254_subtree_instructions += 1;
        }

        let offset = pc as usize * ebpf::INSN_SIZE;
        if offset + ebpf::INSN_SIZE > text.len() {
            continue;
        }
        let insn = ebpf::get_insn_unchecked(text, pc as usize);
        if insn.opc != ebpf::CALL_IMM || (static_syscalls && insn.src != 0) {
            continue;
        }
        let Some((name, _)) = loader_registry.lookup_by_key(insn.imm as u32) else {
            continue;
        };
        trace.syscalls.push(SyscallEvent {
            name: String::from_utf8_lossy(name).into_owned(),
            pc,
            args: [regs[1], regs[2], regs[3], regs[4], regs[5]],
            caller_entry_pc: top_entry,
            under_bn254_frame: bn254_depth > 0,
        });
    }

    Some(trace)
}

/// Charge of a BN254 syscall, or `None` when the syscall is not BN254 work.
/// Drivers supply this because the price of a custom syscall belongs to the
/// shim that charges it, not to a model kept here.
pub type SyscallPricer = fn(&SyscallEvent) -> Option<u64>;

/// Prices the two BN254 syscalls a stock validator exposes.
pub fn stock_bn254_pricer(event: &SyscallEvent) -> Option<u64> {
    match event.name.as_str() {
        "sol_alt_bn128_group_op" => Some(stock_group_op_cu(event.args[0], event.args[2])),
        "sol_alt_bn128_compression" => Some(stock_compression_cu(event.args[0])),
        _ => None,
    }
}

/// Agave 4.1 `SVMTransactionExecutionCost` defaults, which are what the
/// crates.io `solana-syscalls` LiteSVM links charges.
pub const SYSCALL_BASE_CU: u64 = 100;
pub const SHA256_BASE_CU: u64 = 85;
pub const MEM_OP_BASE_CU: u64 = 10;
pub const CPI_BYTES_PER_UNIT: u64 = 250;
pub const POSEIDON_COEFFICIENT_A: u64 = 61;
pub const POSEIDON_COEFFICIENT_C: u64 = 542;
pub const GROUP_OP_G1_ADD_CU: u64 = 334;
pub const GROUP_OP_G2_ADD_CU: u64 = 535;
pub const GROUP_OP_G1_MUL_CU: u64 = 3_840;
pub const GROUP_OP_G2_MUL_CU: u64 = 15_670;
pub const GROUP_OP_PAIRING_ONE_PAIR_CU: u64 = 36_364;
pub const GROUP_OP_PAIRING_PER_EXTRA_PAIR_CU: u64 = 12_121;
pub const PAIRING_ELEMENT_BYTES: u64 = 192;
pub const PAIRING_OUTPUT_BYTES: u64 = 32;
pub const COMPRESSION_G1_CU: u64 = 30;
pub const COMPRESSION_G2_CU: u64 = 86;
pub const DECOMPRESSION_G1_CU: u64 = 398;
pub const DECOMPRESSION_G2_CU: u64 = 13_610;

/// `op` is r1 and `input_size` is r3. The low seven bits select the operation;
/// bit 7 is the SIMD-0284 little-endian flag and does not change the price.
pub fn stock_group_op_cu(op: u64, input_size: u64) -> u64 {
    const LE_FLAG: u64 = 0x80;
    match op & !LE_FLAG {
        0 | 1 => GROUP_OP_G1_ADD_CU,
        2 => GROUP_OP_G1_MUL_CU,
        3 => {
            let pairs = input_size / PAIRING_ELEMENT_BYTES;
            GROUP_OP_PAIRING_ONE_PAIR_CU
                + GROUP_OP_PAIRING_PER_EXTRA_PAIR_CU * pairs.saturating_sub(1)
                + SHA256_BASE_CU
                + input_size
                + PAIRING_OUTPUT_BYTES
        }
        4 | 5 => GROUP_OP_G2_ADD_CU,
        6 => GROUP_OP_G2_MUL_CU,
        _ => 0,
    }
}

/// `op` is r1: 0 g1 compress, 1 g1 decompress, 2 g2 compress, 3 g2 decompress,
/// with bit 7 the little-endian flag.
pub fn stock_compression_cu(op: u64) -> u64 {
    const LE_FLAG: u64 = 0x80;
    let variable = match op & !LE_FLAG {
        0 => COMPRESSION_G1_CU,
        1 => DECOMPRESSION_G1_CU,
        2 => COMPRESSION_G2_CU,
        3 => DECOMPRESSION_G2_CU,
        _ => return 0,
    };
    SYSCALL_BASE_CU + variable
}

/// Prices the non-BN254 syscalls whose charge is fully determined by argument
/// registers. `sol_sha256` and `sol_keccak256` are absent because their price
/// depends on slice lengths held in guest memory, which a register trace does
/// not carry; they stay in the reconciliation residual.
pub fn other_syscall_cu(event: &SyscallEvent) -> Option<u64> {
    match event.name.as_str() {
        "sol_poseidon" => Some(poseidon_cu(poseidon_arity(event)?)),
        "sol_memcpy_" | "sol_memmove_" | "sol_memset_" | "sol_memcmp_" => {
            Some(MEM_OP_BASE_CU.max(event.args[2] / CPI_BYTES_PER_UNIT))
        }
        _ => None,
    }
}

/// `sol_poseidon(parameters, endianness, vals_addr, vals_len, result_addr)`.
/// The charge is quadratic in `vals_len`, which sits in r4 and is therefore
/// measured, not assumed.
pub fn poseidon_arity(event: &SyscallEvent) -> Option<u64> {
    (event.name == "sol_poseidon").then_some(event.args[3])
}

pub fn poseidon_cu(arity: u64) -> u64 {
    POSEIDON_COEFFICIENT_A * arity * arity + POSEIDON_COEFFICIENT_C
}

/// Poseidon is a priced syscall like the BN254 ones but a different family, so
/// it gets its own line rather than being folded into program work.
#[derive(Clone, Debug, Default)]
pub struct PoseidonSummary {
    pub calls: u64,
    pub total_cu: u64,
    /// Call count keyed by input arity.
    pub by_arity: BTreeMap<u64, u64>,
}

pub fn poseidon_summary(traces: &[InvocationTrace]) -> PoseidonSummary {
    let mut summary = PoseidonSummary::default();
    for event in traces.iter().flat_map(|trace| trace.syscalls.iter()) {
        let Some(arity) = poseidon_arity(event) else {
            continue;
        };
        summary.calls += 1;
        summary.total_cu += poseidon_cu(arity);
        *summary.by_arity.entry(arity).or_insert(0) += 1;
    }
    summary
}

/// BN254 syscall CU across every invocation of one transaction, with a
/// per-name (count, CU) breakdown.
pub fn bn254_syscall_total(
    traces: &[InvocationTrace],
    pricer: SyscallPricer,
) -> (u64, BTreeMap<String, (u64, u64)>) {
    let mut total = 0u64;
    let mut by_name: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for event in traces.iter().flat_map(|trace| trace.syscalls.iter()) {
        if let Some(cu) = pricer(event) {
            total += cu;
            let slot = by_name.entry(event.name.clone()).or_insert((0, 0));
            slot.0 += 1;
            slot.1 += cu;
        }
    }
    (total, by_name)
}

pub fn other_syscall_counts(
    traces: &[InvocationTrace],
    pricer: SyscallPricer,
) -> BTreeMap<String, u64> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for event in traces.iter().flat_map(|trace| trace.syscalls.iter()) {
        if pricer(event).is_none() {
            *counts.entry(event.name.clone()).or_insert(0) += 1;
        }
    }
    counts
}

/// The identity the whole measurement rests on, stated so the residual stays
/// visible instead of being absorbed into a bucket.
#[derive(Clone, Debug)]
pub struct Reconciliation {
    pub transaction_cu: u64,
    pub sbpf_instructions: u64,
    pub bn254_syscall_cu: u64,
    /// `transaction_cu - sbpf_instructions - bn254_syscall_cu`. Holds every
    /// non-BN254 syscall charge plus any fixed per-instruction runtime cost.
    pub residual_cu: i64,
}

pub fn reconcile(
    transaction_cu: u64,
    traces: &[InvocationTrace],
    pricer: SyscallPricer,
) -> Reconciliation {
    let sbpf_instructions: u64 = traces.iter().map(|trace| trace.instructions).sum();
    let (bn254_syscall_cu, _) = bn254_syscall_total(traces, pricer);
    Reconciliation {
        transaction_cu,
        sbpf_instructions,
        bn254_syscall_cu,
        residual_cu: transaction_cu as i64 - sbpf_instructions as i64 - bn254_syscall_cu as i64,
    }
}
