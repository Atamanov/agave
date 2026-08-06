//! Which function a syscall was issued from, inclusive of the whole call stack.
//!
//! `zolana-cu-split-core` records only the innermost frame, which inlining
//! turns into the hash helper rather than the caller that wanted the hash. A
//! Poseidon call attributed to `Poseidon::hashv` says nothing about whether the
//! program hashed a tree leaf or compressed a public input, so this collector
//! keeps the whole stack and counts a call against every frame on it.
//!
//! Same frame-pointer walk as the core collector, on the same register trace.
//! Callers and callees both see a call, so these counts do not sum to the
//! total; read them as "calls issued anywhere beneath this frame".

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
use zolana_cu_split_core::FunctionMap;

/// Syscall counts and, for Poseidon, input arities, keyed by enclosing frame.
#[derive(Clone, Debug, Default)]
pub struct Attribution {
    /// Poseidon calls issued anywhere beneath a frame, keyed by function name.
    pub poseidon_by_frame: BTreeMap<String, u64>,
    /// Poseidon call count keyed by the arity in r4.
    pub poseidon_by_arity: BTreeMap<u64, u64>,
    pub poseidon_calls: u64,
}

#[derive(Clone)]
pub struct StackCollector {
    inner: Arc<Mutex<Vec<Attribution>>>,
    symbols: Arc<FunctionMap>,
}

impl StackCollector {
    pub fn new(symbols: FunctionMap) -> Self {
        Self {
            inner: Arc::default(),
            symbols: Arc::new(symbols),
        }
    }

    pub fn install(&self, svm: &mut LiteSVM) {
        svm.set_invocation_inspect_callback(self.clone());
    }

    /// Attribution of the most recent transaction, summed over its invocations.
    pub fn last(&self) -> Option<Attribution> {
        self.inner.lock().unwrap().last().cloned()
    }
}

impl InvocationInspectCallback for StackCollector {
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
        let attribution = Mutex::new(Attribution::default());
        invoke_context.iterate_vm_traces(
            &|_instruction_context: InstructionContext,
              executable: &Executable,
              register_trace: RegisterTrace| {
                let mut slot = attribution.lock().unwrap();
                walk(executable, register_trace, &self.symbols, &mut slot);
            },
        );
        self.inner
            .lock()
            .unwrap()
            .push(attribution.into_inner().unwrap());
    }
}

fn walk(
    executable: &Executable,
    register_trace: RegisterTrace,
    symbols: &FunctionMap,
    out: &mut Attribution,
) {
    let (_text_vaddr, text) = executable.get_text_bytes();
    let sbpf_version = executable.get_sbpf_version();
    let static_syscalls = sbpf_version.static_syscalls();
    let loader_registry = executable.get_loader().get_function_registry();

    let mut stack: Vec<(u64, u64)> = Vec::new();
    // sBPF v0 bumps r10 upward on call; v1 and v2 leave the bump to the callee.
    // The first frame-pointer change in a trace is always a call, because
    // nothing can return past the entry frame, so its sign calibrates the
    // direction without hard-coding a version.
    let mut call_raises_frame_pointer: Option<bool> = None;

    for regs in register_trace.iter() {
        let pc = regs[11];
        let frame_pointer = regs[10];
        if stack.is_empty() {
            stack.push((frame_pointer, pc));
        } else {
            let top = stack[stack.len() - 1].0;
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
                    stack.push((frame_pointer, pc));
                } else {
                    while stack.len() > 1 && deeper(stack[stack.len() - 1].0, frame_pointer) {
                        stack.pop();
                    }
                }
            }
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
        if String::from_utf8_lossy(name) != "sol_poseidon" {
            continue;
        }
        out.poseidon_calls += 1;
        *out.poseidon_by_arity.entry(regs[4]).or_insert(0) += 1;
        // One credit per distinct frame, so a recursive frame is not counted
        // twice for the same call.
        let mut seen: Vec<&str> = Vec::with_capacity(stack.len());
        for (_, entry_pc) in stack.iter() {
            let Some(symbol) = symbols.lookup(*entry_pc) else {
                continue;
            };
            if seen.contains(&symbol.name.as_str()) {
                continue;
            }
            seen.push(symbol.name.as_str());
            *out.poseidon_by_frame
                .entry(symbol.name.clone())
                .or_insert(0) += 1;
        }
    }
}

pub fn render(attribution: &Attribution) -> String {
    let mut out = format!(
        "  Poseidon calls {}  arities {:?}\n",
        attribution.poseidon_calls, attribution.poseidon_by_arity
    );
    let mut frames: Vec<(&String, &u64)> = attribution.poseidon_by_frame.iter().collect();
    frames.sort_by(|left, right| right.1.cmp(left.1).then(left.0.cmp(right.0)));
    for (name, calls) in frames.iter().take(18) {
        let short = name.rsplit_once("::h").map_or(name.as_str(), |(head, _)| head);
        out.push_str(&format!("    {calls:5}  {short}\n"));
    }
    out
}
