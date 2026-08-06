//! Line-by-line decomposition of one real zolana transaction.
//!
//! The family split in `main` leaves an "everything else" bucket. This module
//! opens it. Two sources do the work and neither is a model:
//!
//! * the runtime's own invocation log, which states the compute consumed by
//!   every invocation of the transaction, top level and CPI alike, so the
//!   builtin instructions and the callee side of a CPI are read off rather
//!   than assumed;
//! * price-neutral observers over `sol_invoke_signed_c` and `sol_get_sysvar`,
//!   which delegate to the stock implementation and read the compute meter
//!   either side of it, so a charge is measured at the point the runtime makes
//!   it.
//!
//! A CPI window contains the callee, whose sBPF instructions the register
//! trace already counts. `cpi_caller_cu` subtracts the callee back out so the
//! two lines can be added.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

use solana_program_runtime::{
    invoke_context::InvokeContext,
    solana_sbpf::{
        declare_builtin_function, vm::ContextObject,
    },
};
use solana_syscalls::{SyscallGetSysvar, SyscallInvokeSignedC};

static CPI_CALLS: AtomicU64 = AtomicU64::new(0);
static CPI_WINDOW_CU: AtomicU64 = AtomicU64::new(0);
static SYSVAR_CALLS: AtomicU64 = AtomicU64::new(0);
static SYSVAR_CU: AtomicU64 = AtomicU64::new(0);
static CPI_WINDOWS: Mutex<Vec<u64>> = Mutex::new(Vec::new());

#[derive(Clone, Debug, Default)]
pub struct Observed {
    pub cpi_calls: u64,
    /// Compute consumed between entering and leaving `sol_invoke_signed_c`,
    /// which includes everything the callee spent.
    pub cpi_window_cu: u64,
    pub cpi_windows: Vec<u64>,
    pub sysvar_calls: u64,
    pub sysvar_cu: u64,
}

pub fn reset() {
    CPI_CALLS.store(0, Ordering::Relaxed);
    CPI_WINDOW_CU.store(0, Ordering::Relaxed);
    SYSVAR_CALLS.store(0, Ordering::Relaxed);
    SYSVAR_CU.store(0, Ordering::Relaxed);
    CPI_WINDOWS.lock().unwrap().clear();
}

pub fn observations() -> Observed {
    Observed {
        cpi_calls: CPI_CALLS.load(Ordering::Relaxed),
        cpi_window_cu: CPI_WINDOW_CU.load(Ordering::Relaxed),
        cpi_windows: CPI_WINDOWS.lock().unwrap().clone(),
        sysvar_calls: SYSVAR_CALLS.load(Ordering::Relaxed),
        sysvar_cu: SYSVAR_CU.load(Ordering::Relaxed),
    }
}

declare_builtin_function!(
    /// `sol_invoke_signed_c`, delegated unchanged, with the meter read either
    /// side of it.
    ObservedInvokeSignedC,
    fn rust(
        invoke_context: &mut InvokeContext<'_, '_>,
        instruction_addr: u64,
        account_infos_addr: u64,
        account_infos_len: u64,
        signers_seeds_addr: u64,
        signers_seeds_len: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let before = ContextObject::get_remaining(invoke_context);
        let out = SyscallInvokeSignedC::rust(
            invoke_context,
            instruction_addr,
            account_infos_addr,
            account_infos_len,
            signers_seeds_addr,
            signers_seeds_len,
        );
        let spent = before.saturating_sub(ContextObject::get_remaining(invoke_context));
        CPI_CALLS.fetch_add(1, Ordering::Relaxed);
        CPI_WINDOW_CU.fetch_add(spent, Ordering::Relaxed);
        CPI_WINDOWS.lock().unwrap().push(spent);
        out
    }
);

declare_builtin_function!(
    ObservedGetSysvar,
    fn rust(
        invoke_context: &mut InvokeContext<'_, '_>,
        sysvar_id_addr: u64,
        var_addr: u64,
        offset: u64,
        length: u64,
        arg5: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let before = ContextObject::get_remaining(invoke_context);
        let out = SyscallGetSysvar::rust(
            invoke_context,
            sysvar_id_addr,
            var_addr,
            offset,
            length,
            arg5,
        );
        let spent = before.saturating_sub(ContextObject::get_remaining(invoke_context));
        SYSVAR_CALLS.fetch_add(1, Ordering::Relaxed);
        SYSVAR_CU.fetch_add(spent, Ordering::Relaxed);
        out
    }
);
