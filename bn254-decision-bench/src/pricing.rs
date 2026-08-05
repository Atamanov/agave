//! The one definition of a cell's syscall cost, and the structural split that
//! says how much of a transaction the syscall actually accounts for.
//!
//! Both renderers price through `syscall_cu`. A second copy is what let the
//! stock pairing charge drift between the renderer and the residual subtractor.

use {
    crate::{
        ColumnId, OperationTrace, RowId, current_pairing_map_cu, expected_trace,
        stock_group_op_pairing_cu,
    },
    solana_program_runtime::execution_budget::SVMTransactionExecutionCost,
};

/// Syscall CU for one cell: the charge a validator meters, and nothing else.
pub fn syscall_cu(
    cost: &SVMTransactionExecutionCost,
    column: ColumnId,
    trace: &OperationTrace,
) -> u64 {
    // Current keeps the stock precompile; every other column reaches the batch
    // syscalls and is priced by the fitted schedule.
    // Current keeps the stock precompile; every other column reaches the batch
    // syscalls. Current + Fp12 is a third case: it stays per-proof independent
    // but its finalizer is `pairing_map`, which has no stock equivalent.
    let stock = matches!(column, ColumnId::Current | ColumnId::CurrentFp12);
    let mut cu = 0u64;
    for call in &trace.pairing_checks {
        let each = if stock {
            stock_group_op_pairing_cu(call.pairs.into())
        } else {
            cost.alt_bn128_pairing_cost(call.full_pairs.into(), call.registered_pairs.into())
        };
        cu = cu.saturating_add(u64::from(call.calls).saturating_mul(each));
    }
    for call in &trace.pairing_maps {
        let each = if stock {
            current_pairing_map_cu(call.pairs.into())
        } else {
            cost.alt_bn128_pairing_cost(call.full_pairs.into(), call.registered_pairs.into())
        };
        cu = cu.saturating_add(u64::from(call.calls).saturating_mul(each));
    }
    for call in &trace.msm_calls {
        cu = cu.saturating_add(u64::from(call.calls).saturating_mul(
            cost.alt_bn128_g1_msm_base_cost.saturating_add(
                cost.alt_bn128_g1_msm_per_point_cost
                    .saturating_mul(u64::from(call.points)),
            ),
        ));
    }
    // The unbatched path forms its public-input commitment with stock G1
    // operations rather than an MSM syscall. They are metered, and the residual
    // subtracts them, so omitting them here understates the baseline.
    cu = cu.saturating_add(
        cost.alt_bn128_g1_addition_cost
            .saturating_mul(u64::from(trace.stock_g1_additions)),
    );
    cu = cu.saturating_add(
        cost.alt_bn128_g1_multiplication_cost
            .saturating_mul(u64::from(trace.stock_g1_multiplications)),
    );
    for call in &trace.fr_lincomb_calls {
        cu = cu.saturating_add(u64::from(call.calls).saturating_mul(
            cost.alt_bn128_fr_lincomb_base_cost.saturating_add(
                cost.alt_bn128_fr_lincomb_per_term_cost
                    .saturating_mul(u64::from(call.terms)),
            ),
        ));
    }
    for call in &trace.gt_target_multiexp_calls {
        cu = cu.saturating_add(u64::from(call.calls).saturating_mul(
            cost.alt_bn128_gt_multiexp_base_cost.saturating_add(
                cost.alt_bn128_gt_multiexp_per_target_cost
                    .saturating_mul(u64::from(call.targets)),
            ),
        ));
    }
    cu
}

/// How a cell's transaction CU divides between the syscall and the guest.
#[derive(Clone, Copy, Debug)]
pub struct CostSplit {
    pub syscall: u64,
    pub sbpf: u64,
}

impl CostSplit {
    pub fn total(&self) -> u64 {
        self.syscall.saturating_add(self.sbpf)
    }

    /// Syscall share in tenths of a percent, so the gate needs no float.
    /// A cell with no work reads as zero rather than dividing by it.
    pub fn syscall_share_per_mille(&self) -> u64 {
        self.syscall
            .saturating_mul(1_000)
            .checked_div(self.total())
            .unwrap_or_default()
    }
}

pub fn cost_split(
    cost: &SVMTransactionExecutionCost,
    row: RowId,
    column: ColumnId,
    residual: u64,
) -> CostSplit {
    CostSplit {
        syscall: syscall_cu(cost, column, &expected_trace(row, column)),
        sbpf: residual,
    }
}

/// Floor below which a column stops describing the syscall it is named after.
///
/// Not a physical law. It is a smell detector: a batching column whose cost is
/// overwhelmingly guest-side is measuring the wrapper, not the batch. The value
/// is deliberately loose so that only a structural problem trips it.
pub const MIN_SYSCALL_SHARE_PER_MILLE: u64 = 250;

/// Columns whose whole purpose is to move work into a syscall. `Current` is
/// exempt because it is the baseline, and recursion is exempt because it
/// deliberately trades on-chain pairing work for prover work.
pub const SYSCALL_BEARING_COLUMNS: [ColumnId; 3] = [
    ColumnId::BatchB5,
    ColumnId::RegistryB5,
    ColumnId::BatchFp12B5,
];
