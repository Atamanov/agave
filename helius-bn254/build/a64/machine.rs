//! Abstract AArch64 machine for the mont4 leaf schedule.
//!
//! Same design as the x86-64 layer (`super::super::machine`): a schedule is
//! one Rust function generic over [`MachineA64`], and the two implementations
//! interpret the identical operation sequence differently:
//!
//! * [`super::emit::EmitterA64`] renders GNU-as text, so the emitted kernel
//!   is exactly the schedule, one instruction per call;
//! * [`super::interp::InterpA64`] executes the operations with exact C-flag
//!   semantics, so the schedule's algebra and carry discipline are
//!   machine-checked on any host.
//!
//! Only the instruction forms the leaf uses exist here. Flag contract: MUL,
//! UMULH, loads, stores, MOV, CINC, CSET, and CSEL leave NZCV untouched;
//! ADDS/ADCS/CMN/SUBS/SBCS set it (the schedules consume only C); ADC adds
//! the carry without setting flags.

use core::fmt;

/// General-purpose registers the leaf touches, plus `sp` and `xzr`.
/// `x18` is the platform register and deliberately absent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reg {
    X0,
    X1,
    X2,
    X3,
    X4,
    X5,
    X6,
    X7,
    X8,
    X9,
    X10,
    X11,
    X12,
    X13,
    X14,
    X15,
    X16,
    X17,
    X19,
    X20,
    X21,
    X22,
    X23,
    Sp,
    Xzr,
}

impl Reg {
    pub const fn name(self) -> &'static str {
        match self {
            Reg::X0 => "x0",
            Reg::X1 => "x1",
            Reg::X2 => "x2",
            Reg::X3 => "x3",
            Reg::X4 => "x4",
            Reg::X5 => "x5",
            Reg::X6 => "x6",
            Reg::X7 => "x7",
            Reg::X8 => "x8",
            Reg::X9 => "x9",
            Reg::X10 => "x10",
            Reg::X11 => "x11",
            Reg::X12 => "x12",
            Reg::X13 => "x13",
            Reg::X14 => "x14",
            Reg::X15 => "x15",
            Reg::X16 => "x16",
            Reg::X17 => "x17",
            Reg::X19 => "x19",
            Reg::X20 => "x20",
            Reg::X21 => "x21",
            Reg::X22 => "x22",
            Reg::X23 => "x23",
            Reg::Sp => "sp",
            Reg::Xzr => "xzr",
        }
    }

    /// The 32-bit view (`w` form) of the register, for the loop counter.
    pub const fn name32(self) -> &'static str {
        match self {
            Reg::X3 => "w3",
            _ => panic!("only x3 is used as a 32-bit counter"),
        }
    }

    #[cfg(test)]
    pub const fn index(self) -> usize {
        match self {
            Reg::X0 => 0,
            Reg::X1 => 1,
            Reg::X2 => 2,
            Reg::X3 => 3,
            Reg::X4 => 4,
            Reg::X5 => 5,
            Reg::X6 => 6,
            Reg::X7 => 7,
            Reg::X8 => 8,
            Reg::X9 => 9,
            Reg::X10 => 10,
            Reg::X11 => 11,
            Reg::X12 => 12,
            Reg::X13 => 13,
            Reg::X14 => 14,
            Reg::X15 => 15,
            Reg::X16 => 16,
            Reg::X17 => 17,
            Reg::X19 => 19,
            Reg::X20 => 20,
            Reg::X21 => 21,
            Reg::X22 => 22,
            Reg::X23 => 23,
            Reg::Sp => 24,
            Reg::Xzr => 25,
        }
    }

    #[cfg(test)]
    pub const fn is_callee_saved(self) -> bool {
        matches!(self, Reg::X19 | Reg::X20 | Reg::X21 | Reg::X22 | Reg::X23)
    }
}

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One A64 operation, with a short semantic note (`what`) that becomes the
/// assembly comment where non-empty.
pub trait MachineA64 {
    /// Free-standing comment line in the emitted kernel.
    fn comment(&mut self, text: &str);

    /// `stp r1, r2, [sp, #imm]!` (pre-index spill; `imm` negative).
    fn stp_pre(&mut self, r1: Reg, r2: Reg, imm: i32);
    /// `stp r1, r2, [base, #imm]`.
    fn stp(&mut self, r1: Reg, r2: Reg, base: Reg, imm: i32, what: &str);
    /// `ldp r1, r2, [base, #imm]`.
    fn ldp(&mut self, r1: Reg, r2: Reg, base: Reg, imm: i32, what: &str);
    /// `ldp r1, r2, [base], #imm` (post-index restore).
    fn ldp_post(&mut self, r1: Reg, r2: Reg, base: Reg, imm: i32);
    /// `str r, [base, #imm]`.
    fn str_off(&mut self, r: Reg, base: Reg, imm: i32, what: &str);
    /// `ldr r, [base, #imm]`.
    fn ldr(&mut self, r: Reg, base: Reg, imm: i32, what: &str);
    /// `ldr r, [base], #imm` (post-index walk).
    fn ldr_post(&mut self, r: Reg, base: Reg, imm: i32, what: &str);
    /// `mov r, xzr`.
    fn mov_zero(&mut self, r: Reg, what: &str);

    /// `mul rd, rn, rm`: low 64 product bits; NZCV untouched.
    fn mul(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str);
    /// `umulh rd, rn, rm`: high 64 product bits; NZCV untouched.
    fn umulh(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str);

    /// `adds rd, rn, rm`: opens a carry chain (C = carry out).
    fn adds(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str);
    /// `adcs rd, rn, rm`: continues the chain.
    fn adcs(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str);
    /// `adc rd, rn, rm`: folds the carry in WITHOUT setting flags. The
    /// schedule relies on the discarded carry-out being zero; the
    /// interpreter asserts exactly that.
    fn adc(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str);
    /// `cinc rd, rn, hs`: `rd = rn + C`; NZCV untouched. Must not wrap;
    /// the interpreter asserts it (UMULH high halves are <= 2^64 - 2).
    fn cinc_hs(&mut self, rd: Reg, rn: Reg, what: &str);
    /// `cmn rn, rm`: flags of `rn + rm`, sum discarded.
    fn cmn(&mut self, rn: Reg, rm: Reg, what: &str);
    /// `cset rd, hs`: `rd = C`; NZCV untouched.
    fn cset_hs(&mut self, rd: Reg, what: &str);

    /// `subs rd, rn, rm`: C = NOT borrow (AArch64 convention).
    fn subs(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str);
    /// `sbcs rd, rn, rm`: continues the borrow chain.
    fn sbcs(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str);
    /// `csel rd, rn, rm, hs`: `rd = C ? rn : rm`; NZCV untouched.
    fn csel_hs(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str);

    /// Counted loop: `mov w<counter>, #count`, then `label:`, the body, and
    /// `subs w<counter>, w<counter>, #1; b.ne label`. The 32-bit counter
    /// arithmetic clobbers NZCV between iterations, so the body must not
    /// carry flags across the back edge (each row opens its own chain).
    fn counted_loop(
        &mut self,
        counter: Reg,
        count: u32,
        label: &str,
        body: &mut dyn FnMut(&mut Self),
    ) where
        Self: Sized;

    fn ret(&mut self);
}
