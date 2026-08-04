//! Abstract x86-64 machine over which kernel schedules are written once.
//!
//! A schedule is an ordinary Rust function generic over [`Machine`]; the two
//! implementations interpret the same operation sequence differently:
//! [`super::emit::Emitter`] renders GNU-as Intel-syntax text, so the emitted
//! kernel is exactly the schedule, line for line, and [`super::interp::Interp`]
//! executes the operations with bit-accurate CF/OF semantics, so the
//! schedule's algebra and every claimed carry invariant are machine-checked
//! on any host. Only the instruction forms the kernels need exist here;
//! emission is centralized per-op, so no caller pastes raw instruction text.

use core::fmt;

/// General-purpose registers. `Rsp` is modeled only for push/pop balance.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reg {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rbp,
    Rsp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl Reg {
    pub const fn name(self) -> &'static str {
        match self {
            Reg::Rax => "rax",
            Reg::Rbx => "rbx",
            Reg::Rcx => "rcx",
            Reg::Rdx => "rdx",
            Reg::Rsi => "rsi",
            Reg::Rdi => "rdi",
            Reg::Rbp => "rbp",
            Reg::Rsp => "rsp",
            Reg::R8 => "r8",
            Reg::R9 => "r9",
            Reg::R10 => "r10",
            Reg::R11 => "r11",
            Reg::R12 => "r12",
            Reg::R13 => "r13",
            Reg::R14 => "r14",
            Reg::R15 => "r15",
        }
    }

    pub const fn index(self) -> usize {
        match self {
            Reg::Rax => 0,
            Reg::Rbx => 1,
            Reg::Rcx => 2,
            Reg::Rdx => 3,
            Reg::Rsi => 4,
            Reg::Rdi => 5,
            Reg::Rbp => 6,
            Reg::Rsp => 7,
            Reg::R8 => 8,
            Reg::R9 => 9,
            Reg::R10 => 10,
            Reg::R11 => 11,
            Reg::R12 => 12,
            Reg::R13 => 13,
            Reg::R14 => 14,
            Reg::R15 => 15,
        }
    }

    /// Registers whose encodings need REX.B/REX.R extension bits.
    pub const fn is_extended(self) -> bool {
        self.index() >= 8
    }

    pub const fn is_callee_saved(self) -> bool {
        matches!(
            self,
            Reg::Rbx | Reg::Rbp | Reg::R12 | Reg::R13 | Reg::R14 | Reg::R15
        )
    }
}

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// `[base + offset]` memory operand. Any base and any i32 displacement is
/// modeled: the emitter's byte model charges the SIB byte for `rsp`/`r12`
/// bases, the forced disp8 of `rbp`/`r13` at offset 0, and disp32 once the
/// offset leaves imm8 range.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mem {
    pub base: Reg,
    pub offset: i32,
}

impl Mem {
    pub const fn new(base: Reg, offset: i32) -> Self {
        Mem { base, offset }
    }
}

impl fmt::Display for Mem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.offset == 0 {
            write!(f, "[{}]", self.base)
        } else if self.offset < 0 {
            write!(f, "[{} - {}]", self.base, -(self.offset as i64))
        } else {
            write!(f, "[{} + {}]", self.base, self.offset)
        }
    }
}

/// Loop bound of a [`Machine::stride_loop`]: a register holding the end
/// value, a small immediate, or a frame slot holding the end value (for
/// walks whose cursor is an absolute pointer when no register is free).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoopEnd {
    Reg(Reg),
    Imm(i32),
    Mem(Mem),
}

/// One 64-bit x86 operation, with a short semantic note (`what`) that becomes
/// the assembly comment. Flag behavior is part of each op's contract:
///
/// | op                | CF            | OF            |
/// |-------------------|---------------|---------------|
/// | `mov*`, `mulx_*`  | untouched     | untouched     |
/// | `xor_clear`       | cleared       | cleared       |
/// | `add`/`adc*`      | carry out     | signed ovf    |
/// | `add_imm`         | carry out     | signed ovf    |
/// | `*_stack`         | clobbered     | clobbered     |
/// | `adcx`            | carry out     | untouched     |
/// | `adox`            | untouched     | carry out     |
/// | `sub_mem`/`sbb_*` | borrow out    | signed ovf    |
/// | `sub_rr`/`sbb_rr` | borrow out    | signed ovf    |
/// | `cmov_carry`      | read          | untouched     |
/// | `shld_imm`/`shr_imm` | clobbered  | clobbered     |
/// | `and_mem`         | cleared       | cleared       |
/// | `lea_rodata`      | untouched     | untouched     |
/// | `stride_loop`     | clobbered     | clobbered     |
pub trait Machine {
    /// Free-standing comment line in the emitted kernel.
    fn comment(&mut self, text: &str);

    /// Schedule invariant: both carry chains are closed here (CF = OF = 0).
    /// The emitter prints the claim; the interpreter asserts it.
    fn claim_flags_clear(&mut self, why: &str);

    /// Schedule invariant: `reg` holds exactly zero here. The emitter prints
    /// the claim; the interpreter asserts it.
    fn claim_zero(&mut self, reg: Reg, why: &str);

    fn push(&mut self, src: Reg);
    fn pop(&mut self, dst: Reg);
    fn ret(&mut self);

    /// `sub rsp, bytes` -- open a fixed spill frame (multiple of 8; imm8 or
    /// imm32 encoding). Clobbers CF and OF like any `sub`; no chain may
    /// cross it.
    fn alloc_stack(&mut self, bytes: i32);
    /// `add rsp, bytes` -- close the frame opened by
    /// [`Machine::alloc_stack`]. Clobbers CF and OF.
    fn free_stack(&mut self, bytes: i32);

    /// `mov dst, [addr]`
    fn load(&mut self, dst: Reg, addr: Mem, what: &str);
    /// `mov dst, [base + index]` (SIB, no displacement); flags untouched.
    /// `base` must not be `rsp`/`rbp`/`r12`/`r13` (forced-disp encodings)
    /// and `index` must not be `rsp` (unencodable).
    fn load_indexed(&mut self, dst: Reg, base: Reg, index: Reg, what: &str);
    /// `mov [addr], src`
    fn store(&mut self, addr: Mem, src: Reg, what: &str);
    /// `mov dst, src`
    fn mov(&mut self, dst: Reg, src: Reg, what: &str);
    /// `mov dst, 0` -- zeroing that must not disturb the carry chains.
    fn mov_zero(&mut self, dst: Reg, what: &str);
    /// `xor dst, dst` -- zeroes `dst` and clears CF and OF.
    fn xor_clear(&mut self, dst: Reg, what: &str);

    /// `mulx hi, lo, src`: `hi:lo = rdx * src`; flags untouched.
    fn mulx(&mut self, hi: Reg, lo: Reg, src: Reg, what: &str);
    /// `mulx hi, lo, [addr]`: `hi:lo = rdx * [addr]`; flags untouched.
    fn mulx_mem(&mut self, hi: Reg, lo: Reg, addr: Mem, what: &str);

    /// `adox dst, src`: OF-only carry chain (the "value" chain).
    fn adox(&mut self, dst: Reg, src: Reg, what: &str);
    /// `adcx dst, src`: CF-only carry chain (the "carry" chain).
    fn adcx(&mut self, dst: Reg, src: Reg, what: &str);

    fn add(&mut self, dst: Reg, src: Reg, what: &str);
    fn adc(&mut self, dst: Reg, src: Reg, what: &str);
    /// `adc dst, 0` -- fold the carry into `dst` and terminate an adc chain.
    fn adc_zero(&mut self, dst: Reg, what: &str);
    /// `add dst, [addr]`; sets CF/OF like `add`.
    fn add_mem(&mut self, dst: Reg, src: Mem, what: &str);
    /// `adc dst, [addr]`; sets CF/OF like `adc`.
    fn adc_mem(&mut self, dst: Reg, src: Mem, what: &str);

    fn sub_mem(&mut self, dst: Reg, src: Mem, what: &str);
    fn sbb_mem(&mut self, dst: Reg, src: Mem, what: &str);
    /// `sub dst, src` (register source); CF is the borrow out.
    fn sub_rr(&mut self, dst: Reg, src: Reg, what: &str);
    /// `sbb dst, src` (register source).
    fn sbb_rr(&mut self, dst: Reg, src: Reg, what: &str);
    /// `cmovc dst, src`: keep the pre-subtraction value when CF (borrow) set.
    fn cmov_carry(&mut self, dst: Reg, src: Reg, what: &str);

    /// `and dst, [addr]` -- masking against a memory operand (the borrow-mask
    /// route of the double-width guarded subtraction). Clears CF and OF.
    fn and_mem(&mut self, dst: Reg, src: Mem, what: &str);

    /// Declare a read-only data table for this kernel. Not an instruction:
    /// the emitter collects the values for a `.rodata` block behind `label`,
    /// the interpreter installs them at a synthetic address. Must be declared
    /// before any [`Machine::lea_rodata`] of the same label.
    fn rodata(&mut self, label: &str, values: &[u64]);

    /// `lea dst, [rip + label]` -- materialize the address of a
    /// [`Machine::rodata`] table. Flags untouched.
    fn lea_rodata(&mut self, dst: Reg, label: &str, what: &str);

    /// `shld dst, src, imm`: `dst = (dst << imm) | (src >> (64 - imm))`,
    /// `imm` in 1..=63. Clobbers CF and OF; no chain may cross it.
    fn shld_imm(&mut self, dst: Reg, src: Reg, imm: u32, what: &str);
    /// `shr dst, imm`, `imm` in 1..=63. Clobbers CF and OF.
    fn shr_imm(&mut self, dst: Reg, imm: u32, what: &str);

    /// `add dst, imm`; sets CF/OF like `add`. imm8 or imm32 encoding.
    fn add_imm(&mut self, dst: Reg, imm: i32, what: &str);

    /// Counted loop over a stride: `label:`, the body, then
    /// `add cursor, step; cmp cursor, end; jne label`.
    ///
    /// Runs the body at least once (do-while shape). The back edge's `add`
    /// and `cmp` clobber CF and OF, so no carry chain may cross it: the body
    /// must close its chains and re-seed with `xor_clear` after the top of
    /// the loop. The interpreter checks the trip proof at entry (`end`
    /// strictly ahead of `cursor` by a positive multiple of `step`) and
    /// executes the back edge with exact flag semantics.
    fn stride_loop(
        &mut self,
        cursor: Reg,
        step: i32,
        end: LoopEnd,
        label: &str,
        body: &mut dyn FnMut(&mut Self),
    ) where
        Self: Sized;
}
