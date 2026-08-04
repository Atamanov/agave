//! Bit-accurate interpreter: the executable semantics of a schedule.
//!
//! Running a schedule here proves, on any host, that its operation sequence
//! computes the intended function: registers are u64s, CF and OF are modeled
//! exactly per instruction (adox touches only OF, adcx only CF, mulx neither,
//! add/adc/sub/sbb set both), memory is a sparse map that panics on wild or
//! uninitialized access, and `ret` verifies the System V callee-saved
//! contract plus stack balance. Every `claim_flags_clear` in a schedule
//! becomes a hard assertion, so the carry-bound reasoning documented in
//! `schedule.rs` is checked rather than trusted.

use std::collections::BTreeMap;

use super::machine::{LoopEnd, Machine, Mem, Reg};

/// Synthetic, well-separated buffer addresses for the kernel arguments.
pub const OUT_ADDR: u64 = 0x1_0000;
pub const X_ADDR: u64 = 0x2_0000;
pub const Y_ADDR: u64 = 0x3_0000;
pub const CONSTS_ADDR: u64 = 0x4_0000;
/// Pair-pointer table of the SoS kernel; operand buffers follow above it.
pub const PAIRS_ADDR: u64 = 0x5_0000;
const OPERANDS_ADDR: u64 = 0x6_0000;
const STACK_TOP: u64 = 0x8_0000;
/// Synthetic base of the read-only tables; blobs are bump-allocated upward.
const RODATA_ADDR: u64 = 0x9_0000;
/// Recognizable poison for registers the ABI leaves undefined.
const POISON: u64 = 0xdead_0000_dead_0000;

pub struct Interp {
    regs: [u64; 16],
    /// Registers holding a schedule-defined value. Callee-saved registers
    /// start undefined: `push` may spill them, arithmetic may not read them.
    defined: [bool; 16],
    cf: bool,
    of: bool,
    mem: BTreeMap<u64, u64>,
    entry_callee_saved: [(Reg, u64); 6],
    returned: bool,
    /// Installed rodata tables: label -> synthetic base address.
    rodata_labels: BTreeMap<String, u64>,
    rodata_next: u64,
    /// Byte ranges `(base, len)` a store may legally target besides the stack
    /// frame: the output buffer(s) and, for sosd6, the in-place stage. A store
    /// outside these and the frame panics, machine-proving the leaf contract
    /// "writes nothing outside z and stage".
    write_regions: Vec<(u64, u64)>,
}

impl Interp {
    /// Set up a System V call frame:
    /// `rdi = out`, `rsi = x`, `rdx = y`, `rcx = { p[4], -p^-1 }`.
    pub fn call_frame(x: [u64; 4], y: [u64; 4], p: [u64; 4], p_inv: u64) -> Self {
        let mut regs = [0u64; 16];
        let mut defined = [false; 16];
        for (index, value) in regs.iter_mut().enumerate() {
            *value = POISON | (index as u64) << 16;
        }
        let arguments = [
            (Reg::Rdi, OUT_ADDR),
            (Reg::Rsi, X_ADDR),
            (Reg::Rdx, Y_ADDR),
            (Reg::Rcx, CONSTS_ADDR),
            (Reg::Rsp, STACK_TOP),
        ];
        for (reg, value) in arguments {
            regs[reg.index()] = value;
            defined[reg.index()] = true;
        }

        let mut mem = BTreeMap::new();
        for limb in 0..4 {
            mem.insert(X_ADDR + 8 * limb as u64, x[limb]);
            mem.insert(Y_ADDR + 8 * limb as u64, y[limb]);
            mem.insert(CONSTS_ADDR + 8 * limb as u64, p[limb]);
        }
        mem.insert(CONSTS_ADDR + 32, p_inv);

        let callee_saved = [Reg::Rbx, Reg::Rbp, Reg::R12, Reg::R13, Reg::R14, Reg::R15];
        Interp {
            entry_callee_saved: callee_saved.map(|r| (r, regs[r.index()])),
            regs,
            defined,
            // The ABI does not define entry flags; poison them so a schedule
            // that forgets its initial clear fails deterministically.
            cf: true,
            of: true,
            mem,
            returned: false,
            rodata_labels: BTreeMap::new(),
            rodata_next: RODATA_ADDR,
            // Default single-Fp output at OUT_ADDR; wider-output and staged
            // frames extend this below.
            write_regions: vec![(OUT_ADDR, 32)],
        }
    }

    /// Declare a byte range `[base, base + len)` a store may legally target.
    fn allow_writes(&mut self, base: u64, len: u64) {
        self.write_regions.push((base, len));
    }

    /// Set up a System V call frame for the whole-Fp12 square kernel:
    /// `rdi = z` (48 limbs), `rsi = f` (48 limbs, repr(C) Fp12 order),
    /// `rdx = consts` (`p[4]`, `-p^-1`, mu at +40). With `alias` the output
    /// pointer is `f` itself, exercising the in-place production shape.
    pub fn fp12_sqr_frame(
        f: &[[u64; 4]; 12],
        p: [u64; 4],
        p_inv: u64,
        mu: u64,
        alias: bool,
    ) -> Self {
        let mut frame = Self::call_frame([0; 4], [0; 4], p, p_inv);
        frame.mem.insert(CONSTS_ADDR + 40, mu);
        frame.regs[Reg::Rdx.index()] = CONSTS_ADDR;
        if alias {
            frame.regs[Reg::Rdi.index()] = X_ADDR;
        }
        frame.allow_writes(frame.regs[Reg::Rdi.index()], 384);
        for (i, component) in f.iter().enumerate() {
            for (limb, value) in component.iter().enumerate() {
                frame
                    .mem
                    .insert(X_ADDR + 32 * i as u64 + 8 * limb as u64, *value);
            }
        }
        frame
    }

    /// Set up a System V call frame for the whole-Fp12 multiply kernel:
    /// `rdi = z` (48 limbs), `rsi = a`, `rdx = b` (48 limbs each, repr(C)
    /// Fp12 order), `rcx = consts` (`p[4]`, `-p^-1`, mu at +40). `alias`
    /// selects the output pointer: 0 = distinct z, 1 = `z == a` (the
    /// production MulAssign shape), 2 = `z == b`.
    pub fn fp12_mul_frame(
        a: &[[u64; 4]; 12],
        b: &[[u64; 4]; 12],
        p: [u64; 4],
        p_inv: u64,
        mu: u64,
        alias: usize,
    ) -> Self {
        let mut frame = Self::call_frame([0; 4], [0; 4], p, p_inv);
        frame.mem.insert(CONSTS_ADDR + 40, mu);
        frame.regs[Reg::Rcx.index()] = CONSTS_ADDR;
        frame.regs[Reg::Rdi.index()] = match alias {
            0 => OUT_ADDR,
            1 => X_ADDR,
            2 => Y_ADDR,
            other => panic!("unknown alias mode {other}"),
        };
        frame.allow_writes(frame.regs[Reg::Rdi.index()], 384);
        for (base, operand) in [(X_ADDR, a), (Y_ADDR, b)] {
            for (i, component) in operand.iter().enumerate() {
                for (limb, value) in component.iter().enumerate() {
                    frame
                        .mem
                        .insert(base + 32 * i as u64 + 8 * limb as u64, *value);
                }
            }
        }
        frame
    }

    /// Set up a System V call frame for the SoS kernel:
    /// `rdi = out`, `rsi = pair table`, `rdx = pair count`, `rcx = consts`.
    /// Each `(a_i, b_i)` operand pair lands in its own synthetic buffer and
    /// the table holds the 2T pointers, exactly the production ABI.
    pub fn sos_frame(pairs: &[([u64; 4], [u64; 4])], p: [u64; 4], p_inv: u64) -> Self {
        let mut frame = Self::call_frame([0; 4], [0; 4], p, p_inv);
        frame.regs[Reg::Rsi.index()] = PAIRS_ADDR;
        frame.regs[Reg::Rdx.index()] = pairs.len() as u64;
        for (i, (a, b)) in pairs.iter().enumerate() {
            let a_addr = OPERANDS_ADDR + 0x100 * i as u64;
            let b_addr = a_addr + 0x80;
            frame.mem.insert(PAIRS_ADDR + 16 * i as u64, a_addr);
            frame.mem.insert(PAIRS_ADDR + 16 * i as u64 + 8, b_addr);
            for limb in 0..4 {
                frame.mem.insert(a_addr + 8 * limb as u64, a[limb]);
                frame.mem.insert(b_addr + 8 * limb as u64, b[limb]);
            }
        }
        frame
    }

    /// Set up a System V call frame for the dual-lane sosd2 kernel:
    /// `rdi = z` (8 limbs, lane0 then lane1), `rsi = x0`, `rdx = x1`,
    /// `rcx = y0`, `r8 = y1`, `r9 = consts`.
    pub fn sosd2_frame(
        x0: [u64; 4],
        x1: [u64; 4],
        y0: [u64; 4],
        y1: [u64; 4],
        p: [u64; 4],
        p_inv: u64,
    ) -> Self {
        let mut frame = Self::call_frame(x0, x1, p, p_inv);
        frame.allow_writes(OUT_ADDR, 64);
        let y0_addr = OPERANDS_ADDR;
        let y1_addr = OPERANDS_ADDR + 0x80;
        let arguments = [
            (Reg::Rcx, y0_addr),
            (Reg::R8, y1_addr),
            (Reg::R9, CONSTS_ADDR),
        ];
        for (reg, value) in arguments {
            frame.regs[reg.index()] = value;
            frame.defined[reg.index()] = true;
        }
        for limb in 0..4 {
            frame.mem.insert(y0_addr + 8 * limb as u64, y0[limb]);
            frame.mem.insert(y1_addr + 8 * limb as u64, y1[limb]);
        }
        frame
    }

    /// Set up a System V call frame for the dual-lane sosd6 kernel:
    /// `rdi = z` (8 limbs, lane0 then lane1), `rsi = stage` (64 limbs, built
    /// exactly as the production wrapper stages it: the 24 x limbs
    /// transposed, then the five y pair blocks `[y00, y01] [y01, y00]
    /// [y10, y11] [y11, y10] [y20, y21]`), `rdx = consts`. Operand order is
    /// x00, x01, x10, x11, x20, x21 and y00, y01, y10, y11, y20, y21.
    pub fn sosd6_frame(xs: &[[u64; 4]; 6], ys: &[[u64; 4]; 6], p: [u64; 4], p_inv: u64) -> Self {
        let mut frame = Self::call_frame([0; 4], [0; 4], p, p_inv);
        frame.regs[Reg::Rdx.index()] = CONSTS_ADDR;
        // z (8 limbs) plus the in-place stage (64 limbs at rsi = X_ADDR): the
        // kernel overwrites the negated y images inside the stage.
        frame.allow_writes(OUT_ADDR, 64);
        frame.allow_writes(X_ADDR, 512);
        for (i, x) in xs.iter().enumerate() {
            for (j, limb) in x.iter().enumerate() {
                frame
                    .mem
                    .insert(X_ADDR + 8 * (6 * j as u64 + i as u64), *limb);
            }
        }
        for (block, y) in [0, 1, 1, 0, 2, 3, 3, 2, 4, 5].into_iter().enumerate() {
            for (limb, value) in ys[y].iter().enumerate() {
                frame
                    .mem
                    .insert(X_ADDR + 192 + 32 * block as u64 + 8 * limb as u64, *value);
            }
        }
        frame
    }

    /// Set up a System V call frame for the whole-Fp6 multiply kernel:
    /// `rdi = z` (24 limbs), `rsi = a` (24 limbs), `rdx = b` (24 limbs),
    /// `rcx = consts` (`p[4]`, `-p^-1`, and the xi-reduction estimate `mu`
    /// at +40). Operand order is the `repr(C)` Fp6 layout:
    /// c0.re, c0.im, c1.re, c1.im, c2.re, c2.im.
    pub fn fp6_frame(
        a: &[[u64; 4]; 6],
        b: &[[u64; 4]; 6],
        p: [u64; 4],
        p_inv: u64,
        mu: u64,
    ) -> Self {
        let mut frame = Self::call_frame([0; 4], [0; 4], p, p_inv);
        frame.mem.insert(CONSTS_ADDR + 40, mu);
        frame.allow_writes(OUT_ADDR, 192);
        for (i, component) in a.iter().enumerate() {
            for (limb, value) in component.iter().enumerate() {
                frame
                    .mem
                    .insert(X_ADDR + 32 * i as u64 + 8 * limb as u64, *value);
            }
        }
        for (i, component) in b.iter().enumerate() {
            for (limb, value) in component.iter().enumerate() {
                frame
                    .mem
                    .insert(Y_ADDR + 32 * i as u64 + 8 * limb as u64, *value);
            }
        }
        frame
    }

    /// Set up a System V call frame for the sparse Fp12 034 kernel:
    /// `rdi = z` (48 limbs), `rsi = f` (48 limbs, repr(C) Fp12 order),
    /// `rdx = c` (24 limbs: the sparse coefficients c0, c3, c4 as contiguous
    /// Fp2s), `rcx = consts` (as the fp6 kernel). With `alias` the output
    /// pointer is `f` itself, exercising the in-place production shape.
    pub fn fp12_034_frame(
        f: &[[u64; 4]; 12],
        c: &[[u64; 4]; 6],
        p: [u64; 4],
        p_inv: u64,
        mu: u64,
        alias: bool,
    ) -> Self {
        let mut frame = Self::call_frame([0; 4], [0; 4], p, p_inv);
        frame.mem.insert(CONSTS_ADDR + 40, mu);
        if alias {
            frame.regs[Reg::Rdi.index()] = X_ADDR;
        }
        frame.allow_writes(frame.regs[Reg::Rdi.index()], 384);
        for (i, component) in f.iter().enumerate() {
            for (limb, value) in component.iter().enumerate() {
                frame
                    .mem
                    .insert(X_ADDR + 32 * i as u64 + 8 * limb as u64, *value);
            }
        }
        for (i, component) in c.iter().enumerate() {
            for (limb, value) in component.iter().enumerate() {
                frame
                    .mem
                    .insert(Y_ADDR + 32 * i as u64 + 8 * limb as u64, *value);
            }
        }
        frame
    }

    pub fn output(&self) -> [u64; 4] {
        assert!(self.returned, "kernel did not return");
        core::array::from_fn(|limb| self.read_mem(OUT_ADDR + 8 * limb as u64))
    }

    /// All six Fp components of the fp6 kernel output, `repr(C)` order.
    pub fn output_fp6(&self) -> [[u64; 4]; 6] {
        assert!(self.returned, "kernel did not return");
        core::array::from_fn(|i| {
            core::array::from_fn(|limb| self.read_mem(OUT_ADDR + 32 * i as u64 + 8 * limb as u64))
        })
    }

    /// All twelve Fp components of the fp12_034 kernel output, `repr(C)`
    /// order; `aliased` reads the in-place result from the `f` buffer.
    pub fn output_fp12(&self, aliased: bool) -> [[u64; 4]; 12] {
        assert!(self.returned, "kernel did not return");
        let base = if aliased { X_ADDR } else { OUT_ADDR };
        self.output_fp12_at(base)
    }

    /// Twelve Fp components read from an explicit output buffer (the
    /// fp12_mul frame's three aliasing shapes).
    pub fn output_fp12_at(&self, base: u64) -> [[u64; 4]; 12] {
        assert!(self.returned, "kernel did not return");
        core::array::from_fn(|i| {
            core::array::from_fn(|limb| self.read_mem(base + 32 * i as u64 + 8 * limb as u64))
        })
    }

    /// Both output lanes of the sosd2 kernel: `z[0..4]` and `z[4..8]`.
    pub fn output_lanes(&self) -> ([u64; 4], [u64; 4]) {
        assert!(self.returned, "kernel did not return");
        (
            core::array::from_fn(|limb| self.read_mem(OUT_ADDR + 8 * limb as u64)),
            core::array::from_fn(|limb| self.read_mem(OUT_ADDR + 32 + 8 * limb as u64)),
        )
    }

    fn read_reg(&self, r: Reg) -> u64 {
        assert!(self.defined[r.index()], "read of undefined register {r}");
        self.regs[r.index()]
    }

    fn write_reg(&mut self, r: Reg, value: u64) {
        assert_ne!(r, Reg::Rsp, "rsp is only adjusted by push/pop");
        self.regs[r.index()] = value;
        self.defined[r.index()] = true;
    }

    fn read_mem(&self, addr: u64) -> u64 {
        assert_eq!(addr % 8, 0, "unaligned load at {addr:#x}");
        *self
            .mem
            .get(&addr)
            .unwrap_or_else(|| panic!("load of uninitialized memory at {addr:#x}"))
    }

    fn resolve(&self, addr: Mem) -> u64 {
        self.read_reg(addr.base).wrapping_add(addr.offset as u64)
    }

    /// `dst + src + carry_in`, returning the carry-out bit.
    fn carry_add(&mut self, dst: Reg, src_value: u64, carry_in: bool) -> bool {
        let (mid, c1) = self.read_reg(dst).overflowing_add(src_value);
        let (out, c2) = mid.overflowing_add(carry_in as u64);
        self.write_reg(dst, out);
        c1 | c2
    }

    /// Signed-overflow flag for `a + b + carry = result`.
    fn signed_overflow_add(a: u64, b: u64, result: u64) -> bool {
        ((a ^ result) & (b ^ result)) >> 63 != 0
    }
}

impl Machine for Interp {
    fn comment(&mut self, _text: &str) {}

    fn claim_flags_clear(&mut self, why: &str) {
        assert!(
            !self.cf && !self.of,
            "claimed flags-clear invariant violated: {why} (cf={}, of={})",
            self.cf,
            self.of,
        );
    }

    fn claim_zero(&mut self, reg: Reg, why: &str) {
        let value = self.read_reg(reg);
        assert_eq!(value, 0, "claimed zero invariant violated for {reg}: {why}");
    }

    fn push(&mut self, src: Reg) {
        // Reads the raw register: spilling a caller-owned callee-saved value
        // is exactly what the prologue does before the value is "defined".
        let value = self.regs[src.index()];
        let rsp = self.regs[Reg::Rsp.index()] - 8;
        self.regs[Reg::Rsp.index()] = rsp;
        self.mem.insert(rsp, value);
    }

    fn pop(&mut self, dst: Reg) {
        let rsp = self.regs[Reg::Rsp.index()];
        let value = self.read_mem(rsp);
        self.regs[Reg::Rsp.index()] = rsp + 8;
        self.write_reg(dst, value);
    }

    fn alloc_stack(&mut self, bytes: i32) {
        assert!(
            bytes > 0 && bytes % 8 == 0,
            "frame is a positive 8-multiple"
        );
        self.regs[Reg::Rsp.index()] -= bytes as u64;
        // `sub rsp` clobbers CF/OF; poison them so no chain crosses.
        self.cf = true;
        self.of = true;
    }

    fn free_stack(&mut self, bytes: i32) {
        assert!(
            bytes > 0 && bytes % 8 == 0,
            "frame is a positive 8-multiple"
        );
        self.regs[Reg::Rsp.index()] += bytes as u64;
        self.cf = true;
        self.of = true;
    }

    fn ret(&mut self) {
        assert_eq!(
            self.regs[Reg::Rsp.index()],
            STACK_TOP,
            "stack unbalanced at ret",
        );
        for (reg, entry_value) in self.entry_callee_saved {
            assert_eq!(
                self.regs[reg.index()],
                entry_value,
                "callee-saved {reg} not restored",
            );
        }
        self.returned = true;
    }

    fn load(&mut self, dst: Reg, addr: Mem, _what: &str) {
        let value = self.read_mem(self.resolve(addr));
        self.write_reg(dst, value);
    }

    fn load_indexed(&mut self, dst: Reg, base: Reg, index: Reg, _what: &str) {
        let addr = self.read_reg(base).wrapping_add(self.read_reg(index));
        let value = self.read_mem(addr);
        self.write_reg(dst, value);
    }

    fn store(&mut self, addr: Mem, src: Reg, _what: &str) {
        let target = self.resolve(addr);
        assert_eq!(target % 8, 0, "unaligned store at {target:#x}");
        // A store must land in the current stack frame or a declared
        // output/stage region. Anything else -- an operand buffer, the
        // constant table, rodata, or past a buffer's end -- is a contract
        // violation, so the kernel's "writes nothing outside z and stage"
        // claim is machine-proven, not trusted.
        let rsp = self.regs[Reg::Rsp.index()];
        let in_frame = (rsp..STACK_TOP).contains(&target);
        let in_region = self
            .write_regions
            .iter()
            .any(|&(base, len)| target >= base && target < base + len);
        assert!(
            in_frame || in_region,
            "store outside the declared output/stage/frame regions at {target:#x}",
        );
        let value = self.read_reg(src);
        self.mem.insert(target, value);
    }

    fn mov(&mut self, dst: Reg, src: Reg, _what: &str) {
        let value = self.read_reg(src);
        self.write_reg(dst, value);
    }

    fn mov_zero(&mut self, dst: Reg, _what: &str) {
        self.write_reg(dst, 0);
    }

    fn xor_clear(&mut self, dst: Reg, _what: &str) {
        self.write_reg(dst, 0);
        self.cf = false;
        self.of = false;
    }

    fn mulx(&mut self, hi: Reg, lo: Reg, src: Reg, what: &str) {
        let src_value = self.read_reg(src);
        self.mulx_value(hi, lo, src_value, what);
    }

    fn mulx_mem(&mut self, hi: Reg, lo: Reg, addr: Mem, what: &str) {
        let src_value = self.read_mem(self.resolve(addr));
        self.mulx_value(hi, lo, src_value, what);
    }

    fn adox(&mut self, dst: Reg, src: Reg, _what: &str) {
        let src_value = self.read_reg(src);
        let carry_in = self.of;
        self.of = self.carry_add(dst, src_value, carry_in);
    }

    fn adcx(&mut self, dst: Reg, src: Reg, _what: &str) {
        let src_value = self.read_reg(src);
        let carry_in = self.cf;
        self.cf = self.carry_add(dst, src_value, carry_in);
    }

    fn add(&mut self, dst: Reg, src: Reg, _what: &str) {
        let a = self.read_reg(dst);
        let b = self.read_reg(src);
        self.cf = self.carry_add(dst, b, false);
        self.of = Self::signed_overflow_add(a, b, self.read_reg(dst));
    }

    fn adc(&mut self, dst: Reg, src: Reg, _what: &str) {
        let a = self.read_reg(dst);
        let b = self.read_reg(src);
        let carry_in = self.cf;
        self.cf = self.carry_add(dst, b, carry_in);
        self.of = Self::signed_overflow_add(a, b, self.read_reg(dst));
    }

    fn adc_zero(&mut self, dst: Reg, _what: &str) {
        let a = self.read_reg(dst);
        let carry_in = self.cf;
        self.cf = self.carry_add(dst, 0, carry_in);
        self.of = Self::signed_overflow_add(a, 0, self.read_reg(dst));
    }

    fn add_mem(&mut self, dst: Reg, src: Mem, what: &str) {
        let src_value = self.read_mem(self.resolve(src));
        self.add_value(dst, src_value, false, what);
    }

    fn adc_mem(&mut self, dst: Reg, src: Mem, what: &str) {
        let src_value = self.read_mem(self.resolve(src));
        let carry_in = self.cf;
        self.add_value(dst, src_value, carry_in, what);
    }

    fn sub_mem(&mut self, dst: Reg, src: Mem, what: &str) {
        let src_value = self.read_mem(self.resolve(src));
        self.borrow_sub(dst, src_value, false, what);
    }

    fn sbb_mem(&mut self, dst: Reg, src: Mem, what: &str) {
        let src_value = self.read_mem(self.resolve(src));
        let borrow_in = self.cf;
        self.borrow_sub(dst, src_value, borrow_in, what);
    }

    fn sub_rr(&mut self, dst: Reg, src: Reg, what: &str) {
        let src_value = self.read_reg(src);
        self.borrow_sub(dst, src_value, false, what);
    }

    fn sbb_rr(&mut self, dst: Reg, src: Reg, what: &str) {
        let src_value = self.read_reg(src);
        let borrow_in = self.cf;
        self.borrow_sub(dst, src_value, borrow_in, what);
    }

    fn and_mem(&mut self, dst: Reg, src: Mem, _what: &str) {
        let value = self.read_reg(dst) & self.read_mem(self.resolve(src));
        self.write_reg(dst, value);
        // AND defines CF = OF = 0.
        self.cf = false;
        self.of = false;
    }

    fn rodata(&mut self, label: &str, values: &[u64]) {
        assert!(
            !self.rodata_labels.contains_key(label),
            "rodata label {label} declared twice",
        );
        let base = self.rodata_next;
        for (slot, value) in values.iter().enumerate() {
            self.mem.insert(base + 8 * slot as u64, *value);
        }
        // 64-byte gap so an off-the-end read of one blob cannot silently
        // land in the next.
        self.rodata_next = base + 8 * values.len() as u64 + 64;
        self.rodata_labels.insert(label.to_string(), base);
    }

    fn lea_rodata(&mut self, dst: Reg, label: &str, _what: &str) {
        let base = *self
            .rodata_labels
            .get(label)
            .unwrap_or_else(|| panic!("lea of undeclared rodata label {label}"));
        self.write_reg(dst, base);
    }

    fn shld_imm(&mut self, dst: Reg, src: Reg, imm: u32, _what: &str) {
        assert!((1..64).contains(&imm), "shift count in 1..=63");
        let value = (self.read_reg(dst) << imm) | (self.read_reg(src) >> (64 - imm));
        self.write_reg(dst, value);
        // Shifts leave CF/OF in shift-defined states no schedule relies on;
        // poison them so no chain crosses.
        self.cf = true;
        self.of = true;
    }

    fn shr_imm(&mut self, dst: Reg, imm: u32, _what: &str) {
        assert!((1..64).contains(&imm), "shift count in 1..=63");
        let value = self.read_reg(dst) >> imm;
        self.write_reg(dst, value);
        self.cf = true;
        self.of = true;
    }

    fn cmov_carry(&mut self, dst: Reg, src: Reg, _what: &str) {
        if self.cf {
            let value = self.read_reg(src);
            self.write_reg(dst, value);
        }
    }

    fn add_imm(&mut self, dst: Reg, imm: i32, _what: &str) {
        let a = self.read_reg(dst);
        let b = imm as i64 as u64;
        self.cf = self.carry_add(dst, b, false);
        self.of = Self::signed_overflow_add(a, b, self.read_reg(dst));
    }

    fn stride_loop(
        &mut self,
        cursor: Reg,
        step: i32,
        end: LoopEnd,
        _label: &str,
        body: &mut dyn FnMut(&mut Self),
    ) {
        // Trip proof: the bound is strictly ahead of the cursor by a positive
        // multiple of the step, so `jne` terminates by exact equality.
        assert!(step > 0, "only forward strides are modeled");
        let start = self.read_reg(cursor);
        let end_value = |interp: &Self| match end {
            LoopEnd::Reg(reg) => interp.read_reg(reg),
            LoopEnd::Imm(imm) => imm as i64 as u64,
            LoopEnd::Mem(addr) => interp.read_mem(interp.resolve(addr)),
        };
        let span = end_value(self).wrapping_sub(start);
        assert!(
            span > 0 && span % step as u64 == 0,
            "stride {step} from {start:#x} cannot hit the bound exactly",
        );
        loop {
            body(self);
            self.add_imm(cursor, step, "");
            // `cmp cursor, end`: flags of the subtraction, result discarded.
            let a = self.read_reg(cursor);
            let b = end_value(self);
            self.cf = a < b;
            self.of = ((a ^ b) & (a ^ a.wrapping_sub(b))) >> 63 != 0;
            if a == b {
                break;
            }
            assert!(
                a.wrapping_sub(start) < span,
                "loop cursor overshot its bound",
            );
        }
    }
}

impl Interp {
    fn mulx_value(&mut self, hi: Reg, lo: Reg, src_value: u64, _what: &str) {
        assert_ne!(
            hi, lo,
            "mulx with equal destinations keeps only the high half"
        );
        let product = self.read_reg(Reg::Rdx) as u128 * src_value as u128;
        // Low half first: `mulx hi, rdx, src` legally overwrites rdx.
        self.write_reg(lo, product as u64);
        self.write_reg(hi, (product >> 64) as u64);
    }

    fn add_value(&mut self, dst: Reg, b: u64, carry_in: bool, _what: &str) {
        let a = self.read_reg(dst);
        self.cf = self.carry_add(dst, b, carry_in);
        self.of = Self::signed_overflow_add(a, b, self.read_reg(dst));
    }

    fn borrow_sub(&mut self, dst: Reg, b: u64, borrow_in: bool, _what: &str) {
        let a = self.read_reg(dst);
        let (mid, b1) = a.overflowing_sub(b);
        let (out, b2) = mid.overflowing_sub(borrow_in as u64);
        self.write_reg(dst, out);
        self.cf = b1 | b2;
        self.of = ((a ^ b) & (a ^ out)) >> 63 != 0;
    }
}
