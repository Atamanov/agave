//! GNU-as Intel-syntax emitter with an exact byte-count model.
//!
//! Every instruction form the [`super::machine::Machine`] trait exposes has a
//! fixed, statically known encoding length; the sums appear in the generated
//! file's provenance header and are cross-checked against the assembled
//! object on real x86-64 hardware.

use super::machine::{LoopEnd, Machine, Mem, Reg};

/// Comments use `/* */` so GNU as, clang's integrated assembler, and the
/// repository source-surface audit all agree on what is a comment.
const COMMENT_COLUMN: usize = 34;

#[derive(Default)]
pub struct Emitter {
    lines: Vec<String>,
    instructions: usize,
    bytes: usize,
    rodata: Vec<(String, Vec<u64>)>,
}

/// SIB and displacement bytes of `addr`, on top of REX.W + opcode + ModRM.
/// `rsp`/`r12` bases force a SIB byte (their ModRM r/m encoding means "SIB
/// follows"); `rbp`/`r13` bases have no disp-free form (mod = 00 there means
/// rip-relative), so they pay disp8 even at offset 0; offsets outside imm8
/// range pay disp32.
fn mem_extra_len(addr: Mem) -> usize {
    let sib = matches!(addr.base, Reg::Rsp | Reg::R12) as usize;
    let disp = if addr.offset == 0 && !matches!(addr.base, Reg::Rbp | Reg::R13) {
        0
    } else if (-128..128).contains(&addr.offset) {
        1
    } else {
        4
    };
    sib + disp
}

impl Emitter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn instructions(&self) -> usize {
        self.instructions
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn into_lines(self) -> Vec<String> {
        self.lines
    }

    /// Bytes of declared `.rodata` tables (not part of the text byte model).
    pub fn rodata_bytes(&self) -> usize {
        self.rodata.iter().map(|(_, values)| 8 * values.len()).sum()
    }

    pub fn into_parts(self) -> (Vec<String>, Vec<(String, Vec<u64>)>) {
        (self.lines, self.rodata)
    }

    fn instr(&mut self, text: String, bytes: usize, what: &str) {
        self.instructions += 1;
        self.bytes += bytes;
        if what.is_empty() {
            self.lines.push(format!("    {text}"));
        } else {
            let pad = COMMENT_COLUMN.saturating_sub(text.len());
            self.lines
                .push(format!("    {text}{:pad$} /* {what} */", ""));
        }
    }

    /// REX.W + opcode + ModRM: every 64-bit reg-reg ALU/mov form.
    fn rr(&mut self, mnemonic: &str, dst: Reg, src: Reg, bytes: usize, what: &str) {
        self.instr(format!("{mnemonic} {dst}, {src}"), bytes, what);
    }
}

impl Machine for Emitter {
    fn comment(&mut self, text: &str) {
        if text.is_empty() {
            self.lines.push(String::new());
        } else {
            self.lines.push(format!("    /* {text} */"));
        }
    }

    fn claim_flags_clear(&mut self, why: &str) {
        self.lines
            .push(format!("    /* invariant: CF = OF = 0 ({why}) */"));
    }

    fn claim_zero(&mut self, reg: Reg, why: &str) {
        self.lines
            .push(format!("    /* invariant: {reg} = 0 ({why}) */"));
    }

    fn push(&mut self, src: Reg) {
        let bytes = if src.is_extended() { 2 } else { 1 };
        self.instr(format!("push {src}"), bytes, "");
    }

    fn pop(&mut self, dst: Reg) {
        let bytes = if dst.is_extended() { 2 } else { 1 };
        self.instr(format!("pop {dst}"), bytes, "");
    }

    fn ret(&mut self) {
        self.instr("ret".to_string(), 1, "");
    }

    fn alloc_stack(&mut self, bytes: i32) {
        assert!(
            bytes > 0 && bytes % 8 == 0,
            "frame is a positive 8-multiple"
        );
        // REX.W 83 /5 ib, or REX.W 81 /5 id past imm8 range.
        let len = if bytes < 128 { 4 } else { 7 };
        self.instr(format!("sub rsp, {bytes}"), len, "");
    }

    fn free_stack(&mut self, bytes: i32) {
        assert!(
            bytes > 0 && bytes % 8 == 0,
            "frame is a positive 8-multiple"
        );
        // REX.W 83 /0 ib, or REX.W 81 /0 id past imm8 range.
        let len = if bytes < 128 { 4 } else { 7 };
        self.instr(format!("add rsp, {bytes}"), len, "");
    }

    fn load(&mut self, dst: Reg, addr: Mem, what: &str) {
        self.instr(format!("mov {dst}, {addr}"), 3 + mem_extra_len(addr), what);
    }

    fn load_indexed(&mut self, dst: Reg, base: Reg, index: Reg, what: &str) {
        assert!(
            !matches!(base, Reg::Rsp | Reg::Rbp | Reg::R12 | Reg::R13),
            "bases needing a forced displacement are not modeled",
        );
        assert_ne!(index, Reg::Rsp, "rsp cannot be an index register");
        // REX.W 8B ModRM(SIB) SIB.
        self.instr(format!("mov {dst}, [{base} + {index}]"), 4, what);
    }

    fn store(&mut self, addr: Mem, src: Reg, what: &str) {
        self.instr(format!("mov {addr}, {src}"), 3 + mem_extra_len(addr), what);
    }

    fn mov(&mut self, dst: Reg, src: Reg, what: &str) {
        self.rr("mov", dst, src, 3, what);
    }

    fn mov_zero(&mut self, dst: Reg, what: &str) {
        // REX.W C7 /0 imm32.
        self.instr(format!("mov {dst}, 0"), 7, what);
    }

    fn xor_clear(&mut self, dst: Reg, what: &str) {
        self.rr("xor", dst, dst, 3, what);
    }

    fn mulx(&mut self, hi: Reg, lo: Reg, src: Reg, what: &str) {
        assert_ne!(
            hi, lo,
            "mulx with equal destinations keeps only the high half"
        );
        // Three-byte VEX (map 0F38) + opcode + ModRM.
        self.instr(format!("mulx {hi}, {lo}, {src}"), 5, what);
    }

    fn mulx_mem(&mut self, hi: Reg, lo: Reg, addr: Mem, what: &str) {
        assert_ne!(
            hi, lo,
            "mulx with equal destinations keeps only the high half"
        );
        self.instr(
            format!("mulx {hi}, {lo}, qword ptr {addr}"),
            5 + mem_extra_len(addr),
            what,
        );
    }

    fn adox(&mut self, dst: Reg, src: Reg, what: &str) {
        // F3 REX.W 0F 38 F6 /r.
        self.rr("adox", dst, src, 6, what);
    }

    fn adcx(&mut self, dst: Reg, src: Reg, what: &str) {
        // 66 REX.W 0F 38 F6 /r.
        self.rr("adcx", dst, src, 6, what);
    }

    fn add(&mut self, dst: Reg, src: Reg, what: &str) {
        self.rr("add", dst, src, 3, what);
    }

    fn adc(&mut self, dst: Reg, src: Reg, what: &str) {
        self.rr("adc", dst, src, 3, what);
    }

    fn adc_zero(&mut self, dst: Reg, what: &str) {
        // REX.W 83 /2 imm8.
        self.instr(format!("adc {dst}, 0"), 4, what);
    }

    fn add_mem(&mut self, dst: Reg, src: Mem, what: &str) {
        self.instr(format!("add {dst}, {src}"), 3 + mem_extra_len(src), what);
    }

    fn adc_mem(&mut self, dst: Reg, src: Mem, what: &str) {
        self.instr(format!("adc {dst}, {src}"), 3 + mem_extra_len(src), what);
    }

    fn sub_mem(&mut self, dst: Reg, src: Mem, what: &str) {
        self.instr(format!("sub {dst}, {src}"), 3 + mem_extra_len(src), what);
    }

    fn sbb_mem(&mut self, dst: Reg, src: Mem, what: &str) {
        self.instr(format!("sbb {dst}, {src}"), 3 + mem_extra_len(src), what);
    }

    fn sub_rr(&mut self, dst: Reg, src: Reg, what: &str) {
        self.rr("sub", dst, src, 3, what);
    }

    fn sbb_rr(&mut self, dst: Reg, src: Reg, what: &str) {
        self.rr("sbb", dst, src, 3, what);
    }

    fn cmov_carry(&mut self, dst: Reg, src: Reg, what: &str) {
        // REX.W 0F 42 /r.
        self.rr("cmovc", dst, src, 4, what);
    }

    fn and_mem(&mut self, dst: Reg, src: Mem, what: &str) {
        // REX.W 23 /r.
        self.instr(format!("and {dst}, {src}"), 3 + mem_extra_len(src), what);
    }

    fn rodata(&mut self, label: &str, values: &[u64]) {
        assert!(
            self.rodata.iter().all(|(existing, _)| existing != label),
            "rodata label {label} declared twice",
        );
        self.rodata.push((label.to_string(), values.to_vec()));
    }

    fn lea_rodata(&mut self, dst: Reg, label: &str, what: &str) {
        assert!(
            self.rodata.iter().any(|(existing, _)| existing == label),
            "lea of undeclared rodata label {label}",
        );
        // REX.W 8D /r with RIP-relative ModRM: always disp32.
        self.instr(format!("lea {dst}, [rip + {label}]"), 7, what);
    }

    fn shld_imm(&mut self, dst: Reg, src: Reg, imm: u32, what: &str) {
        assert!((1..64).contains(&imm), "shift count in 1..=63");
        // REX.W 0F A4 /r ib.
        self.instr(format!("shld {dst}, {src}, {imm}"), 5, what);
    }

    fn shr_imm(&mut self, dst: Reg, imm: u32, what: &str) {
        assert!((1..64).contains(&imm), "shift count in 1..=63");
        // REX.W C1 /5 ib.
        self.instr(format!("shr {dst}, {imm}"), 4, what);
    }

    fn add_imm(&mut self, dst: Reg, imm: i32, what: &str) {
        // REX.W 83 /0 ib; past imm8 range REX.W 81 /0 id, except rax's
        // dedicated REX.W 05 id form (assemblers always pick it).
        let len = if (-128..128).contains(&imm) {
            4
        } else if dst == Reg::Rax {
            6
        } else {
            7
        };
        self.instr(format!("add {dst}, {imm}"), len, what);
    }

    fn stride_loop(
        &mut self,
        cursor: Reg,
        step: i32,
        end: LoopEnd,
        label: &str,
        body: &mut dyn FnMut(&mut Self),
    ) {
        self.lines.push(format!("{label}:"));
        let bytes_at_label = self.bytes;
        body(self);
        self.add_imm(cursor, step, "advance the cursor (clobbers CF/OF)");
        match end {
            // REX.W 39 /r.
            LoopEnd::Reg(reg) => self.instr(format!("cmp {cursor}, {reg}"), 3, "back-edge test"),
            LoopEnd::Imm(imm) => {
                // REX.W 83 /7 ib, or REX.W 81 /7 id past imm8 range.
                let len = if (-128..128).contains(&imm) { 4 } else { 7 };
                self.instr(format!("cmp {cursor}, {imm}"), len, "back-edge test")
            }
            // REX.W 3B /r.
            LoopEnd::Mem(addr) => self.instr(
                format!("cmp {cursor}, {addr}"),
                3 + mem_extra_len(addr),
                "back-edge test",
            ),
        }
        // Backward jump: rel8 when label is within reach, else rel32. The
        // byte model must match what GNU as relaxes to.
        let distance = self.bytes - bytes_at_label;
        let jne_bytes = if distance + 2 <= 128 { 2 } else { 6 };
        self.instr(format!("jne {label}"), jne_bytes, "");
    }
}
