//! GNU-as AArch64 emitter. Every A64 instruction is four bytes, so the size
//! model is exact by construction: bytes = 4 * instructions.

use super::machine::{MachineA64, Reg};

/// Comments use `/* */` so GNU as and clang's integrated assembler agree.
const COMMENT_COLUMN: usize = 34;

#[derive(Default)]
pub struct EmitterA64 {
    lines: Vec<String>,
    instructions: usize,
}

impl EmitterA64 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn instructions(&self) -> usize {
        self.instructions
    }

    pub fn bytes(&self) -> usize {
        4 * self.instructions
    }

    pub fn into_lines(self) -> Vec<String> {
        self.lines
    }

    fn instr(&mut self, text: String, what: &str) {
        self.instructions += 1;
        if what.is_empty() {
            self.lines.push(format!("    {text}"));
        } else {
            let pad = COMMENT_COLUMN.saturating_sub(text.len());
            self.lines
                .push(format!("    {text}{:pad$} /* {what} */", ""));
        }
    }

    fn rrr(&mut self, mnemonic: &str, rd: Reg, rn: Reg, rm: Reg, what: &str) {
        self.instr(format!("{mnemonic} {rd}, {rn}, {rm}"), what);
    }

    fn mem(base: Reg, imm: i32) -> String {
        if imm == 0 {
            format!("[{base}]")
        } else {
            format!("[{base}, #{imm}]")
        }
    }
}

impl MachineA64 for EmitterA64 {
    fn comment(&mut self, text: &str) {
        if text.is_empty() {
            self.lines.push(String::new());
        } else {
            self.lines.push(format!("    /* {text} */"));
        }
    }

    fn stp_pre(&mut self, r1: Reg, r2: Reg, imm: i32) {
        self.instr(format!("stp {r1}, {r2}, [sp, #{imm}]!"), "");
    }

    fn stp(&mut self, r1: Reg, r2: Reg, base: Reg, imm: i32, what: &str) {
        self.instr(format!("stp {r1}, {r2}, {}", Self::mem(base, imm)), what);
    }

    fn ldp(&mut self, r1: Reg, r2: Reg, base: Reg, imm: i32, what: &str) {
        self.instr(format!("ldp {r1}, {r2}, {}", Self::mem(base, imm)), what);
    }

    fn ldp_post(&mut self, r1: Reg, r2: Reg, base: Reg, imm: i32) {
        self.instr(format!("ldp {r1}, {r2}, [{base}], #{imm}"), "");
    }

    fn str_off(&mut self, r: Reg, base: Reg, imm: i32, what: &str) {
        self.instr(format!("str {r}, {}", Self::mem(base, imm)), what);
    }

    fn ldr(&mut self, r: Reg, base: Reg, imm: i32, what: &str) {
        self.instr(format!("ldr {r}, {}", Self::mem(base, imm)), what);
    }

    fn ldr_post(&mut self, r: Reg, base: Reg, imm: i32, what: &str) {
        self.instr(format!("ldr {r}, [{base}], #{imm}"), what);
    }

    fn mov_zero(&mut self, r: Reg, what: &str) {
        self.instr(format!("mov {r}, xzr"), what);
    }

    fn mul(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str) {
        self.rrr("mul", rd, rn, rm, what);
    }

    fn umulh(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str) {
        self.rrr("umulh", rd, rn, rm, what);
    }

    fn adds(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str) {
        self.rrr("adds", rd, rn, rm, what);
    }

    fn adcs(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str) {
        self.rrr("adcs", rd, rn, rm, what);
    }

    fn adc(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str) {
        self.rrr("adc", rd, rn, rm, what);
    }

    fn cinc_hs(&mut self, rd: Reg, rn: Reg, what: &str) {
        self.instr(format!("cinc {rd}, {rn}, hs"), what);
    }

    fn cmn(&mut self, rn: Reg, rm: Reg, what: &str) {
        self.instr(format!("cmn {rn}, {rm}"), what);
    }

    fn cset_hs(&mut self, rd: Reg, what: &str) {
        self.instr(format!("cset {rd}, hs"), what);
    }

    fn subs(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str) {
        self.rrr("subs", rd, rn, rm, what);
    }

    fn sbcs(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str) {
        self.rrr("sbcs", rd, rn, rm, what);
    }

    fn csel_hs(&mut self, rd: Reg, rn: Reg, rm: Reg, what: &str) {
        self.instr(format!("csel {rd}, {rn}, {rm}, hs"), what);
    }

    fn counted_loop(
        &mut self,
        counter: Reg,
        count: u32,
        label: &str,
        body: &mut dyn FnMut(&mut Self),
    ) {
        let w = counter.name32();
        self.instr(format!("mov {w}, #{count}"), "loop counter");
        self.lines.push(format!("{label}:"));
        body(self);
        self.instr(format!("subs {w}, {w}, #1"), "");
        self.instr(format!("b.ne {label}"), "");
    }

    fn ret(&mut self) {
        self.instr("ret".to_string(), "");
    }
}
