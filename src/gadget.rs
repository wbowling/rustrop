extern crate capstone;
extern crate ansi_term;

use std::hash::{Hash, Hasher};
use self::capstone::Insn;
use self::ansi_term::Colour::{Red, Yellow, Cyan};
use std::cmp::Ordering;

pub struct Gadget {
    pub addr: u64,
        asm: Vec<Insn>,
    pub output: String,
}

impl Gadget {
    pub fn new(addr: u64, asm: Vec<Insn>) -> Gadget {
        let output: Vec<String> = asm.iter()
            .map(|inst| {
                let mut s = String::with_capacity(50);
                s.push_str(inst.mnemonic().unwrap_or(""));
                s.push_str(" ");
                s.push_str(inst.op_str().unwrap_or(""));
                s
            }).collect();
        Gadget { addr: addr, asm: asm, output: output.join("; ") }
    }

    pub fn color(&self) -> String {
        let offset = Cyan.paint(format!("0x{:x}", self.addr));
        let output: Vec<String> = self.asm.iter()
            .map(|inst| {
                let mut s = String::with_capacity(100);

                s.push_str(&Red.paint(inst.mnemonic().unwrap_or("")).to_string());
                s.push_str(" ");
                s.push_str(&Yellow.paint(inst.op_str().unwrap_or("")).to_string());

                s
            }).collect();

        format!("{}: {}", offset, output.join("; "))
    }
}

impl PartialEq for Gadget {
    fn eq(&self, other: &Gadget) -> bool {
        self.output == other.output
    }
}

impl Eq for Gadget {}

impl Hash for Gadget {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.output.hash(state);
    }
}

impl PartialOrd for Gadget {
    fn partial_cmp(&self, other: &Gadget) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Gadget {
    fn cmp(&self, other: &Gadget) -> Ordering {
        self.output.cmp(&other.output)
    }
}
