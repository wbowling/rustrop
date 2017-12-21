extern crate capstone;

use std::hash::{Hash, Hasher};
use self::capstone::Insn;

pub struct Gadget {
    pub addr: u64,
    //    asm: Vec<Insn>,
    pub output: String,
}

impl Gadget {
    pub fn new(addr: u64, asm: Vec<Insn>) -> Gadget {
        let output: Vec<String> = asm.iter()
            .map({|inst| format!("{} {}", inst.mnemonic().unwrap_or(""), inst.op_str().unwrap_or(""))})
            .collect();
        Gadget { addr: addr, output: output.join("; ") }
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
