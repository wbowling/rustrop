extern crate elf;
extern crate capstone;

use std::path::PathBuf;
use capstone::{Capstone, arch, Insn};
use capstone::arch::{BuildsCapstone, BuildsCapstoneSyntax};
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::env;

pub struct Gadget {
    addr: u64,
    asm: Vec<Insn>,
    output: String,
}

impl Gadget {
    pub fn new(addr: u64, asm: Vec<Insn>) -> Gadget {
        let output = asm.iter()
                            .map({|inst| format!("{} {}\n", inst.mnemonic().unwrap_or(""), inst.op_str().unwrap_or(""))})
                            .collect();
        Gadget { addr: addr, asm: asm, output: output }
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

fn main() {
    let arg1 = env::args().nth(1).expect("Must pass in arg");

    let path = PathBuf::from(arg1);
    let file = match elf::File::open_path(&path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };

    let executabe = file.sections
        .iter()
        .filter({ |s| (s.shdr.flags.0 & elf::types::SHF_EXECINSTR.0) != 0});

    let mut set = HashSet::new();
    for section in executabe {
        set = dis(section.data.as_slice(), section.shdr.addr, set);
    }

    for entry in set {
        println!("Found 0x{:x}:\n{}\n", entry.addr, entry.output);
    }
}


fn dis(bytes: &[u8], addr: u64, mut map:HashSet<Gadget>) -> HashSet<Gadget>{
    let cs: Capstone = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build().expect("err");

    for x in 0..bytes.len().into() {

        if bytes[x] == 0xc3 || bytes[x] == 0xc2 {
            for y in 0..10 {
                let start = if x >= y {
                    x - y
                } else {
                    0
                };

                match cs.disasm_all(&bytes[start..(x + 1)], addr+start as u64) {
                    Ok(insns) => {
                        match insns.iter().last() {
                            Some(ref inst) if is_ret(inst) => {
                                let mut key = String::new();
                                let mut asm = Vec::new();
                                for inst in insns.iter() {
                                    key.push_str(&format!("{} {}\n", inst.mnemonic().unwrap_or(""), inst.op_str().unwrap_or("")));
                                    let done = is_ret(&inst);
                                    asm.push(inst);
                                    if done { break }
                                }
                                let addr = asm.first().map({|i| i.address()});
                                if let Some(a) = addr {
                                    map.insert(Gadget::new(a, asm));
                                }

                            },
                            _ => {}
                        }
                    },
                    Err(_) => ()
                }
            }
        }
    }
    map
}

fn is_ret(inst: &Insn) -> bool {
    inst.mnemonic().unwrap_or("").starts_with("ret")
}

