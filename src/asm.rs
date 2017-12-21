extern crate capstone;

use self::capstone::{Capstone, arch, Insn};
use self::capstone::arch::{BuildsCapstone, BuildsCapstoneSyntax};
use std::collections::HashSet;

use gadget::Gadget;

pub fn dis(bytes: &[u8], addr: u64, mut map:HashSet<Gadget>, num: usize) -> HashSet<Gadget>{
    let cs: Capstone = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build().expect("err");

    for x in 0..bytes.len().into() {

        if bytes[x] == 0xc3 || bytes[x] == 0xc2 {
            for y in 0..(num*4) {
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

                                if asm.len() == num {
                                    let addr = asm.first().map({ |i| i.address() });
                                    if let Some(a) = addr {
                                        map.insert(Gadget::new(a, asm));
                                    }
                                }

                            },
                            _ => {}
                        }
                    },
                    _ => ()
                }
            }
        }
    }
    map
}

fn is_ret(inst: &Insn) -> bool {
    inst.mnemonic().unwrap_or("").starts_with("ret")
}