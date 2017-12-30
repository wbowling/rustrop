extern crate capstone;

use self::capstone::{Capstone, arch, Insn};
use self::capstone::arch::{BuildsCapstone, BuildsCapstoneSyntax};
use std::collections::HashSet;

use gadget::Gadget;

pub fn dis(bytes: &[u8], addr: u64, max: usize, min: usize) -> Vec<Gadget> {
    let mut found = HashSet::new();
    let mut list: Vec<Gadget> = Vec::new();
    let cs: Capstone = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build().expect("err");

    for x in 0..bytes.len().into() {
            for y in 0..(max*4) {
                let start = if x >= y {
                    x - y
                } else {
                    0
                };

                match cs.disasm_all(&bytes[start..(x + 1)], addr+start as u64) {
                    Ok(insns) => {
                        match insns.iter().last() {
                            Some(ref inst) if is_ret(inst) => {
                                let mut asm = Vec::new();
                                for inst in insns.iter() {
                                    let done = is_ret(&inst);
                                    asm.push(inst);
                                    if done { break }
                                }

                                if asm.len() >= min && asm.len() <= max {
                                    let addr = asm.first().map({ |i| i.address() });
                                    if let Some(a) = addr {
                                        if !found.contains(&a) {
                                            found.insert(a);
                                            list.push(Gadget::new(a, asm));
                                        }
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
    list
}

fn is_ret(inst: &Insn) -> bool {
    inst.mnemonic().unwrap_or("").starts_with("ret")
}