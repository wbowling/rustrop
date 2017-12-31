extern crate capstone;
extern crate elf;

use self::capstone::{Capstone, arch, Insn};
use self::capstone::arch::{BuildsCapstone, BuildsCapstoneSyntax};
use std::collections::HashSet;
use self::elf::types::FileHeader;

use gadget::Gadget;

pub fn dis(file_type: FileHeader, bytes: &[u8], addr: u64, depth: usize) -> Vec<Gadget> {
    let mut found = HashSet::new();
    let mut list: Vec<Gadget> = Vec::new();

    let cs: Capstone = match file_type {
        FileHeader { machine: elf::types::EM_X86_64, .. } => {
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build().expect("err")
        },
        FileHeader { machine: elf::types::EM_386, .. } => {
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build().expect("err")
        },
        FileHeader { machine: elf::types::EM_ARM, .. } => {
            Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .detail(true)
                .build().expect("err")
        },
        FileHeader { machine: elf::types::EM_AARCH64, .. } => {
            Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build().expect("err")
        },
        _ => panic!("Unsupported file type: {:?}", file_type),
    };

    for x in 0..bytes.len().into() {
            for y in 0..(depth*4) {
                let start = if x >= y {
                    x - y
                } else {
                    0
                };

                match cs.disasm_all(&bytes[start..(x + 1)], addr+start as u64) {
                    Ok(insns) => {
                        match insns.iter().last() {
                            Some(ref inst) if is_end(inst) => {
                                let mut asm = Vec::new();
                                for inst in insns.iter() {
                                    let done = is_end(&inst);
                                    asm.push(inst);
                                    if done { break }
                                }

                                let addr = asm.first().map({ |i| i.address() });
                                if let Some(a) = addr {
                                    if !found.contains(&a) {
                                        found.insert(a);
                                        list.push(Gadget::new(a, asm));
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

fn is_end(inst: &Insn) -> bool {
 is_ret(inst) || is_jmp(inst) || is_call(inst)
}

fn is_ret(inst: &Insn) -> bool {
    inst.mnemonic().unwrap_or("").starts_with("ret") ||
        (inst.mnemonic().unwrap_or("") == "bx" && inst.op_str().unwrap_or("") == "lr") ||
        (inst.mnemonic().unwrap_or("") == "pop" && inst.op_str().unwrap_or("").contains("pc"))
}

fn is_jmp(inst: &Insn) -> bool {
    inst.mnemonic().unwrap_or("").starts_with("j") && !inst.op_str().unwrap_or("").starts_with("0x")
}

fn is_call(inst: &Insn) -> bool {
    inst.mnemonic().unwrap_or("").starts_with("call") && !inst.op_str().unwrap_or("").starts_with("0x")
}