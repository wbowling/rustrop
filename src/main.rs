extern crate elf;
extern crate capstone;

use std::path::PathBuf;
use capstone::Capstone;
use capstone::arch;
use capstone::arch::BuildsCapstone;
use capstone::arch::BuildsCapstoneSyntax;
use capstone::Insn;
use std::collections::HashMap;

fn main() {
    let path = PathBuf::from("testcases/baby_stack");
    let file = match elf::File::open_path(&path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };

    let executabe = file.sections
        .iter()
        .filter({ |s| (s.shdr.flags.0 & elf::types::SHF_EXECINSTR.0) != 0});

    let mut map = HashMap::new();
    for section in executabe {
        map = dis(section.data.as_slice(), section.shdr.addr, map);
    }

    for entry in map.values() {
        println!("{}", entry);
    }
}


fn dis(bytes: &[u8], addr: u64, mut map:HashMap<String, String>) -> HashMap<String, String>{
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
                                let mut val = String::new();
                                let mut key = String::new();
                                for inst in insns.iter() {
                                    key.push_str(&format!("{} {}", inst.mnemonic().unwrap_or(""), inst.op_str().unwrap_or("")));
                                    val.push_str(&format!("0x{:x} {} {}\n", inst.address(), inst.mnemonic().unwrap_or(""), inst.op_str().unwrap_or("")));
                                    if is_ret(&inst) { break }
                                }
                                map.insert(key, val);
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

