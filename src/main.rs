extern crate elf;

use std::collections::HashSet;
use std::path::PathBuf;
use std::env;

mod gadget;
mod asm;
use gadget::Gadget;

fn main() {
    let arg1 = env::args().nth(1).expect("Must pass in arg");
    let arg2: usize = env::args().nth(2).unwrap_or("10".to_string()).parse().expect("Must be an int");

    let path = PathBuf::from(arg1);
    let file = match elf::File::open_path(&path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };

    let executable = file.sections
        .iter()
        .filter({ |s| (s.shdr.flags.0 & elf::types::SHF_EXECINSTR.0) != 0});

    let mut set: HashSet<Gadget> = HashSet::new();
    for section in executable {
        set = asm::dis(section.data.as_slice(), section.shdr.addr, set, arg2);
    }

    for entry in set {
        println!("0x{:x}: {} ", entry.addr, entry.output);
    }
}


