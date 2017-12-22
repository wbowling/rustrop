extern crate elf;
extern crate clap;
extern crate regex;

use std::collections::btree_set::BTreeSet;
use std::path::PathBuf;
use clap::{Arg, App};
use regex::Regex;

mod gadget;
mod asm;
use gadget::Gadget;

fn main() {
    let matches = App::new("rustrop")
        .version("1.0")
        .author("William Bowling <will@wbowling.info>")
        .about("A tool for finding rop gadgets")
        .arg(Arg::with_name("file")
            .short("f")
            .long("file")
            .value_name("FILE")
            .help("The file to search for rop gadgets")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("inst_count")
            .short("i")
            .long("inst_count")
            .value_name("MAX")
            .help("The maximum length of the gadgets")
            .takes_value(true))
        .arg(Arg::with_name("regex")
            .short("r")
            .long("regex")
            .value_name("REGEX")
            .help("Regex to filter instructions on")
            .takes_value(true))
        .get_matches();

    let file_arg = matches.value_of("file").unwrap();
    let max_inst: usize = matches.value_of("inst_count")
        .unwrap_or("10")
        .parse()
        .expect("Must be an int");

    let regex = matches.value_of("regex").map({|r| Regex::new(r).unwrap()});

    let path = PathBuf::from(file_arg);
    let file = match elf::File::open_path(&path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };

    let executable = file.sections
        .iter()
        .filter({ |s| (s.shdr.flags.0 & elf::types::SHF_EXECINSTR.0) != 0});

    let mut set: BTreeSet<Gadget> = BTreeSet::new();
    for section in executable {
        set = asm::dis(section.data.as_slice(), section.shdr.addr, set, max_inst);
    }

    if let Some(reg) = regex {
        set = set.into_iter().filter(|g| reg.is_match(&g.output)).collect();
    }

    for entry in set {
        println!("{}", entry.color());
    }
}


