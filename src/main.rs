extern crate elf;
extern crate clap;
extern crate regex;

use std::collections::btree_set::BTreeSet;
use std::path::PathBuf;
use clap::{Arg, App};
use regex::Regex;

mod gadget;
mod asm;
mod prompt;
use gadget::Gadget;

fn main() {
//    prompt::prompt();
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
        .arg(Arg::with_name("max")
            .short("m")
            .long("max")
            .value_name("MAX")
            .help("The maximum length of the gadgets")
            .takes_value(true))
        .arg(Arg::with_name("min")
            .short("n")
            .long("min")
            .value_name("MIN")
            .help("The minimum length of the gadgets")
            .takes_value(true))
        .arg(Arg::with_name("regex")
            .short("r")
            .long("regex")
            .value_name("REGEX")
            .help("Regex to filter instructions on")
            .takes_value(true))
        .arg(Arg::with_name("duplicates")
            .short("d")
            .long("duplicates")
            .help("Show duplicate gadgets")
            .takes_value(false))
        .get_matches();

    let file_arg = matches.value_of("file").unwrap();
    let max: usize = matches.value_of("max")
        .unwrap_or("5")
        .parse()
        .expect("Must be an int");
    let min: usize = matches.value_of("min")
        .unwrap_or("1")
        .parse()
        .expect("Must be an int");

    let duplicates: bool = matches.is_present("duplicates");

    let regex = matches.value_of("regex").map({|r| Regex::new(r).unwrap()});

    let path = PathBuf::from(file_arg);
    let file = match elf::File::open_path(&path) {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}", e),
    };

    let executable = file.sections
        .iter()
        .filter({ |s| (s.shdr.flags.0 & elf::types::SHF_EXECINSTR.0) != 0});

    let mut instr: Vec<Gadget> = Vec::new();

    if !duplicates {
        let mut set: BTreeSet<Gadget> = BTreeSet::new();
        for section in executable {
            set.extend(asm::dis(section.data.as_slice(), section.shdr.addr, max, min));
        }
        instr.extend(set);
    } else {
        for section in executable {
            instr.extend(asm::dis(section.data.as_slice(), section.shdr.addr, max, min));
        }
    }


    if let Some(reg) = regex {
        instr = instr.into_iter().filter(|g| reg.is_match(&g.output)).collect();
    }

    instr.sort();
    for entry in instr {
        println!("{}", entry.color());
    }
}


