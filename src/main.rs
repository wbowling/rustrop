extern crate elf;
extern crate clap;
extern crate regex;



use clap::{Arg, App};
use rop::RustRop;

mod gadget;
mod asm;
mod prompt;
mod rop;

fn main() {
    let matches = App::new("rustrop")
        .version("1.0")
        .author("William Bowling <will@wbowling.info>")
        .about("A tool for finding rop gadgets")
        .arg(Arg::with_name("file")
            .value_name("FILE")
            .help("The file to search for rop gadgets")
            .index(1)
            .required(true))
        .get_matches();

    let file_arg = matches.value_of("file").unwrap();
    let mut rop = RustRop::new(file_arg.to_string());

    rop.prompt();

}


