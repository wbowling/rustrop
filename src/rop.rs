extern crate elf;

use gadget::Gadget;
use regex::Regex;
use std::path::PathBuf;
use asm;
use prompt;

pub struct RustRop {
    file_path: PathBuf,
    instr: Vec<Gadget>,
    duplicates: bool,
    min: usize,
    max: usize,
    depth: usize,
}

impl RustRop {
    pub fn new(file: String) -> RustRop {
        let mut rop = RustRop { file_path: PathBuf::from(file), duplicates: false, min: 1, max: 6, depth: 6, instr: vec![] };
        rop.load_gadgets();
        rop
    }

    pub fn prompt(&mut self) {
        let commands: Vec<String> = vec!["search".to_string(), "s".to_string(), "help".to_string(), "h".to_string(), "min".to_string(), "max".to_string(), "depth".to_string(), "file".to_string(), "duplicates".to_string()];

        prompt::prompt(commands, &mut |line: String| {
            let mut args: Vec<&str> = line.split(" ").collect();
            if args.len() > 0 {
                let first = args.remove(0);
                let remain: String = args.join(" ");
                match first {
                    "help" | "h" => self.help_handler(remain),
                    "search" | "s" => self.search_handler(remain),
                    "min" => self.set_min(remain),
                    "max" => self.set_max(remain),
                    "depth" => self.set_depth(remain),
                    "file" => self.set_file(remain),
                    "duplicates" => self.set_duplicates(remain),
                    _ => println!("Unknown command"),
                }
            } else {
                println!("Unknown command");
            }
        });
    }

    fn search_handler(&self, line: String) {
        let res = Regex::new(&line);
        match res {
            Ok(regex) => {
                let mut filtered: Vec<&Gadget> = self.instr.iter().filter(|g| {
                    g.len() <= self.max
                        && g.len() >= self.min
                        && regex.is_match(&g.output)
                }).collect();

                if !self.duplicates {
                    filtered.dedup();
                }

                for entry in filtered {
                    println!("{}", entry.color());
                }
            }
            Err(e) => println!("Regex error {:?}", e)
        }
    }

    fn set_min(&mut self, line: String) {
        let res = line.parse::<usize>();
        match res {
            Ok(m) => {
                self.min = m;
                println!("Done");
            },
            Err(e) => println!("Error {:?}", e)
        }
    }

    fn set_max(&mut self, line: String) {
        let res = line.parse::<usize>();
        match res {
            Ok(m) => {
                self.max = m;
                println!("Done");
            },
            Err(e) => println!("Error {:?}", e)
        }
    }

    fn set_depth(&mut self, line: String) {
        let old_depth = self.depth;
        let res = line.parse::<usize>();
        match res {
            Ok(d) => self.depth = d,
            Err(e) => println!("Error {:?}", e)
        }
        if self.depth > old_depth {
            self.load_gadgets();
        } else {
            println!("Done");
        }
    }

    fn set_file(&mut self, line: String) {
        self.file_path = PathBuf::from(line);
        self.load_gadgets();
    }

    fn set_duplicates(&mut self, line: String) {
        let res = line.parse::<bool>();
        match res {
            Ok(d) => {
                self.duplicates = d;
                println!("Done");
            }
            Err(e) => println!("Error {:?}", e)
        }
    }

    fn help_handler(&self, _line: String) {
        println!("Available commands:");
        println!("-------------------");
        println!("help|h - Show this message");
        println!("search|s - Regex search of gadgets");
        println!("max - Max gadget chain length");
        println!("min - Min gadget chain length");
        println!("depth - Search for gadgets up to this length");
        println!("duplicates - Show duplicates");
        println!("file - Change the file to search for gadgets in");
    }

    fn load_gadgets(&mut self) {
        println!("Loading gadgets...");
        let file = match elf::File::open_path(&self.file_path) {
            Ok(f) => f,
            Err(e) => panic!("Error: {:?}", e),
        };

        let executable = file.sections
            .iter()
            .filter({ |s| (s.shdr.flags.0 & elf::types::SHF_EXECINSTR.0) != 0});

        let mut instr: Vec<Gadget> = Vec::new();

        for section in executable {
            instr.extend(asm::dis(file.ehdr, section.data.as_slice(), section.shdr.addr, self.depth));
        }
        instr.sort();
        println!("Done");
        self.instr = instr;
    }
}