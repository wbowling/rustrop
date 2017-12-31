extern crate rustyline;
extern crate ansi_term;

use self::rustyline::error::ReadlineError;
use self::rustyline::{Editor, Result};
use self::rustyline::completion::Completer;

use self::ansi_term::Colour::Green;

pub fn prompt(commands: Vec<String>, handler: &mut FnMut(String) -> ()) {
    let mut rl = Editor::<CommandCompleter>::new();
    rl.set_completer(Some(CommandCompleter::new(commands)));
    rl.load_history("history.txt").ok();

    loop {
        let readline = rl.readline(&Green.paint(">> ").to_string());
        match readline {
            Ok(ref line) if line == "exit" || line == "quit"  => break,
            Ok(line) => {
                rl.add_history_entry(&line);
                handler(line);
            },
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                break
            },
            Err(err) => {
                println!("Error: {:?}", err);
                break
            }
        }
    }
    rl.save_history("history.txt").unwrap();
}

pub struct CommandCompleter {
    commands: Vec<String>
}

impl CommandCompleter {
    pub fn new(commands: Vec<String>) -> CommandCompleter {
        CommandCompleter { commands: commands }
    }
}

impl Completer for CommandCompleter {
    fn complete(&self, line: &str, _pos: usize) -> Result<(usize, Vec<String>)> {
        let mut completions : Vec<String> = Vec::new();
        for command in &self.commands {
            if command.starts_with(line) {
                completions.push(command.to_string());
            }
        }

        Ok((0, completions))
    }
}