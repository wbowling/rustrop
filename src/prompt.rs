extern crate rustyline;
extern crate ansi_term;

use self::rustyline::error::ReadlineError;
use self::rustyline::Editor;
use self::ansi_term::Colour::Green;

pub fn prompt(f: &Fn(String) -> ()) {
    // `()` can be used when no completer is required
    let mut rl = Editor::<()>::new();
    if let Err(_) = rl.load_history("history.txt") {
        println!("No previous history.");
    }
    loop {
        let readline = rl.readline(&Green.paint(">> ").to_string());
        match readline {
            Ok(line) => {
                rl.add_history_entry(&line);
                f(line);
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