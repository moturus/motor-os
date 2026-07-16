pub mod buffer;
pub mod config;
pub mod editor;
pub mod input;
pub mod terminal;
pub mod syntax;

use config::Config;
use editor::Editor;
use input::{read_key, Key};
use terminal::TerminalGuard;
use std::time::{Instant, Duration};
use std::io::{self, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let filenames = if args.len() > 1 {
        args[1..].to_vec()
    } else {
        Vec::new()
    };

    // Read the config before raw mode, but report any complaint about it through
    // the status bar once the editor is up.
    let (config, config_complaint) = Config::load();

    // Instantiate terminal guard to safely enter raw mode and restore it on drop
    let _guard = TerminalGuard::new();

    let mut editor = Editor::new(filenames, config);
    if let Some(complaint) = config_complaint {
        editor.set_status(&complaint);
    }
    let mut last_query = Instant::now();

    while !editor.quit_requested {
        editor.scroll();
        editor.draw();

        let key = read_key();
        if key != Key::None {
            match key {
                Key::TerminalResponse(rows, cols) => {
                    // Update editor size. Only redraws everything if the size
                    // actually changed, so a stable window never flickers.
                    editor.apply_terminal_size(rows, cols);
                }
                _ => {
                    editor.process_keypress(key);
                }
            }
        } else {
            // Idle: query terminal size at most once every 1 second
            if last_query.elapsed() > Duration::from_secs(1) {
                // Query size invisibly (hide cursor, jump to 9999;9999, query)
                // The cursor will be restored to its correct position during the next draw() cycle!
                print!("\x1b[?25l\x1b[9999;9999H\x1b[6n");
                let _ = io::stdout().flush();
                last_query = Instant::now();
            }
        }
    }
}
