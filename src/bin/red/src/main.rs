pub mod buffer;
pub mod config;
pub mod editor;
pub mod input;
pub mod syntax;
pub mod terminal;

use config::Config;
use editor::Editor;
use input::{Key, read_key};
use terminal::TerminalGuard;

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

    while !editor.quit_requested {
        editor.scroll();
        editor.draw();

        match read_key() {
            // The terminal is gone: there are no more keys coming, and nowhere
            // left to paint. (Asking again forever is what red used to do.)
            Key::None => break,
            // Only redraws everything if the size really changed, so a window
            // that is sitting still never flickers.
            Key::Resize(rows, cols) => editor.apply_terminal_size(rows, cols),
            key => editor.process_keypress(key),
        }
    }
}
