//! Autocompletion logic
//! It gets engaged when you press Tab after entering partial command and does the following:
//! - if there're no spaces in the line - lookup respective binary
//! - if there're spaces - extract first argument as a binary and call a helper for the command

pub fn try_complete(partial_cmdline: &str) -> Option<String> {
    if partial_cmdline.is_empty() {
        return None; // nothing to complete
    }

    todo!("tokenize")
}
