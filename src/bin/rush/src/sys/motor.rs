//! Motor OS terminal backend.
//!
//! Motor OS has no termios: the console is always raw and is driven entirely
//! with ANSI escape sequences (see the `sys` module docs). There is therefore
//! no raw/cooked mode to toggle, so mode control is a no-op. Input bytes are
//! read directly and the shell owns all echo and line editing.

pub struct MotorTerm;

impl MotorTerm {
    pub fn new() -> Self {
        Self
    }
}

impl super::TermImpl for MotorTerm {
    // make_raw / make_cooked / on_exit intentionally use the default no-op
    // implementations: the console is already raw and cannot be reconfigured.
}
