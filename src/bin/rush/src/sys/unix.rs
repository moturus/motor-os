//! Unix host terminal backend.
//!
//! This is the ONLY place in the crate that may touch termios. It exists so the
//! shell is comfortable to develop and test on Linux; the portable contract
//! (see `sys` module docs) is that the console is always raw and driven purely
//! with ANSI escape sequences, which is what the Motor OS backend assumes.

use libc::termios as Termios;

pub struct HostTerm {
    cooked_termios: Termios,
    raw_termios: Termios,
}

impl HostTerm {
    pub fn new() -> Self {
        let mut cooked_termios: Termios = unsafe { core::mem::zeroed() };
        unsafe {
            libc::tcgetattr(libc::STDOUT_FILENO, &mut cooked_termios);
        }

        let mut raw_termios: Termios = cooked_termios;
        // We do not call 'libc::cfmakeraw(&mut raw_termios)'
        // at the resulting terminal becomes too raw. We need it
        // slightly cooked.

        raw_termios.c_iflag &=
            !(libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON);

        // raw_termios.c_oflag &= !libc::OPOST;

        raw_termios.c_cflag |= libc::CS8;
        raw_termios.c_lflag &= !(libc::ECHO | libc::ICANON | libc::IEXTEN | libc::ISIG);

        Self {
            cooked_termios,
            raw_termios,
        }
    }
}

impl super::TermImpl for HostTerm {
    fn make_raw(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDOUT_FILENO, libc::TCSANOW, &self.raw_termios);
        }
    }

    fn make_cooked(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDOUT_FILENO, libc::TCSANOW, &self.cooked_termios);
        }
    }

    fn on_exit(&mut self) {
        self.make_cooked(); // Restore termios.
    }
}
