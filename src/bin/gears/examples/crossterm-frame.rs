//! Retained proof of the exact terminal dependency shape Gears will use.

use std::io::{self, Write};

use crossterm::terminal::{
    Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{cursor, execute};

fn main() -> io::Result<()> {
    let mut output = io::stdout().lock();
    execute!(output, EnterAlternateScreen, cursor::Hide)?;
    let frame = (|| {
        enable_raw_mode()?;
        execute!(output, Clear(ClearType::All), cursor::MoveTo(0, 0))?;
        write!(output, "gears-crossterm-frame")?;
        output.flush()
    })();

    let raw_restore = disable_raw_mode();
    let screen_restore = execute!(output, cursor::Show, LeaveAlternateScreen);
    frame?;
    raw_restore?;
    screen_restore?;
    writeln!(output, "frame=restored")
}
