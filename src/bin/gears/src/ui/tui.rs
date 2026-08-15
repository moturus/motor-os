//! Safe terminal lifecycle and minimal drawing for the interactive UI.

use std::io::{self, Write};

use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::style::Print;
use crossterm::terminal::{
    Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{execute, queue};

use super::state::{Activity, State};
use crate::agent::bus::ROOT;

pub trait Surface {
    fn enter(&mut self) -> io::Result<()>;
    fn size(&self) -> io::Result<(u16, u16)>;
    fn draw(&mut self, lines: &[String]) -> io::Result<()>;
    fn leave(&mut self) -> io::Result<()>;
}

/// An entered alternate screen. Every return path restores it through Drop.
pub struct Screen<S: Surface> {
    surface: S,
    active: bool,
}

impl<S: Surface> Screen<S> {
    pub fn open(mut surface: S, state: &State) -> io::Result<Screen<S>> {
        surface.enter()?;
        let mut screen = Screen {
            surface,
            active: true,
        };
        if let Err(error) = screen.redraw(state) {
            screen.close();
            return Err(error);
        }
        Ok(screen)
    }

    /// Redrawing also handles resize: the current dimensions are read once
    /// for this complete frame rather than retained across terminal events.
    pub fn redraw(&mut self, state: &State) -> io::Result<()> {
        let size = self.surface.size()?;
        self.surface.draw(&frame(state, size))
    }

    pub fn close(&mut self) {
        if self.active {
            self.active = false;
            let _ = self.surface.leave();
        }
    }
}

impl<S: Surface> Drop for Screen<S> {
    fn drop(&mut self) {
        self.close();
    }
}

pub struct Crossterm<W: Write> {
    out: W,
    entered: bool,
}

impl<W: Write> Crossterm<W> {
    pub fn new(out: W) -> Crossterm<W> {
        Crossterm {
            out,
            entered: false,
        }
    }
}

impl<W: Write> Surface for Crossterm<W> {
    fn enter(&mut self) -> io::Result<()> {
        enable_raw_mode()?;
        if let Err(error) = execute!(self.out, EnterAlternateScreen, Hide) {
            let _ = execute!(self.out, Show, LeaveAlternateScreen);
            let _ = disable_raw_mode();
            return Err(error);
        }
        self.entered = true;
        Ok(())
    }

    fn size(&self) -> io::Result<(u16, u16)> {
        crossterm::terminal::size()
    }

    fn draw(&mut self, lines: &[String]) -> io::Result<()> {
        queue!(self.out, MoveTo(0, 0), Clear(ClearType::All))?;
        for (row, line) in lines.iter().enumerate() {
            queue!(self.out, MoveTo(0, row as u16), Print(line))?;
        }
        self.out.flush()
    }

    fn leave(&mut self) -> io::Result<()> {
        if !self.entered {
            return Ok(());
        }
        self.entered = false;
        let terminal = execute!(self.out, Show, LeaveAlternateScreen);
        let raw = disable_raw_mode();
        terminal.and(raw)
    }
}

fn frame(state: &State, (width, height): (u16, u16)) -> Vec<String> {
    let mut lines = vec!["Motor OS Gears".to_string()];
    let activity = match state.activity(ROOT).unwrap_or(&Activity::Idle) {
        Activity::Idle => "idle".to_string(),
        Activity::Model => "model".to_string(),
        Activity::Tool { detail, elapsed } => {
            format!("tool {:.1}s: {detail}", elapsed.as_secs_f64())
        }
        Activity::Permission { detail } => format!("permission: {detail}"),
        Activity::Cancelled => "cancelled".to_string(),
        Activity::Failed { detail } => format!("failed: {detail}"),
        Activity::Completed => "completed".to_string(),
        Activity::Exited => "exited".to_string(),
    };
    lines.push(activity);
    if let Some(task) = state.task() {
        lines.push(task.compact());
    }
    lines
        .into_iter()
        .take(usize::from(height))
        .map(|line| safe_width(&line, usize::from(width)))
        .collect()
}

fn safe_width(text: &str, width: usize) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(width)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Default)]
    struct Calls {
        entered: usize,
        left: usize,
        frames: Vec<Vec<String>>,
    }

    struct Fake {
        calls: Rc<RefCell<Calls>>,
        size: (u16, u16),
        fail_enter: bool,
        fail_draw: bool,
    }

    impl Surface for Fake {
        fn enter(&mut self) -> io::Result<()> {
            if self.fail_enter {
                return Err(io::Error::other("setup failed"));
            }
            self.calls.borrow_mut().entered += 1;
            Ok(())
        }

        fn size(&self) -> io::Result<(u16, u16)> {
            Ok(self.size)
        }

        fn draw(&mut self, lines: &[String]) -> io::Result<()> {
            if self.fail_draw {
                return Err(io::Error::other("draw failed"));
            }
            self.calls.borrow_mut().frames.push(lines.to_vec());
            Ok(())
        }

        fn leave(&mut self) -> io::Result<()> {
            self.calls.borrow_mut().left += 1;
            Ok(())
        }
    }

    fn fake(calls: Rc<RefCell<Calls>>) -> Fake {
        Fake {
            calls,
            size: (80, 24),
            fail_enter: false,
            fail_draw: false,
        }
    }

    #[test]
    fn setup_redraw_resize_and_drop_are_balanced() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        let mut screen = Screen::open(fake(calls.clone()), &State::new()).unwrap();
        screen.surface.size = (5, 1);
        screen.redraw(&State::new()).unwrap();
        drop(screen);
        let calls = calls.borrow();
        assert_eq!((calls.entered, calls.left, calls.frames.len()), (1, 1, 2));
        assert_eq!(calls.frames[1], ["Motor"]);
    }

    #[test]
    fn setup_and_output_failures_restore_exactly_when_needed() {
        let calls = Rc::new(RefCell::new(Calls::default()));
        let mut setup = fake(calls.clone());
        setup.fail_enter = true;
        assert!(Screen::open(setup, &State::new()).is_err());
        assert_eq!(calls.borrow().left, 0);

        let mut output = fake(calls.clone());
        output.fail_draw = true;
        assert!(Screen::open(output, &State::new()).is_err());
        assert_eq!(calls.borrow().left, 1);
    }

    #[test]
    fn frame_text_cannot_inject_terminal_controls() {
        let mut state = State::new();
        state.apply(&crate::agent::bus::Event::Failed {
            agent: ROOT,
            text: "bad\x1b[2J\nnext".into(),
        });
        let rendered = frame(&state, (80, 24)).join("\n");
        assert!(!rendered.contains('\x1b'), "{rendered:?}");
        assert!(!rendered.contains("\nnext"), "{rendered:?}");
    }
}
