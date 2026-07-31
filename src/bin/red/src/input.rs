//! Keys, as the editor names them.
//!
//! The bytes below this are crossterm's: an escape sequence arriving one byte at
//! a time down a serial line, a UTF-8 character split across two reads, the CR
//! LF that one press of Enter is on Motor OS. What is left here is which of the
//! keys it decodes red has a use for.

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

#[derive(Debug, PartialEq, Clone)]
pub enum Key {
    Char(char),
    Esc,
    Backspace,
    Delete,
    Enter,
    Tab,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Ctrl(char),
    /// The terminal is a different shape now: rows, then columns.
    ///
    /// Nothing on Motor OS announces a resize — there is no `SIGWINCH` and no
    /// size call — so this is the answer to a question crossterm asks on a clock
    /// while red waits for a key, and it arrives among the keys.
    Resize(usize, usize),
    /// There will be no more keys: the terminal on the other end is gone.
    None,
}

/// Wait for the next key.
///
/// A read error is the session ending — the far end of stdin closed — and is
/// reported as [`Key::None`] rather than retried: red has nobody left to show
/// anything to.
pub fn read_key() -> Key {
    loop {
        match event::read() {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                if let Some(key) = key_of(key) {
                    return key;
                }
            }
            Ok(Event::Resize(cols, rows)) if rows > 0 && cols > 0 => {
                return Key::Resize(usize::from(rows), usize::from(cols));
            }
            // A key release, a mouse report, a paste: not this editor's.
            Ok(_) => {}
            Err(_) => return Key::None,
        }
    }
}

/// What the editor makes of one key event, or `None` for one it has no name for
/// (a function key, say) — which the caller waits past rather than acting on.
fn key_of(event: KeyEvent) -> Option<Key> {
    let ctrl = event.modifiers.contains(KeyModifiers::CONTROL);
    Some(match event.code {
        // A console that sends a bare LF for Enter reaches raw mode as `^J`,
        // and `^H` is the other Backspace: terminals disagree about which byte
        // the key sends, and Motor OS has no termios `erase` setting to consult.
        KeyCode::Char('j') if ctrl => Key::Enter,
        KeyCode::Char('h') if ctrl => Key::Backspace,
        KeyCode::Char(c) if ctrl => Key::Ctrl(c.to_ascii_lowercase()),
        // Alt is not a modifier red binds anything to; the character it was
        // held with is still the character typed.
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Esc => Key::Esc,
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Delete => Key::Delete,
        KeyCode::Enter => Key::Enter,
        KeyCode::Tab => Key::Tab,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::Home => Key::Home,
        KeyCode::End => Key::End,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode, mods: KeyModifiers) -> Option<Key> {
        key_of(KeyEvent::new(code, mods))
    }

    fn plain(code: KeyCode) -> Option<Key> {
        key(code, KeyModifiers::NONE)
    }

    #[test]
    fn the_keys_the_editor_binds_are_the_keys_it_gets() {
        assert_eq!(plain(KeyCode::Char('j')), Some(Key::Char('j')));
        assert_eq!(
            key(KeyCode::Char('Z'), KeyModifiers::SHIFT),
            Some(Key::Char('Z'))
        );
        assert_eq!(plain(KeyCode::Esc), Some(Key::Esc));
        assert_eq!(plain(KeyCode::PageDown), Some(Key::PageDown));
        assert_eq!(
            key(KeyCode::Char('f'), KeyModifiers::CONTROL),
            Some(Key::Ctrl('f'))
        );
        // `C-F` is `C-f`: a control byte carries no case.
        assert_eq!(
            key(
                KeyCode::Char('F'),
                KeyModifiers::CONTROL | KeyModifiers::SHIFT
            ),
            Some(Key::Ctrl('f'))
        );
    }

    #[test]
    fn the_two_keys_terminals_disagree_about_have_both_spellings() {
        assert_eq!(
            key(KeyCode::Char('j'), KeyModifiers::CONTROL),
            Some(Key::Enter)
        );
        assert_eq!(
            key(KeyCode::Char('h'), KeyModifiers::CONTROL),
            Some(Key::Backspace)
        );
        assert_eq!(plain(KeyCode::Enter), Some(Key::Enter));
        assert_eq!(plain(KeyCode::Backspace), Some(Key::Backspace));
    }

    #[test]
    fn a_key_red_has_no_name_for_is_not_guessed_at() {
        // Waited past rather than turned into an `Esc`, which in normal mode
        // would cancel whatever the user was in the middle of.
        assert_eq!(plain(KeyCode::F(5)), None);
        assert_eq!(plain(KeyCode::Insert), None);
        assert_eq!(plain(KeyCode::BackTab), None);
    }
}
