//! What the client and the server say to each other.
//!
//! Small, framed, and deliberately dumb (details.md §4.2). The server owns
//! everything and renders; the client relays keystrokes one way and paints
//! bytes the other, so the protocol is barely more than those two directions
//! plus enough to pick a session.
//!
//! Framed, because the transport is a byte stream and a stream has no message
//! boundaries. On the serial console sys-tty hands rmux one byte at a time
//! (§8.3) and TCP is free to split a write anywhere, so [`Frames`] buffers and
//! never assumes a message arrives whole.
//!
//! Encoded by hand: rmux links nothing (§4.6), so there is no `serde` behind
//! this. The format is `tag`, then a big-endian `u32` length, then that many
//! bytes of payload — enough that a reader can skip a message it does not
//! understand rather than losing the stream, which is what a length prefix is
//! for.
//!
//! # The trap this protocol is shaped around
//!
//! `systest/src/tcp.rs:250` records it: *"If the server is dropped now, the
//! write above may not be delivered."* Closing a `TcpStream` can discard
//! unflushed writes on Motor. So **nothing here relies on a close to deliver
//! anything**. The side that owes a final message sends it and then waits for
//! the other end to go away first; see [`ToClient::Exit`]. It is the same
//! drain-before-close discipline russhd needs on its pipes
//! (`local_session.rs:170-181`), in a third place.

/// Whether an error is a read or write that ran out of time.
///
/// Two kinds, because a socket timeout is `WouldBlock` on some platforms and
/// `TimedOut` on others, and rmux runs on two. What a caller must *not* do with
/// this is treat it as a clock: a timeout can be reported early, so whether the
/// time is really up is a question for [`std::time::Instant`] (see
/// `client::relay`).
pub fn timed_out(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

/// A message that can cross the wire.
pub trait Message: Sized {
    fn tag(&self) -> u8;
    fn encode_payload(&self, out: &mut Vec<u8>);
    fn decode(tag: u8, payload: &[u8]) -> Option<Self>;
}

/// The most a single message may carry.
///
/// A frame header is four attacker-controlled bytes; without a bound, one bad
/// length is an allocation the size of whatever those bytes said.
const MAX_PAYLOAD: usize = 1 << 20;

/// Client to server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToServer {
    /// Take me to a session — a named one, or the most recently used (§7.3).
    Attach {
        session: Option<String>,
        rows: u16,
        cols: u16,
    },
    /// Start a session and attach to it — `rmux new [-s name]` (§7.3). Distinct
    /// from [`ToServer::Attach`], which joins one that already exists and says
    /// so when it does not.
    NewSession {
        name: Option<String>,
        rows: u16,
        cols: u16,
    },
    /// A key the user pressed.
    ///
    /// The key rather than the bytes: the console's decoder is crossterm's and
    /// runs in the client, which is the only side that has a terminal. What a
    /// pane is given for it is [`crate::keys::Key::encode`], on the server,
    /// where the pane is.
    Key(crate::keys::Key),
    /// This client's console is a different shape now.
    Resize { rows: u16, cols: u16 },
    /// This client's console has no more input, so a shell reading a script
    /// should see the end of it. The session is not over.
    EndInput,
    /// I am leaving; the session and everything in it lives on.
    Detach,
    /// Name every session, for `rmux ls`.
    List,
    /// Kill a session and everything in it.
    Kill(String),
}

/// Server to client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToClient {
    /// Bytes destined for the console, verbatim.
    Write(Vec<u8>),
    /// The session is over and this is its status. **The server does not close
    /// after this** — it waits for the client to, because a close here can
    /// discard the very message it is meant to deliver (see the module docs).
    Exit(i32),
    /// Leave, but the session lives on — which is what makes it a session
    /// (§7.3), and why this is not an [`ToClient::Exit`].
    Detached,
    /// One line per session: name, windows, attached.
    Sessions(Vec<String>),
    /// The request worked and there is nothing to print.
    ///
    /// Every request a *question* client sends ([`ToServer::List`],
    /// [`ToServer::Kill`]) is answered, including the ones whose answer is
    /// "done" — the client blocks on a reply, so a request the server handles
    /// silently is a request the client waits out forever. `kill-session` hung
    /// exactly that way before this existed.
    Done,
    /// What went wrong with the last request.
    Failed(String),
}

const ATTACH: u8 = 1;
const KEY: u8 = 2;
const RESIZE: u8 = 3;
const END_INPUT: u8 = 4;
const DETACH: u8 = 5;
const LIST: u8 = 6;
const KILL: u8 = 7;
const NEW_SESSION: u8 = 8;

const WRITE: u8 = 65;
const EXIT: u8 = 66;
const DETACHED: u8 = 67;
const SESSIONS: u8 = 68;
const FAILED: u8 = 69;
const DONE: u8 = 70;

impl Message for ToServer {
    fn tag(&self) -> u8 {
        match self {
            ToServer::Attach { .. } => ATTACH,
            ToServer::NewSession { .. } => NEW_SESSION,
            ToServer::Key(_) => KEY,
            ToServer::Resize { .. } => RESIZE,
            ToServer::EndInput => END_INPUT,
            ToServer::Detach => DETACH,
            ToServer::List => LIST,
            ToServer::Kill(_) => KILL,
        }
    }

    fn encode_payload(&self, out: &mut Vec<u8>) {
        match self {
            ToServer::Attach {
                session,
                rows,
                cols,
            }
            | ToServer::NewSession {
                name: session,
                rows,
                cols,
            } => {
                put_u16(*rows, out);
                put_u16(*cols, out);
                put_str(session.as_deref().unwrap_or(""), out);
            }
            ToServer::Key(key) => put_key(*key, out),
            ToServer::Resize { rows, cols } => {
                put_u16(*rows, out);
                put_u16(*cols, out);
            }
            ToServer::EndInput | ToServer::Detach | ToServer::List => {}
            ToServer::Kill(name) => put_str(name, out),
        }
    }

    fn decode(tag: u8, payload: &[u8]) -> Option<ToServer> {
        Some(match tag {
            ATTACH => {
                let rows = take_u16(payload, 0)?;
                let cols = take_u16(payload, 2)?;
                let session = take_str(payload.get(4..)?)?;
                ToServer::Attach {
                    // An empty name is "whichever session is most recent",
                    // which is what a bare `rmux` means (§7.3).
                    session: (!session.is_empty()).then_some(session),
                    rows,
                    cols,
                }
            }
            NEW_SESSION => {
                let rows = take_u16(payload, 0)?;
                let cols = take_u16(payload, 2)?;
                let name = take_str(payload.get(4..)?)?;
                ToServer::NewSession {
                    name: (!name.is_empty()).then_some(name),
                    rows,
                    cols,
                }
            }
            KEY => ToServer::Key(take_key(payload)?),
            RESIZE => ToServer::Resize {
                rows: take_u16(payload, 0)?,
                cols: take_u16(payload, 2)?,
            },
            END_INPUT => ToServer::EndInput,
            DETACH => ToServer::Detach,
            LIST => ToServer::List,
            KILL => ToServer::Kill(take_str(payload)?),
            _ => return None,
        })
    }
}

impl Message for ToClient {
    fn tag(&self) -> u8 {
        match self {
            ToClient::Write(_) => WRITE,
            ToClient::Exit(_) => EXIT,
            ToClient::Detached => DETACHED,
            ToClient::Sessions(_) => SESSIONS,
            ToClient::Done => DONE,
            ToClient::Failed(_) => FAILED,
        }
    }

    fn encode_payload(&self, out: &mut Vec<u8>) {
        match self {
            ToClient::Write(bytes) => out.extend_from_slice(bytes),
            ToClient::Exit(code) => out.extend_from_slice(&code.to_be_bytes()),
            ToClient::Detached | ToClient::Done => {}
            ToClient::Sessions(lines) => {
                for line in lines {
                    put_str(line, out);
                }
            }
            ToClient::Failed(why) => put_str(why, out),
        }
    }

    fn decode(tag: u8, payload: &[u8]) -> Option<ToClient> {
        Some(match tag {
            WRITE => ToClient::Write(payload.to_vec()),
            EXIT => ToClient::Exit(i32::from_be_bytes(payload.get(..4)?.try_into().ok()?)),
            DETACHED => ToClient::Detached,
            SESSIONS => {
                let mut lines = Vec::new();
                let mut rest = payload;
                while !rest.is_empty() {
                    let len = take_u16(rest, 0)? as usize;
                    lines.push(take_str(rest)?);
                    rest = rest.get(2 + len..)?;
                }
                ToClient::Sessions(lines)
            }
            DONE => ToClient::Done,
            FAILED => ToClient::Failed(take_str(payload)?),
            _ => return None,
        })
    }
}

/// Frame `message` for the wire.
pub fn encode<M: Message>(message: &M) -> Vec<u8> {
    let mut payload = Vec::new();
    message.encode_payload(&mut payload);
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.push(message.tag());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// A byte stream, reassembled into messages.
#[derive(Default)]
pub struct Frames {
    buf: Vec<u8>,
    /// A length this side will not honour was read; the stream is no longer
    /// trustworthy and every later call says so rather than guessing.
    broken: bool,
}

impl Frames {
    pub fn new() -> Frames {
        Frames::default()
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Take the next whole message, if one has arrived.
    ///
    /// `Some(None)` is a frame that decoded to nothing — a message this build
    /// does not know. The frame is still consumed, which is the point of the
    /// length prefix: an unknown message costs its own bytes and no more.
    pub fn take<M: Message>(&mut self) -> Option<Option<M>> {
        if self.broken || self.buf.len() < 5 {
            return None;
        }
        let tag = self.buf[0];
        let len = u32::from_be_bytes(self.buf[1..5].try_into().unwrap()) as usize;
        if len > MAX_PAYLOAD {
            self.broken = true;
            return None;
        }
        if self.buf.len() < 5 + len {
            return None;
        }
        let message = M::decode(tag, &self.buf[5..5 + len]);
        self.buf.drain(..5 + len);
        Some(message)
    }

    /// Whether the stream said something this side will not act on.
    pub fn is_broken(&self) -> bool {
        self.broken
    }
}

fn put_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// A key as three fields: the modifiers, which named key it is, and the number
/// that key needs — a character's codepoint, or a function key's number.
fn put_key(key: crate::keys::Key, out: &mut Vec<u8>) {
    use crate::keys::Code;

    let (code, number) = match key.code {
        Code::Char(c) => (0, c as u32),
        Code::Up => (1, 0),
        Code::Down => (2, 0),
        Code::Left => (3, 0),
        Code::Right => (4, 0),
        Code::Home => (5, 0),
        Code::End => (6, 0),
        Code::PageUp => (7, 0),
        Code::PageDown => (8, 0),
        Code::Insert => (9, 0),
        Code::Delete => (10, 0),
        Code::Enter => (11, 0),
        Code::Tab => (12, 0),
        Code::Backspace => (13, 0),
        Code::Escape => (14, 0),
        Code::F(n) => (15, u32::from(n)),
    };
    out.push(key.mods);
    out.push(code);
    out.extend_from_slice(&number.to_be_bytes());
}

fn take_key(payload: &[u8]) -> Option<crate::keys::Key> {
    use crate::keys::Code;

    let mods = *payload.first()?;
    let number = u32::from_be_bytes(payload.get(2..6)?.try_into().ok()?);
    let code = match payload.get(1)? {
        0 => Code::Char(char::from_u32(number)?),
        1 => Code::Up,
        2 => Code::Down,
        3 => Code::Left,
        4 => Code::Right,
        5 => Code::Home,
        6 => Code::End,
        7 => Code::PageUp,
        8 => Code::PageDown,
        9 => Code::Insert,
        10 => Code::Delete,
        11 => Code::Enter,
        12 => Code::Tab,
        13 => Code::Backspace,
        14 => Code::Escape,
        15 => Code::F(u8::try_from(number).ok()?),
        _ => return None,
    };
    Some(crate::keys::Key { code, mods })
}

fn put_str(value: &str, out: &mut Vec<u8>) {
    put_u16(value.len().min(u16::MAX as usize) as u16, out);
    out.extend_from_slice(&value.as_bytes()[..value.len().min(u16::MAX as usize)]);
}

fn take_u16(payload: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        payload.get(at..at + 2)?.try_into().ok()?,
    ))
}

fn take_str(payload: &[u8]) -> Option<String> {
    let len = take_u16(payload, 0)? as usize;
    String::from_utf8(payload.get(2..2 + len)?.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode, then decode through the framer one chunk at a time.
    fn round_trip<M: Message + PartialEq + std::fmt::Debug>(message: M, chunk: usize) -> M {
        let bytes = encode(&message);
        let mut frames = Frames::new();
        let mut out = None;
        for piece in bytes.chunks(chunk.max(1)) {
            frames.feed(piece);
            if let Some(decoded) = frames.take::<M>() {
                out = decoded;
            }
        }
        out.expect("the message never came back")
    }

    #[test]
    fn every_message_survives_the_wire() {
        let messages = [
            ToServer::Attach {
                session: Some("build".into()),
                rows: 30,
                cols: 90,
            },
            ToServer::Attach {
                session: None,
                rows: 24,
                cols: 80,
            },
            ToServer::NewSession {
                name: Some("notes".into()),
                rows: 30,
                cols: 90,
            },
            ToServer::NewSession {
                name: None,
                rows: 24,
                cols: 80,
            },
            ToServer::Key(crate::keys::Key::with(
                crate::keys::Code::Left,
                crate::keys::Key::SHIFT,
            )),
            ToServer::Key(crate::keys::Key::plain(crate::keys::Code::Char('日'))),
            ToServer::Key(crate::keys::Key::plain(crate::keys::Code::F(12))),
            ToServer::Resize { rows: 1, cols: 1 },
            ToServer::EndInput,
            ToServer::Detach,
            ToServer::List,
            ToServer::Kill("notes".into()),
        ];
        for message in messages {
            assert_eq!(round_trip(message.clone(), usize::MAX), message);
        }

        let replies = [
            ToClient::Write(b"\x1b[2J".to_vec()),
            ToClient::Exit(0),
            ToClient::Exit(-1),
            ToClient::Detached,
            ToClient::Sessions(vec!["0: 1 window".into(), "build: 2 windows".into()]),
            ToClient::Done,
            ToClient::Failed("no such session".into()),
        ];
        for reply in replies {
            assert_eq!(round_trip(reply.clone(), usize::MAX), reply);
        }
    }

    #[test]
    fn a_message_split_anywhere_is_still_one_message() {
        // TCP may split a write at any byte, and the console really does
        // deliver one at a time (§8.3).
        let message = ToServer::Attach {
            session: Some("build".into()),
            rows: 30,
            cols: 90,
        };
        for chunk in 1..=encode(&message).len() {
            assert_eq!(round_trip(message.clone(), chunk), message);
        }
    }

    #[test]
    fn messages_arriving_together_are_read_one_at_a_time() {
        let mut frames = Frames::new();
        let key = ToServer::Key(crate::keys::Key::ctrl('a'));
        frames.feed(&encode(&key));
        frames.feed(&encode(&ToServer::Detach));
        assert_eq!(frames.take::<ToServer>(), Some(Some(key)));
        assert_eq!(frames.take::<ToServer>(), Some(Some(ToServer::Detach)));
        assert_eq!(frames.take::<ToServer>(), None);
    }

    #[test]
    fn a_key_survives_one_byte_at_a_time() {
        // The console really does deliver one byte at a time (§8.3), and the
        // client's socket is no different.
        let key = ToServer::Key(crate::keys::Key::with(
            crate::keys::Code::Char('|'),
            crate::keys::Key::ALT,
        ));
        assert_eq!(round_trip(key.clone(), 1), key);
    }

    #[test]
    fn a_message_this_build_does_not_know_costs_its_own_bytes_and_no_more() {
        // What the length prefix is for: a reader skips what it cannot read
        // and stays in step with the stream.
        let mut frames = Frames::new();
        frames.feed(&[99, 0, 0, 0, 3, b'x', b'y', b'z']);
        frames.feed(&encode(&ToServer::Detach));
        assert_eq!(frames.take::<ToServer>(), Some(None));
        assert_eq!(frames.take::<ToServer>(), Some(Some(ToServer::Detach)));
    }

    #[test]
    fn a_length_this_side_will_not_honour_breaks_the_stream_rather_than_the_heap() {
        let mut frames = Frames::new();
        frames.feed(&[KEY, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(frames.take::<ToServer>(), None);
        assert!(frames.is_broken());
    }

    #[test]
    fn a_truncated_message_waits_rather_than_decoding_half_of_itself() {
        let bytes = encode(&ToServer::Attach {
            session: Some("build".into()),
            rows: 30,
            cols: 90,
        });
        let mut frames = Frames::new();
        frames.feed(&bytes[..bytes.len() - 1]);
        assert_eq!(frames.take::<ToServer>(), None);
        assert!(!frames.is_broken());
    }

    #[test]
    fn a_payload_that_lies_about_its_own_shape_decodes_to_nothing() {
        // A frame whose length is honest but whose contents are not: the
        // stream stays in step, and the message is simply not understood.
        let mut frames = Frames::new();
        frames.feed(&[ATTACH, 0, 0, 0, 2, 0, 30]);
        assert_eq!(frames.take::<ToServer>(), Some(None));
        assert!(!frames.is_broken());
    }
}
