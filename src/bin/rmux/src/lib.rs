//! rmux — a terminal multiplexer for Motor OS.
//!
//! The design is in `details.md`, and doc comments cite it by section ("details.md
//! §3.1"). Built so far: M0's scaffolding (the library seam, the `tests/` hook,
//! the `sys::` platform layer), M1's pane, M2's emulator (`ansi` + `grid`),
//! M3's compositor (`screen`), M4's split into a `server` that owns everything
//! and a `client` that paints what it is sent, M5's `config` and `bindings`,
//! M6's `window`s, `session`s and `status` line, M7's `layout` tree, M8's
//! scrollback and `copy` mode, and M9's conformance corpus — which is where
//! `tests/conformance.rs` came from, and why what rmux does differently from
//! tmux is a tested list rather than prose.
//!
//! The crate root is a library with a thin `main.rs` over it, following rush:
//! that is what lets `tests/` drive the binary as an integration test while the
//! pure parts (the terminal emulator, the layout tree) stay unit-testable
//! without a terminal at all (details.md §9.3).

pub mod ansi;
pub mod bindings;
pub mod client;
pub mod config;
pub mod copy;
pub mod grid;
pub mod keys;
pub mod layout;
pub mod pane;
pub mod proto;
pub mod screen;
pub mod server;
pub mod session;
pub mod status;
pub mod sys;
pub mod window;

pub use pane::Pane;
pub use pane::PaneId;
pub use screen::Frame;
pub use screen::Screen;
pub use server::Event;

/// The argument that makes this process the server rather than a client.
///
/// Not part of the command surface (§4.1) — a user never types it. The client
/// spawns itself with it, which is how one binary is both halves.
pub const SERVER_ARG: &str = "--server";

/// rmux's whole command surface (details.md §4.1, §7.3), and nothing else is
/// planned:
///
/// ```text
/// rmux                       attach to the most recent session, or start one
/// rmux new [-s name]         start a session and attach
/// rmux attach [-d] [-t name] attach to a session, optionally detaching its clients
/// rmux ls                    list sessions
/// rmux kill-session -t name  kill it and everything in it
/// ```
const USAGE: &str = "\
usage: rmux
       rmux new [-s name]
       rmux attach [-d] [-t name]
       rmux ls
       rmux kill-session -t name";

/// Run rmux. Returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match words.as_slice() {
        [] => client::attach(None, false),
        [SERVER_ARG] => server::serve().map(|()| 0),

        ["new"] => client::create(None),
        ["new", "-s", name] => client::create(Some((*name).to_owned())),

        ["attach"] => client::attach(None, false),
        ["attach", "-d"] => client::attach(None, true),
        ["attach", "-t", name] => client::attach(Some((*name).to_owned()), false),
        ["attach", "-d", "-t", name] | ["attach", "-t", name, "-d"] => {
            client::attach(Some((*name).to_owned()), true)
        }

        ["ls"] => client::ask(proto::ToServer::List),
        ["kill-session", "-t", name] => client::ask(proto::ToServer::Kill((*name).to_owned())),

        _ => {
            eprintln!("{USAGE}");
            return 2;
        }
    };
    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("rmux: {err}");
            1
        }
    }
}
