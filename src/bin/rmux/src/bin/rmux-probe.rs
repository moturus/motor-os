//! A hand-written rmux client for adversarial tests (src/tests/full-test.sh).
//!
//! rmux's own client only looks for the server its capabilities would start.
//! This one names any server, so a test can check that a server refuses a
//! client that lacks its capabilities, whatever that client sends. Not part
//! of the image: the tests copy it to the VM.
//!
//! ```text
//! rmux-probe whoami                          caps=0x... profile=0x...
//! rmux-probe ls|kill|new|attach NAME PROFILE [SESSION]
//! rmux-probe raw NAME                        a Kill as the first request
//! rmux-probe half NAME                       open an output, print its token, wait
//! rmux-probe pair NAME TOKEN                 pair an input with that token
//! ```
//!
//! Prints `refused: <why>` and exits 3 when the server turns it away.

#[cfg(unix)]
fn main() {
    eprintln!("rmux-probe: Motor OS only");
    std::process::exit(2);
}

#[cfg(not(unix))]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(motor::run(&args));
}

#[cfg(not(unix))]
mod motor {
    use std::io::Read;
    use std::io::Write;
    use std::time::Duration;

    use moto_ipc::sync::ChannelSize;
    use moto_ipc::sync::ClientConnection;
    use moto_ipc::sync::RequestHeader;
    use moto_ipc::sync::ResponseHeader;
    use rmux::proto;
    use rmux::proto::Frames;
    use rmux::proto::ToClient;
    use rmux::proto::ToServer;
    use rmux::sys::ipc;

    const REFUSED: i32 = 3;

    pub fn run(args: &[String]) -> i32 {
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        match words.as_slice() {
            ["whoami"] => {
                let caps = moto_sys::ProcessStaticPage::get().capabilities;
                println!("caps={caps:#x} profile={:#x}", ipc::profile());
                0
            }
            ["ls", name, profile] => ask(name, profile, ToServer::List),
            ["kill", name, profile, session] => {
                ask(name, profile, ToServer::Kill((*session).to_owned()))
            }
            ["new", name, profile, session] => ask(
                name,
                profile,
                ToServer::NewSession {
                    name: Some((*session).to_owned()),
                    rows: 24,
                    cols: 80,
                },
            ),
            ["attach", name, profile, session] => ask(
                name,
                profile,
                ToServer::Attach {
                    session: Some((*session).to_owned()),
                    detach_others: true,
                    rows: 24,
                    cols: 80,
                },
            ),
            ["raw", name] => raw(name),
            ["half", name] => half(name),
            ["pair", name, token] => pair(name, token),
            _ => {
                eprintln!("rmux-probe: bad arguments: {words:?}");
                2
            }
        }
    }

    fn parse_mask(text: &str) -> u64 {
        u64::from_str_radix(text.trim_start_matches("0x"), 16).expect("a hex mask")
    }

    /// Say one thing to the server over the real protocol, and print the
    /// first thing it says back.
    fn ask(name: &str, profile: &str, request: ToServer) -> i32 {
        let (mut writer, mut reader) = match ipc::connect(name, parse_mask(profile)) {
            Ok(Some(link)) => link,
            Ok(None) => {
                println!("no server");
                return 1;
            }
            Err(err) => {
                println!("refused: {err}");
                return REFUSED;
            }
        };
        if let Err(err) = writer.write_all(&proto::encode(&request)) {
            println!("refused: {err}");
            return REFUSED;
        }
        let _ = reader.set_read_timeout(Some(Duration::from_secs(5)));
        let mut frames = Frames::new();
        let mut buf = [0_u8; 4096];
        loop {
            let read = match reader.read(&mut buf) {
                Ok(0) | Err(_) => {
                    println!("refused: the server said nothing");
                    return REFUSED;
                }
                Ok(read) => read,
            };
            frames.feed(&buf[..read]);
            if let Some(message) = frames.take::<ToClient>() {
                match message {
                    Some(ToClient::Sessions(lines)) => println!("sessions: {}", lines.join("; ")),
                    Some(ToClient::Write(_)) => println!("attached"),
                    Some(other) => println!("answered: {other:?}"),
                    None => println!("answered: an unknown message"),
                }
                return 0;
            }
        }
    }

    /// One request on a fresh connection, with no handshake and no check of
    /// the server's mask: the server has to refuse it all the same.
    fn request(name: &str, cmd: u16, token: u64, data: &[u8]) -> Result<ClientConnection, String> {
        let mut conn = ClientConnection::new(ChannelSize::Small).map_err(|e| format!("{e}"))?;
        conn.connect(name).map_err(|e| format!("connect: {e}"))?;
        conn.req::<RequestHeader>().cmd = cmd;
        let page = conn.data_mut();
        page[ipc::TOKEN_AT..ipc::TOKEN_AT + 8].copy_from_slice(&token.to_ne_bytes());
        page[ipc::LEN_AT..ipc::LEN_AT + 4].copy_from_slice(&(data.len() as u32).to_ne_bytes());
        page[ipc::DATA_AT..ipc::DATA_AT + data.len()].copy_from_slice(data);
        let deadline = moto_rt::time::Instant::now() + Duration::from_secs(5);
        conn.do_rpc(Some(deadline))
            .map_err(|e| format!("rpc: {e}"))?;
        match conn.resp::<ResponseHeader>().result {
            moto_rt::E_OK => Ok(conn),
            err => Err(format!("result {err}")),
        }
    }

    fn raw(name: &str) -> i32 {
        let kill = proto::encode(&ToServer::Kill("priv".to_owned()));
        match request(name, ipc::CMD_INPUT, 1, &kill) {
            Ok(_) => {
                println!("accepted");
                0
            }
            Err(why) => {
                println!("refused: {why}");
                REFUSED
            }
        }
    }

    /// The first half of a client: an output connection whose token another
    /// process could learn, held open and never paired.
    fn half(name: &str) -> i32 {
        match request(name, ipc::CMD_OPEN_OUTPUT, 0, &[]) {
            Ok(conn) => {
                println!(
                    "token={}",
                    u64::from_ne_bytes(
                        conn.data()[ipc::TOKEN_AT..ipc::TOKEN_AT + 8]
                            .try_into()
                            .unwrap(),
                    )
                );
                std::thread::sleep(Duration::from_secs(20));
                0
            }
            Err(why) => {
                println!("refused: {why}");
                REFUSED
            }
        }
    }

    /// Pair an input connection with `token`, which another process opened.
    fn pair(name: &str, token: &str) -> i32 {
        let token: u64 = token.parse().expect("a token");
        match request(name, ipc::CMD_OPEN_INPUT, token, &[]) {
            Ok(_) => {
                println!("paired with token {token}");
                0
            }
            Err(why) => {
                println!("refused: {why}");
                REFUSED
            }
        }
    }
}
