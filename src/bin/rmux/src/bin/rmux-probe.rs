//! A hand-written rmux client for adversarial tests (src/tests/full-test.sh).
//!
//! rmux's own client only looks for the server its capabilities would start.
//! This one names any server, so a test can check that a server refuses a
//! client that lacks its capabilities, whatever that client sends. Not part
//! of the image: the tests copy it to the VM.
//!
//! ```text
//! rmux-probe errors                          explicit refusals and closed-peer EOF
//! rmux-probe closing                         final poll overlaps input; exit 5
//! rmux-probe whoami                          caps=0x... profile=0x...
//! rmux-probe ls|kill|new|attach NAME PROFILE [SESSION]
//! rmux-probe raw NAME                        a Kill as the first request
//! rmux-probe half NAME                       open an output, print its token, wait
//! rmux-probe silent NAME                     connect without an RPC, wait for rejection
//! rmux-probe saturate NAME PROFILE           fill the pool until stdin supplies a line
//! rmux-probe parallel NAME PROFILE           list sessions from three concurrent clients
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
            ["errors"] => errors(),
            ["closing"] => closing(),
            ["silent", name] => silent(name),
            ["saturate", name, profile] => saturate(name, profile),
            ["parallel", name, profile] => {
                std::thread::scope(|scope| {
                    for _ in 0..3 {
                        scope.spawn(|| assert_eq!(ask(name, profile, ToServer::List), 0));
                    }
                });
                0
            }
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

    fn errors() -> i32 {
        use moto_ipc::sync::LocalServer;
        use moto_sys::SysHandle;
        use std::sync::mpsc::channel;

        let caps = moto_sys::ProcessStaticPage::get().capabilities;
        let name = format!("rmux-probe-errors/{}", std::process::id());
        for (stop_on, close) in [
            (ipc::CMD_OPEN_OUTPUT, false),
            (ipc::CMD_POLL, false),
            (ipc::CMD_POLL, true),
        ] {
            let (started, ready) = channel();
            let (finish, finished) = channel();
            let service = name.clone();
            let peer = std::thread::spawn(move || {
                let mut server = LocalServer::new(&service, ChannelSize::Small, 4, 2).unwrap();
                started.send(()).unwrap();
                loop {
                    for handle in server.wait(SysHandle::NONE, &[]).unwrap() {
                        let conn = server.get_connection(handle).unwrap();
                        if !conn.have_req() {
                            continue;
                        }
                        let cmd = conn.req::<RequestHeader>().cmd;
                        assert!(matches!(
                            cmd,
                            ipc::CMD_OPEN_OUTPUT | ipc::CMD_OPEN_INPUT | ipc::CMD_POLL
                        ));
                        if cmd == stop_on && close {
                            return; // Drop both endpoints without a response.
                        }
                        conn.resp::<ResponseHeader>().result = if cmd == stop_on {
                            moto_rt::E_NOT_ALLOWED
                        } else {
                            moto_rt::E_OK
                        };
                        let page = conn.data_mut();
                        page[ipc::TOKEN_AT..ipc::TOKEN_AT + 8]
                            .copy_from_slice(&1_u64.to_ne_bytes());
                        page[ipc::LEN_AT..ipc::LEN_AT + 4].copy_from_slice(&0_u32.to_ne_bytes());
                        conn.finish_rpc().unwrap();
                        if cmd == stop_on {
                            // Keep the peer alive until the client has inspected
                            // the explicit error, so closure cannot mask it.
                            finished.recv().unwrap();
                            return;
                        }
                    }
                }
            });
            ready.recv().unwrap();
            if stop_on == ipc::CMD_OPEN_OUTPUT {
                let error = ipc::connect(&name, caps)
                    .err()
                    .expect("opening refusal was lost");
                assert_eq!(error.raw_os_error(), Some(moto_rt::E_NOT_ALLOWED as i32));
            } else {
                let (_writer, mut reader) = ipc::connect(&name, caps).unwrap().unwrap();
                reader
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut buf = [0; 32];
                if close {
                    assert_eq!(reader.read(&mut buf).unwrap(), 0);
                    assert_eq!(reader.read(&mut buf).unwrap(), 0);
                } else {
                    let error = reader.read(&mut buf).unwrap_err();
                    assert_eq!(error.raw_os_error(), Some(moto_rt::E_NOT_ALLOWED as i32));
                }
            }
            if !close {
                finish.send(()).unwrap();
            }
            peer.join().unwrap();
        }
        println!("opening and poll refusals preserved; closed peer remains EOF");
        0
    }

    fn closing() -> i32 {
        use rmux::server::Event;

        // Own both application ends, but use the real IPC thread and forwarder.
        let (events, queue) = std::sync::mpsc::channel();
        ipc::listen(events).unwrap();
        let caps = moto_sys::ProcessStaticPage::get().capabilities;
        let (mut writer, mut reader) = ipc::connect(&ipc::service_name(caps), caps)
            .unwrap()
            .unwrap();
        let Event::ClientArrived(client) = queue.recv().unwrap() else {
            panic!("missing client arrival");
        };
        client
            .out
            .send(ToClient::Write(b"farewell".to_vec()))
            .unwrap();
        client.out.send(ToClient::Exit(5)).unwrap();
        drop(client.out);

        let mut frames = Frames::new();
        let mut output = Vec::new();
        let mut buf = [0; 4096];
        reader
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let status = 'read: loop {
            let len = reader.read(&mut buf).unwrap();
            assert_ne!(len, 0, "closed before Exit");
            frames.feed(&buf[..len]);
            while let Some(Some(message)) = frames.take::<ToClient>() {
                match message {
                    ToClient::Write(bytes) => output.extend(bytes),
                    ToClient::Exit(code) => break 'read code,
                    _ => panic!("unexpected final message"),
                }
            }
        };
        assert_eq!(output, b"farewell");
        assert_eq!(status, 5);

        // Model read_server polling before the relay consumes Exit. Timeout
        // leaves that poll in flight; it must not close the input connection.
        assert_eq!(
            reader.read(&mut buf).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        writer
            .write_all(&proto::encode(&ToServer::EndInput))
            .unwrap();
        assert!(
            matches!(queue.recv().unwrap(), Event::FromClient(id, ToServer::EndInput) if id == client.id)
        );
        drop(writer);
        assert!(matches!(queue.recv().unwrap(), Event::ClientGone(id) if id == client.id));
        client.farewell.join().unwrap();
        drop(reader);
        println!("final input acknowledged; exit={status}");
        status
    }

    fn saturate(name: &str, profile: &str) -> i32 {
        // rmux's 64-endpoint limit permits 32 paired clients. Use its normal
        // open path so transient pool exhaustion exercises bounded refill waits.
        let clients: Vec<_> = (0..32)
            .map(|_| ipc::connect(name, parse_mask(profile)).unwrap().unwrap())
            .collect();
        let mut extra = ClientConnection::new(ChannelSize::Small).unwrap();
        assert_eq!(extra.connect(name), Err(moto_rt::E_NOT_READY));
        assert_eq!(ipc::service_name(ipc::profile()), name);
        let error = ipc::connect_or_start(
            || panic!("a busy server must not invoke the spawn callback"),
            Duration::from_secs(5),
        )
        .err()
        .expect("a full server accepted another client");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("server is busy"));
        println!("pool full");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        drop(clients);
        0
    }

    fn silent(name: &str) -> i32 {
        use moto_sys::{SysCpu, SysHandle, SysObj};

        let mut conn = ClientConnection::new(ChannelSize::Small).unwrap();
        conn.connect(name).unwrap();
        let mut handles = [conn.handle()];
        let deadline = moto_rt::time::Instant::now() + Duration::from_secs(5);
        // Closing during wait is a wake; closing before wait is a bad handle.
        let result = SysCpu::wait(
            &mut handles,
            SysHandle::NONE,
            SysHandle::NONE,
            Some(deadline),
        );
        assert!(result.is_ok() || result == Err(moto_rt::E_BAD_HANDLE));
        assert_eq!(
            SysObj::handle_status(conn.handle()),
            Err(moto_rt::E_BAD_HANDLE),
            "silent unauthorized connection was not rejected"
        );
        println!("silent rejected");
        std::io::stdout().flush().unwrap();
        // Keep the client endpoint and process alive during the legitimate list.
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        drop(conn);
        0
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
