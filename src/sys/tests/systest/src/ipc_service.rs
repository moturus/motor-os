use moto_ipc::sync::{ChannelSize, ClientConnection, LocalServer, RequestHeader, ResponseHeader};
use moto_sys::{SysHandle, SysObj};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdout, Command, Stdio};

const CHILD: &str = "ipc-service-child";
const CHILD_CAPS: u64 = moto_sys::caps::CAP_SPAWN | moto_sys::caps::CAP_INTERACTIVE;

fn listen(url: &str) -> Result<LocalServer, moto_rt::ErrorCode> {
    LocalServer::new(url, ChannelSize::Small, 4, 1)
}

pub fn run_command(args: &[String]) -> bool {
    match args.get(1).map(String::as_str) {
        Some("test-ipc-service-ownership") => run_tests(),
        Some("ipc-service-busy") if args.len() == 3 => {
            assert_eq!(listen(&args[2]).err(), Some(moto_rt::E_INVALID_ARGUMENT));
        }
        Some(CHILD) if args.len() == 3 => run_child(&args[2]),
        _ => return false,
    }
    true
}

fn run_child(url: &str) {
    let mut server = Some(listen(url).unwrap());
    let mut last = SysHandle::NONE;
    let mut duplicate = SysHandle::NONE;
    println!("ready");
    std::io::stdout().flush().unwrap();
    for command in std::io::stdin().lock().lines() {
        match command.unwrap().as_str() {
            "rpc" => {
                let server = server.as_mut().unwrap();
                let ready = server.wait(SysHandle::NONE, &[]).unwrap();
                assert_eq!(ready.len(), 1);
                last = ready[0];
                let conn = server.get_connection(last).unwrap();
                assert!(conn.have_req());
                conn.resp::<ResponseHeader>().result = moto_rt::E_OK;
                conn.finish_rpc().unwrap();
            }
            "duplicate" => duplicate = SysObj::dup(last).unwrap(),
            "close" => drop(server.take().unwrap()),
            "release" => {
                SysObj::put(duplicate).unwrap();
                duplicate = SysHandle::NONE;
            }
            "busy" => assert_eq!(listen(url).err(), Some(moto_rt::E_INVALID_ARGUMENT)),
            "free" => drop(listen(url).unwrap()),
            _ => panic!("unknown IPC service test command"),
        }
        println!("ok");
        std::io::stdout().flush().unwrap();
    }
    assert_eq!(duplicate, SysHandle::NONE);
}

struct Peer {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

impl Peer {
    fn start(url: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([CHILD, url])
            .env(
                moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
                format!("0x{CHILD_CAPS:x}"),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut peer = Self { child, stdout };
        peer.expect("ready\n");
        peer
    }

    fn expect(&mut self, expected: &str) {
        let mut line = String::new();
        assert_ne!(self.stdout.read_line(&mut line).unwrap(), 0);
        assert_eq!(line, expected);
    }

    fn send(&mut self, command: &str) {
        writeln!(self.child.stdin.as_mut().unwrap(), "{command}").unwrap();
    }

    fn command(&mut self, command: &str) {
        self.send(command);
        self.expect("ok\n");
    }

    fn rpc(&mut self, client: &mut ClientConnection) {
        self.send("rpc");
        client.req::<RequestHeader>().cmd = 1;
        client.do_rpc(None).unwrap();
        assert_eq!(client.resp::<ResponseHeader>().result, moto_rt::E_OK);
        self.expect("ok\n");
    }

    fn stop(mut self) {
        drop(self.child.stdin.take());
        assert_eq!(self.child.wait().unwrap().code(), Some(0));
    }
}

pub fn run_tests() {
    let url = format!("systest-ipc-owner-{}", std::process::id());
    let mut peer = Peer::start(&url);
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));
    let mut client = ClientConnection::new(ChannelSize::Small).unwrap();
    assert_eq!(client.handle(), SysHandle::NONE);
    client.connect(&url).unwrap();
    assert_eq!(
        SysObj::get_pid(client.handle()).unwrap(),
        u64::from(peer.child.id())
    );
    assert_eq!(
        SysObj::get_capabilities(client.handle()).unwrap(),
        CHILD_CAPS
    );

    // Connecting and a subsequent failed lookup must both retain ownership.
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));
    let mut extra = ClientConnection::new(ChannelSize::Small).unwrap();
    assert_eq!(extra.connect(&url), Err(moto_rt::E_NOT_FOUND));
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));
    peer.rpc(&mut client);
    peer.rpc(&mut client); // Replenishes the exhausted listener pool.
    extra.connect(&url).unwrap();
    assert_eq!(
        SysObj::get_pid(extra.handle()).unwrap(),
        u64::from(peer.child.id())
    );
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));

    // Closing a client does not release the server's endpoint or name.
    extra.disconnect();
    assert_eq!(extra.handle(), SysHandle::NONE);
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));
    peer.command("duplicate");
    peer.command("close");
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));
    peer.command("release");
    let replacement = listen(&url).unwrap();
    client.disconnect(); // Old client cleanup must not affect the replacement.
    peer.command("busy");
    drop(replacement);
    peer.command("free"); // Closing an unconnected listener also releases its name.
    peer.stop();
    assert_eq!(extra.connect(&url), Err(moto_rt::E_NOT_FOUND));

    // Preserve takeover after death even with an exhausted pool and retained
    // process/client handles. The original pending-listener restart test stays.
    let mut peer = Peer::start(&url);
    client.connect(&url).unwrap();
    peer.child.kill().unwrap();
    let replacement = listen(&url).unwrap();
    assert_eq!(peer.child.wait().unwrap().code(), Some(-1));
    client.disconnect();
    assert!(
        Command::new(std::env::current_exe().unwrap())
            .args(["ipc-service-busy", &url])
            .status()
            .unwrap()
            .success()
    );
    drop(replacement);
    drop(listen(&url).unwrap());
    println!("test_ipc_service_ownership PASS");
}
