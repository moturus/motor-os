//! Native command, identity, permission and lifecycle acceptance tests.
use crate::{config::Config, control, motor_files as files, motor_ipc as ipc};
use base64::{Engine, engine::general_purpose::STANDARD};
use moto_sdk::async_runtime::LocalRuntime;
use moto_sdk::io::fs::{AccessPermissions as Access, FsClient, RolePermissions};
use moto_sdk::sys::caps;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(super) const TOOL_CAPS: u64 = caps::CAP_INTERACTIVE
    | caps::CAP_NET
    | caps::CAP_FS_WRITE
    | caps::CAP_SPAWN
    | caps::CAP_SPAWN_DETACHED;

pub(super) fn command(args: &[&str], input: &str, caps: u64, expected: i32) -> String {
    let mut child = Command::new("/system/bin/wg-tool")
        .args(args)
        .env_clear()
        .env(caps::MOTOR_OS_CAPS_ENV_KEY, format!("0x{caps:x}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Some negative cases reject before reading stdin.
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    let deadline = Instant::now() + Duration::from_secs(7);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("wg-tool did not finish: {args:?}");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let output = child.wait_with_output().unwrap();
    let text = String::from_utf8([output.stdout, output.stderr].concat()).unwrap();
    assert_eq!(output.status.code(), Some(expected), "{args:?}: {text}");
    text
}

pub(super) fn tool(args: &[&str], input: &str) -> String {
    command(args, input, TOOL_CAPS, 0)
}

pub(super) fn permissions(path: &str, permissions: RolePermissions) {
    LocalRuntime::new().block_on(async {
        let fs = FsClient::connect().unwrap();
        let id = fs.stat(path).await.unwrap().0;
        fs.set_all_permissions(id, permissions).await.unwrap();
    });
}

pub(super) fn provider_pids() -> Vec<u64> {
    moto_sdk::sys_io::stats::IoStatsService::connect()
        .unwrap()
        .list_external_net_device_pids(Some(ipc::deadline()))
        .unwrap()
}

pub(super) fn pid(output: &str) -> u64 {
    output
        .split("pid=")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

pub fn run() {
    assert_eq!(ipc::own_caps() & TOOL_CAPS, TOOL_CAPS);
    assert!(provider_pids().is_empty());
    assert!(tool(&["status"], "").contains("No WireGuard"));
    for (mask, expected) in [
        (TOOL_CAPS & !caps::CAP_INTERACTIVE, "Interactive"),
        (TOOL_CAPS & !caps::CAP_NET, "CAP_NET"),
        (TOOL_CAPS & !caps::CAP_SPAWN, "CAP_SPAWN"),
        (TOOL_CAPS & !caps::CAP_SPAWN_DETACHED, "CAP_SPAWN_DETACHED"),
    ] {
        assert!(command(&["up", "/user/cfg/missing.toml"], "", mask, 1).contains(expected));
    }
    command(&["new"], "", TOOL_CAPS & !caps::CAP_FS_WRITE, 1);
    command(&["new"], "\n\n\n\n192.168.4.2\nno\n", TOOL_CAPS, 130);
    assert!(!Path::new("/user/cfg/wireguard/wg0.toml").exists());
    let output = tool(&["new"], "\r\n\r\n\r\n\r\n192.168.4.2\r\nyes\r\n");
    assert!(output.contains("Interface: wg0"));
    let original = "/user/cfg/wireguard/wg0.toml";
    let renamed = "/user/cfg/wireguard/office.toml";
    let document = files::read(Path::new(original)).unwrap();
    assert_eq!(document.permissions, files::FILE_PERMISSIONS);
    let config = Config::parse(&document.text).unwrap();
    assert!(!output.contains(&STANDARD.encode(config.private_key)));
    assert!(config.peers.is_empty());
    assert!(!Path::new("/user/cfg/wireguard/wg0.key").exists());
    let second = tool(&["new"], "\n\n51821\n10.21.0.1/24\n192.168.4.2\nyes\n");
    assert!(second.contains("Interface: wg1"));
    std::fs::rename(original, renamed).unwrap();
    std::fs::write("/user/cfg/wireguard/office.key", "ignored malformed key").unwrap();

    let daemon = pid(&tool(&["up", renamed], ""));
    assert_eq!(provider_pids(), vec![daemon]);
    {
        let (mut connection, peer_caps) =
            ipc::Connection::open(&format!("wg-control-{daemon}"), daemon)
                .unwrap()
                .unwrap();
        assert_eq!(peer_caps, caps::CAP_INTERACTIVE | caps::CAP_NET);
        let initial = control::Interface::decode(
            &connection
                .rpc(control::GET_INTERFACE, &[], ipc::deadline())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(initial.name, "wg0");
        assert_eq!(initial.path, renamed);
        assert_eq!(initial.peer_count, 0);
        assert!(
            connection
                .rpc(control::GET_PEER, &0u16.to_le_bytes(), ipc::deadline())
                .is_err()
        );
        let request = connection.0.req::<moto_sdk::ipc::sync::RequestHeader>();
        request.cmd = control::GET_INTERFACE;
        request.ver = control::VERSION;
        request.flags = 1;
        connection.0.do_rpc(Some(ipc::deadline())).unwrap();
        assert_eq!(
            connection
                .0
                .resp::<moto_sdk::ipc::sync::ResponseHeader>()
                .result,
            moto_sdk::rt::E_INVALID_ARGUMENT
        );
        assert!(
            connection
                .rpc(control::GET_INTERFACE, &[], ipc::deadline())
                .is_ok()
        );
    }
    command(&["up", renamed], "", TOOL_CAPS, 1);
    assert_eq!(provider_pids(), vec![daemon]);
    std::fs::write(
        renamed,
        format!("{}\n# manual trailing comment\n", document.text),
    )
    .unwrap();
    let psk = STANDARD.encode([23; 32]);
    let output = tool(
        &["add-peer", renamed],
        &format!(
            "office laptop\n{}\n\n10.22.0.19/24\n0\n{psk}\nyes\n",
            STANDARD.encode([9; 32])
        ),
    );
    assert!(!output.contains(&psk));
    let edited = files::read(Path::new(renamed)).unwrap();
    assert!(edited.text.starts_with(&document.text));
    assert!(edited.text.contains("# manual trailing comment"));
    assert!(edited.text.contains("# Peer: office laptop"));
    assert_eq!(edited.permissions, files::FILE_PERMISSIONS);
    assert_eq!(Config::parse(&edited.text).unwrap().peers.len(), 1);
    assert!(tool(&["status"], "").contains("peers: 0"));
    tool(&["down", "wg0"], "");
    assert!(provider_pids().is_empty());
    drop(std::net::UdpSocket::bind("192.168.4.2:51820").unwrap());
    assert!(tool(&["down", "wg0"], "").contains("already down"));

    tool(&["up", renamed], "");
    tool(&["up", "/user/cfg/wireguard/wg1.toml"], "");
    std::fs::remove_file(renamed).unwrap();
    let status = tool(&["status"], "");
    assert!(status.contains("interface: wg0") && status.contains("interface: wg1"));
    assert!(status.contains("peers: 1") && status.contains("preshared key: set"));
    assert!(status.contains("none (no current session)") && status.contains("not learned"));
    assert!(!status.contains(&psk) && !status.contains(&STANDARD.encode(config.private_key)));
    // wg0 is known only from discovery after its source file was removed.
    assert!(command(&["new"], "", TOOL_CAPS, 130).contains("Interface name [wg2]"));
    tool(&["down", "wg0"], "");
    tool(&["down", "wg1"], "");
    assert!(provider_pids().is_empty());

    files::Destination::prepare(renamed, None)
        .unwrap()
        .publish(&edited.text)
        .unwrap();
    permissions(
        renamed,
        RolePermissions::new(Access::Rwx, Access::Rw, Access::R),
    );
    command(&["up", renamed], "", TOOL_CAPS, 1);
    permissions(renamed, files::FILE_PERMISSIONS);
    permissions(CONFIG_DIRECTORY, RolePermissions::all(Access::Rwx));
    command(&["up", renamed], "", TOOL_CAPS, 1);
    permissions(
        CONFIG_DIRECTORY,
        RolePermissions::new(Access::Rwx, Access::Rwx, Access::None),
    );
    // Removing Interactive write access is irreversible through chmod by that
    // role. Test it last, then delete the fixture through its writable parent.
    permissions(
        renamed,
        RolePermissions::new(Access::Rwx, Access::R, Access::None),
    );
    command(&["add-peer", renamed], "", TOOL_CAPS, 1);
    assert_eq!(std::fs::read_to_string(renamed).unwrap(), edited.text);
    assert!(provider_pids().is_empty());
    for path in [
        renamed,
        "/user/cfg/wireguard/wg1.toml",
        "/user/cfg/wireguard/office.key",
    ] {
        std::fs::remove_file(path).unwrap();
    }
    println!("wg-tool native lifecycle and permissions PASS");
}

const CONFIG_DIRECTORY: &str = "/user/cfg/wireguard";
