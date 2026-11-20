//! Native boundary cases using real provider registrations and IPC handles.
use crate::tool_tests::{TOOL_CAPS, command, pid, provider_pids, tool};
use crate::{config::Config, control, motor_files as files, motor_ipc as ipc};
use moto_sdk::async_runtime::LocalRuntime;
use moto_sdk::io::ip_device::IpDevice;
use moto_sdk::ipc::sync::{ChannelSize, ClientConnection, LocalServer};
use moto_sdk::rt;
use moto_sdk::sys::{self, SysCpu, SysHandle, caps};
use moto_sdk::sys_io::api_ip_device::{Cidr, Registration};
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

pub(super) fn config() -> Config {
    Config {
        name: "wg_protocol".into(),
        private_key: [7; 32],
        transport_addresses: vec!["192.168.4.2".parse().unwrap()],
        listen_port: 51827,
        cidrs: vec!["10.247.0.1/24".parse().unwrap()],
        peers: Vec::new(),
    }
}

pub(super) fn save(path: &str, config: &Config) {
    files::Destination::prepare(path, None)
        .unwrap()
        .publish(&crate::edit::serialize(config).unwrap())
        .unwrap();
}

fn denied_connection(url: &str) {
    let mut conn = ClientConnection::new(ChannelSize::Small).unwrap();
    conn.connect(url).unwrap();
    let deadline = ipc::deadline();
    loop {
        let result = SysCpu::wait(
            &mut [conn.handle()],
            SysHandle::NONE,
            SysHandle::NONE,
            Some(deadline),
        );
        if result == Err(rt::E_BAD_HANDLE) {
            break;
        }
        assert!(
            result.is_ok(),
            "unauthorized silent client was not disconnected: {result:?}"
        );
    }
    conn.disconnect();
}

pub fn child(args: &[String]) -> bool {
    match args {
        [mode, url] if mode == "denied-client" => {
            denied_connection(url);
        }
        [mode, url] if mode == "fake-listener" => {
            let _server = LocalServer::new(url, ChannelSize::Small, 1, 1).unwrap();
            println!("LISTENER READY");
            std::io::stdout().flush().unwrap();
            let _ = std::io::stdin().read(&mut [0]);
        }
        [mode, path] if mode == "provisional-launcher" => {
            crate::tool_startup_tests::orphan(path);
        }
        [mode, url, scenario, parent] if mode == "startup-report" => {
            crate::tool_startup_tests::report_child(url, scenario, parent.parse().unwrap());
        }
        _ => return false,
    }
    true
}

pub(super) fn child_command(mode: &str, url: &str, caps: u64) -> Command {
    let mut command = Command::new("/none/tmp/wg-tool-test-helper");
    command
        .args([mode, url])
        .env_clear()
        .env(caps::MOTOR_OS_CAPS_ENV_KEY, format!("0x{caps:x}"));
    command
}

fn install_helper() {
    let path = "/none/tmp/wg-tool-test-helper";
    std::fs::copy(std::env::current_exe().unwrap(), path).unwrap();
    LocalRuntime::new().block_on(async {
        use moto_sdk::io::fs::{AccessPermissions as Access, FsClient, RolePermissions};
        let fs = FsClient::connect().unwrap();
        let id = fs.stat(path).await.unwrap().0;
        fs.set_all_permissions(
            id,
            RolePermissions::new(Access::Rwx, Access::Rx, Access::Rx),
        )
        .await
        .unwrap();
    });
}

fn registration() -> Registration {
    Registration {
        name: "wg_discovery_fixture".into(),
        mtu: 1420,
        addresses: vec![Cidr {
            address: "10.246.0.1".parse().unwrap(),
            prefix_len: 24,
        }],
        routes: Vec::new(),
    }
}

fn discovery() {
    LocalRuntime::new().block_on(async {
        let device = IpDevice::register(&registration()).await.unwrap();
        assert_eq!(provider_pids(), vec![sys::current_pid()]);
        // A listed non-WireGuard provider with no endpoint is an empty success.
        assert!(tool(&["status"], "").contains("No WireGuard"));
        let url = format!("wg-control-{}", sys::current_pid());
        {
            let _server = LocalServer::new(&url, ChannelSize::Small, 1, 1).unwrap();
            let mut occupied = ClientConnection::new(ChannelSize::Small).unwrap();
            occupied.connect(&url).unwrap();
            let result = command(&["status"], "", TOOL_CAPS, 1);
            assert!(result.contains("cannot connect"));
            assert!(!result.contains("No WireGuard"));
        }
        {
            let _server = LocalServer::new(&url, ChannelSize::Small, 1, 1).unwrap();
            let result = command(&["status"], "", TOOL_CAPS, 1);
            assert!(result.contains("deadline expired"));
            assert!(!result.contains("No WireGuard"));
        }
        {
            let (started, ready) = std::sync::mpsc::sync_channel(1);
            let url = url.clone();
            let responder = std::thread::spawn(move || {
                let mut server = LocalServer::new(&url, ChannelSize::Small, 1, 1).unwrap();
                started.send(()).unwrap();
                while let Ok(handles) = server.wait(SysHandle::NONE, &[]) {
                    for handle in handles {
                        let connection = server.get_connection(handle).unwrap();
                        if connection.have_req() {
                            let bytes = connection.data_mut();
                            bytes[8..].fill(0);
                            bytes[10..12].copy_from_slice(&control::VERSION.to_le_bytes());
                            bytes[12] = 1; // Unsupported response flags.
                            connection.finish_rpc().unwrap();
                        }
                    }
                }
            });
            ready.recv().unwrap();
            assert!(
                command(&["status"], "", TOOL_CAPS, 1)
                    .contains("unsupported control version or flags")
            );
            responder.join().unwrap();
        }
        {
            let mut imposter =
                child_command("fake-listener", &url, caps::CAP_INTERACTIVE | caps::CAP_NET)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap();
            let mut ready = String::new();
            std::io::BufReader::new(imposter.stdout.take().unwrap())
                .read_line(&mut ready)
                .unwrap();
            assert_eq!(ready.trim(), "LISTENER READY");
            let result = command(&["status"], "", TOOL_CAPS, 1);
            assert!(result.contains("unexpected PID"));
            assert!(!result.contains("No WireGuard"));
            drop(imposter.stdin.take());
            assert!(imposter.wait().unwrap().success());
        }
        device.unregister().await.unwrap();
        assert!(provider_pids().is_empty());
    });
    println!("wg-tool discovery errors and impersonation PASS");
}

fn protocol_and_conflicts(path: &str) {
    let daemon = pid(&tool(&["up", path], ""));
    let url = format!("wg-control-{daemon}");
    for mask in [caps::CAP_NET, caps::CAP_INTERACTIVE] {
        assert!(
            child_command("denied-client", &url, mask)
                .status()
                .unwrap()
                .success()
        );
    }
    {
        let (mut conn, _) = ipc::Connection::open(&url, daemon).unwrap().unwrap();
        for (version, flags, length, command) in [
            (2u16, 0u32, 0u32, control::GET_INTERFACE),
            (1, 1, 0, control::GET_INTERFACE),
            (1, 0, u32::MAX, control::GET_INTERFACE),
            (1, 0, 0, u16::MAX),
        ] {
            let bytes = conn.0.data_mut();
            bytes[8..].fill(0xa5);
            bytes[8..10].copy_from_slice(&command.to_le_bytes());
            bytes[10..12].copy_from_slice(&version.to_le_bytes());
            bytes[12..16].copy_from_slice(&flags.to_le_bytes());
            bytes[16..20].copy_from_slice(&length.to_le_bytes());
            bytes[20..24].fill(0);
            conn.0.do_rpc(Some(ipc::deadline())).unwrap();
            let header = conn.0.resp::<moto_sdk::ipc::sync::ResponseHeader>();
            assert_eq!(header.result, rt::E_INVALID_ARGUMENT);
            assert_eq!(header.ver, control::VERSION);
            assert!(conn.0.data()[12..].iter().all(|byte| *byte == 0));
        }
        assert!(
            conn.rpc(control::GET_PEER, &0u16.to_le_bytes(), ipc::deadline())
                .is_err()
        );
        assert!(
            conn.rpc(control::GET_INTERFACE, &[], ipc::deadline())
                .is_ok()
        );
    }
    let conflict = "/user/cfg/wireguard/conflict.toml";
    for variant in 0..5 {
        let mut candidate = config();
        match variant {
            0 => candidate.listen_port += 1, // Same interface name, different port.
            1 => {
                candidate.name = "wg_other".into();
                candidate.listen_port += 1;
            } // Same address.
            2 => {
                candidate.name = "wg_other".into();
                candidate.cidrs = vec!["10.245.0.1/24".parse().unwrap()];
            } // Same port.
            3 => {
                candidate.name = "wg_other".into();
                candidate.transport_addresses = vec!["192.0.2.199".parse().unwrap()];
            }
            _ => {
                candidate.name = "wg_other".into();
                candidate.listen_port += 1;
                candidate.cidrs = vec!["10.245.0.1/24".parse().unwrap()];
                candidate.peers = Config::parse(&std::fs::read_to_string(path).unwrap())
                    .unwrap()
                    .peers; // Same explicit route, otherwise independent.
            }
        }
        save(conflict, &candidate);
        let output = command(&["up", conflict], "", TOOL_CAPS, 1);
        assert!(output.contains("could not activate"), "{output}");
        assert!(!output.contains("activation is not confirmed"), "{output}");
        assert_eq!(provider_pids(), vec![daemon]);
        std::fs::remove_file(conflict).unwrap();
    }
    assert!(tool(&["status"], "").contains("wg_protocol"));
    // Stop on the same authenticated connection, then ensure it cannot address
    // a replacement process with the reused name.
    let (mut old, _) = ipc::Connection::open(&url, daemon).unwrap().unwrap();
    old.rpc(control::GET_INTERFACE, &[], ipc::deadline())
        .unwrap();
    old.rpc(control::STOP, &[], ipc::deadline()).unwrap();
    old.0.disconnect();
    let replacement = pid(&tool(&["up", path], ""));
    assert_ne!(daemon, replacement);
    assert!(old.rpc(control::STOP, &[], ipc::deadline()).is_err());
    assert_eq!(provider_pids(), vec![replacement]);
    tool(&["down", "wg_protocol"], "");
    println!("wg-tool authorization, malformed IPC and conflicts PASS");
}

fn writes(path: &str) {
    let before = files::read(Path::new(path)).unwrap();
    let entries = || {
        let mut names: Vec<_> = std::fs::read_dir(files::CONFIG_DIR)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        names
    };
    let names = entries();
    assert_eq!(
        files::Destination::prepare(path, Some(before.permissions))
            .unwrap()
            .fail_write_for_test("not published"),
        Err("cannot write staging file")
    );
    let after = files::read(Path::new(path)).unwrap();
    assert_eq!(before.text, after.text);
    assert_eq!(before.permissions, after.permissions);
    assert_eq!(names, entries());
    command(&["new"], &format!("unique\n{path}\n"), TOOL_CAPS, 130);
    assert_eq!(std::fs::read_to_string(path).unwrap(), before.text);
    let invalid = "/user/cfg/wireguard/invalid.toml";
    files::Destination::prepare(invalid, None)
        .unwrap()
        .publish("private_key = 'PRIVATE-INVALID-SECRET'\n")
        .unwrap();
    let output = command(&["up", invalid], "", TOOL_CAPS, 1);
    assert!(output.contains("rejected the configuration"), "{output}");
    assert!(!output.contains("activation is not confirmed"), "{output}");
    assert!(!output.contains("PRIVATE-INVALID-SECRET"));
    assert!(provider_pids().is_empty());
    for unreadable in [false, true] {
        if unreadable {
            use moto_sdk::io::fs::{AccessPermissions as Access, RolePermissions};
            crate::tool_tests::permissions(
                invalid,
                RolePermissions::new(Access::Rwx, Access::None, Access::None),
            );
        }
        let output = command(&["new"], "", TOOL_CAPS, 1);
        assert!(output.contains(invalid), "{output}");
        assert!(!output.contains("PRIVATE-INVALID-SECRET"));
    }
    std::fs::remove_file(invalid).unwrap();
    println!("wg-tool failed publication preserves original PASS");
}

pub fn run() {
    install_helper();
    discovery();
    let path = "/user/cfg/wireguard/protocol.toml";
    let mut config = config();
    config.peers.push(crate::config::Peer {
        public_key: [9; 32],
        endpoint: None,
        allowed_ips: vec!["10.241.0.0/24".parse().unwrap()],
        persistent_keepalive: None,
        preshared_key: None,
    });
    save(path, &config);
    protocol_and_conflicts(path);
    crate::tool_startup_tests::run(path);
    writes(path);
    std::fs::remove_file(path).unwrap();
    std::fs::remove_file("/none/tmp/wg-tool-test-helper").unwrap();
}

pub fn system() {
    assert!(ipc::own_caps() & caps::CAP_SYS != 0 && ipc::own_caps() & caps::CAP_INTERACTIVE != 0);
    for operation in ["new", "status"] {
        assert!(
            command(&[operation], "", TOOL_CAPS | caps::CAP_SYS, 1).contains("Interactive role")
        );
    }
    LocalRuntime::new().block_on(async {
        let device = IpDevice::register(&registration()).await.unwrap();
        let _server = LocalServer::new(
            &format!("wg-control-{}", sys::current_pid()),
            ChannelSize::Small,
            1,
            1,
        )
        .unwrap();
        assert!(
            command(&["status"], "", TOOL_CAPS, 1).contains("unexpected PID, role or capabilities")
        );
        device.unregister().await.unwrap();
    });
    // The positive path uses an Interactive tool and daemon; the System parent
    // is denied even with CAP_INTERACTIVE also set and without sending a request.
    let path = "/user/cfg/wireguard/system-test.toml";
    tool(
        &["new"],
        &format!("wg_system_test\n{path}\n51827\n10.247.0.1/24\n192.168.4.2\nyes\n"),
    );
    let daemon = pid(&tool(&["up", path], ""));
    denied_connection(&format!("wg-control-{daemon}"));
    tool(&["down", "wg_system_test"], "");
    let before = std::fs::read_to_string(path).unwrap();
    LocalRuntime::new().block_on(async {
        use moto_sdk::io::fs::{AccessPermissions as Access, FsClient, RolePermissions};
        let fs = FsClient::connect().unwrap();
        let directory = fs.stat(files::CONFIG_DIR).await.unwrap().0;
        fs.set_all_permissions(
            directory,
            RolePermissions::new(Access::Rwx, Access::Rx, Access::None),
        )
        .await
        .unwrap();
        assert!(command(&["add-peer", path], "", TOOL_CAPS, 1).contains("parent is read-only"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), before);
        fs.set_all_permissions(
            directory,
            RolePermissions::new(Access::Rwx, Access::Rwx, Access::None),
        )
        .await
        .unwrap();
    });
    // System can install restrictive System permissions; edits must refuse
    // instead of silently adding execute permission to a replacement.
    LocalRuntime::new().block_on(async {
        use moto_sdk::io::fs::{AccessPermissions as Access, FsClient, RolePermissions};
        let fs = FsClient::connect().unwrap();
        let id = fs.stat(path).await.unwrap().0;
        fs.set_all_permissions(
            id,
            RolePermissions::new(Access::Rw, Access::Rw, Access::None),
        )
        .await
        .unwrap();
    });
    assert!(
        command(&["add-peer", path], "", TOOL_CAPS, 1).contains("restricted System permissions")
    );
    std::fs::remove_file(path).unwrap();
    println!("wg-tool System role and permission preservation PASS");
}
