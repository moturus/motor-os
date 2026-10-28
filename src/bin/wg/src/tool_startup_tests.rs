//! Exercise provisional activation with a real private launcher endpoint.
use crate::tool_protocol_tests::child_command;
use crate::tool_tests::{TOOL_CAPS, provider_pids, tool};
use crate::{control, motor_ipc as ipc};
use moto_sdk::ipc::sync::{ChannelSize, LocalServer};
use moto_sdk::rt;
use moto_sdk::sys::{self, SysHandle, caps};
use std::io::{BufRead, Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn spawn(path: &str) -> (LocalServer, Child, ipc::Handle) {
    let deadline = ipc::deadline();
    let url = format!("wg-startup-test-{}", sys::current_pid());
    let server = LocalServer::new(&url, ChannelSize::Small, 1, 1).unwrap();
    let child = Command::new("/system/bin/wg")
        .args([
            "--managed",
            &url,
            &sys::current_pid().to_string(),
            &deadline.as_u64().to_string(),
            path,
        ])
        .env_clear()
        .env(
            caps::MOTOR_OS_CAPS_ENV_KEY,
            format!("0x{:x}", caps::CAP_INTERACTIVE | caps::CAP_NET),
        )
        .env(caps::MOTOR_OS_DETACHED_ENV_KEY, "true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    (server, child, ipc::alarm(deadline).unwrap())
}

fn request(server: &mut LocalServer, alarm: &ipc::Handle, pid: u64, command: u16) -> SysHandle {
    loop {
        for handle in server.wait(SysHandle::NONE, &[alarm.0]).unwrap() {
            assert_ne!(handle, alarm.0, "startup request {command} timed out");
            let connection = server.get_connection(handle).unwrap();
            ipc::authenticate(handle, Some(pid)).unwrap();
            if connection.have_req() {
                let (actual, payload) = ipc::request(connection).unwrap();
                assert_eq!(actual, command);
                if command == control::READY {
                    let interface = control::Interface::decode(&payload).unwrap();
                    assert_eq!(interface.name, "wg_protocol");
                    assert_eq!(provider_pids(), vec![pid]);
                }
                return handle;
            }
        }
    }
}

fn reply(server: &mut LocalServer, handle: SysHandle, payload: &[u8]) {
    ipc::respond(server.get_connection(handle).unwrap(), rt::E_OK, payload).unwrap();
}

fn wait_exit(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(7);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success(), "provisional daemon must report failure");
            break;
        }
        assert!(Instant::now() < deadline, "provisional daemon did not exit");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(provider_pids().is_empty());
    drop(std::net::UdpSocket::bind("192.168.4.2:51827").unwrap());
}

pub(super) fn orphan(path: &str) {
    let (mut server, child, alarm) = spawn(path);
    let pid = u64::from(child.id());
    let handle = request(&mut server, &alarm, pid, control::HELLO);
    reply(&mut server, handle, &[]);
    request(&mut server, &alarm, pid, control::READY);
    println!("PROVISIONAL {pid}");
    std::io::stdout().flush().unwrap();
    // The test parent kills this launcher while its detached child awaits ACK.
    let _ = std::io::stdin().read(&mut [0]);
}

pub(super) fn report_child(url: &str, scenario: &str, parent: u64) {
    if scenario == "exited" {
        return;
    }
    let (mut connection, _) = ipc::Connection::open(url, parent).unwrap().unwrap();
    connection
        .rpc(control::HELLO, &[], ipc::deadline())
        .unwrap();
    if scenario == "after-ready" {
        let interface = control::Snapshot::new(
            &crate::tool_protocol_tests::config(),
            "/user/cfg/wireguard/protocol.toml",
        )
        .interface;
        connection
            .rpc(
                control::READY,
                &interface.encode().unwrap(),
                ipc::deadline(),
            )
            .unwrap();
    }
    if scenario != "deadline" {
        connection.0.disconnect();
    }
    // Keep the child alive so a lost connection cannot be mistaken for exit.
    let _ = std::io::stdin().read(&mut [0]);
}

fn startup_errors() {
    for scenario in ["exited", "before-ready", "after-ready", "deadline"] {
        let url = format!("wg-report-test-{}-{scenario}", sys::current_pid());
        let mut server = LocalServer::new(&url, ChannelSize::Small, 1, 1).unwrap();
        let deadline = ipc::deadline();
        let alarm = ipc::alarm(deadline).unwrap();
        let mut child = child_command(
            "startup-report",
            &url,
            caps::CAP_INTERACTIVE | caps::CAP_NET,
        )
        .args([scenario, &sys::current_pid().to_string()])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
        if scenario == "exited" {
            assert!(child.wait().unwrap().success());
        }
        let error = crate::launch::await_startup(&mut server, &mut child, &alarm, deadline)
            .expect_err("startup without COMMITTED must fail");
        let reason = match scenario {
            "exited" => "daemon exited before startup completed",
            "deadline" => "startup deadline expired",
            _ => "startup connection closed",
        };
        assert!(error.starts_with(reason), "{scenario}: {error}");
        assert!(error.contains(&format!("pid={}", child.id())), "{error}");
        assert_eq!(
            error.contains("activation is not confirmed; use wg-tool status"),
            matches!(scenario, "after-ready" | "deadline"),
            "{scenario}: {error}"
        );
        drop(server);
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
    }
    println!("wg-tool definite and uncertain startup failures PASS");
}

pub(super) fn run(path: &str) {
    startup_errors();
    for mode in [
        "hello",
        "occupied",
        "ready",
        "timeout",
        "malformed",
        "receipt",
    ] {
        let (mut server, mut child, alarm) = spawn(path);
        let pid = u64::from(child.id());
        let handle = request(&mut server, &alarm, pid, control::HELLO);
        if mode == "hello" {
            drop(server);
            wait_exit(&mut child);
            continue;
        }
        let _occupied = (mode == "occupied").then(|| {
            LocalServer::new(&format!("wg-control-{pid}"), ChannelSize::Small, 1, 1).unwrap()
        });
        reply(&mut server, handle, &[]);
        if mode == "occupied" {
            let handle = request(&mut server, &alarm, pid, control::START_ERROR);
            reply(&mut server, handle, &[]);
            wait_exit(&mut child);
            continue;
        }
        let handle = request(&mut server, &alarm, pid, control::READY);
        match mode {
            "ready" => drop(server),
            "timeout" => {
                wait_exit(&mut child); // Keep the channel open without acknowledging.
                continue;
            }
            "malformed" => {
                reply(&mut server, handle, &[1]);
                wait_exit(&mut child);
                continue;
            }
            "receipt" => {
                reply(&mut server, handle, &[]);
                request(&mut server, &alarm, pid, control::COMMITTED);
                drop(server); // An acknowledged activation survives a lost receipt.
                assert!(tool(&["status"], "").contains("wg_protocol"));
                tool(&["down", "wg_protocol"], "");
                assert!(child.wait().unwrap().success());
                continue;
            }
            _ => unreachable!(),
        }
        wait_exit(&mut child);
    }
    let mut launcher = child_command("provisional-launcher", path, TOOL_CAPS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(launcher.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let pid: u64 = line
        .strip_prefix("PROVISIONAL ")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(provider_pids(), vec![pid]);
    launcher.kill().unwrap();
    launcher.wait().unwrap();
    // Retirement is asynchronous after launcher death; observe its completion
    // without restarting the operation or hiding a failed attempt.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !provider_pids().is_empty() {
        assert!(
            Instant::now() < deadline,
            "orphaned provisional device remained"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    // A fresh activation proves the name, address and listen port were released.
    tool(&["up", path], "");
    tool(&["down", "wg_protocol"], "");
    println!("wg-tool provisional startup, cancellation and launcher death PASS");
}
