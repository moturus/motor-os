//! Sys-io network admission: a peer without `CAP_NET` is dropped before any
//! network command is served, whatever other capabilities it holds.

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use moto_sys::caps::{
    CAP_FS_WRITE, CAP_INTERACTIVE, CAP_NET, CAP_SPAWN, CAP_VSOCK, MOTOR_OS_CAPS_ENV_KEY,
};

use crate::net_harness::{bounded, bounded_output, drain_host_channel, host_channel};

const DENIED_CHILD: &str = "net-caps-denied-child";
const WITHOUT_VSOCK_CHILD: &str = "net-caps-without-vsock-child";
const DEADLINE_SECS: u64 = 10;
/// More than sys-io's accept pool of eight listeners.
const REPEATED_DENIALS: usize = 20;

/// Runs `f` on its own thread; missing the deadline is a failure.
fn with_deadline<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(DEADLINE_SECS))
        .unwrap_or_else(|_| panic!("{what} missed its deadline"))
}

/// A raw client's first RPC ends in a channel error, not a response.
async fn raw_denied_rpc() {
    let (sender, mut receiver) = moto_ipc::io_channel::connect("sys-io").unwrap();
    let mut request = moto_sys_io::api_vsock::availability_request();
    request.id = 1;
    // The peer may already be gone; the receive below reports that either way.
    let _ = sender.send(request).await;
    let response = bounded_output(receiver.recv(), DEADLINE_SECS)
        .await
        .expect("denied raw RPC missed its deadline");
    assert!(
        response.is_err(),
        "denied raw client was served: {response:?}"
    );
}

/// Sys-io drops an idle denied peer without waiting for a request.
async fn raw_denied_idle() {
    let (_sender, mut receiver) = moto_ipc::io_channel::connect("sys-io").unwrap();
    let response = bounded_output(receiver.recv(), DEADLINE_SECS)
        .await
        .expect("idle denied peer was not dropped");
    assert!(response.is_err(), "idle denied peer got {response:?}");
}

/// Every client path fails promptly without `CAP_NET`. Also run by a System
/// process: `CAP_SYS` does not substitute.
pub fn check_denied(port: u16) {
    let caps = moto_sys::ProcessStaticPage::get().capabilities;
    assert_eq!(0, caps & CAP_NET);

    let error = with_deadline("denied std connect", move || {
        std::net::TcpStream::connect(("127.0.0.1", port)).unwrap_err()
    });
    assert_eq!(std::io::ErrorKind::NotConnected, error.kind(), "{error:?}");

    moto_async::LocalRuntime::new().block_on(async {
        // The native connect returns before sys-io's decision; its RPCs fail.
        let (client, driver_task) = host_channel().await;
        assert_eq!(
            Some(Err(moto_rt::Error::NotConnected)),
            bounded_output(moto_io::net::vsock::availability(&client), DEADLINE_SECS).await
        );
        drop(client);
        assert!(bounded(driver_task, DEADLINE_SECS).await);

        raw_denied_idle().await;
        for _ in 0..REPEATED_DENIALS {
            raw_denied_rpc().await;
        }
    });
    println!(
        "net_caps::check_denied({:?}) PASS",
        moto_sys::caps::ProcessRole::from_caps(caps)
    );
}

pub fn is_denied_child(args: &[String]) -> bool {
    args.len() == 3 && args[1] == DENIED_CHILD
}

pub fn run_denied_child(args: &[String]) -> ! {
    check_denied(args[2].parse().unwrap());
    std::process::exit(0)
}

pub fn is_without_vsock_child(args: &[String]) -> bool {
    args.len() == 3 && args[1] == WITHOUT_VSOCK_CHILD
}

/// Holds `CAP_NET` but not `CAP_VSOCK`: TCP is served, vsock is refused.
pub fn run_without_vsock_child(args: &[String]) -> ! {
    let port: u16 = args[2].parse().unwrap();
    with_deadline("authorized TCP exchange", move || {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(b"v").unwrap();
        let mut byte = [0_u8];
        stream.read_exact(&mut byte).unwrap();
        assert_eq!(b"v", &byte);
    });
    moto_async::LocalRuntime::new().block_on(async {
        let (client, driver_task) = host_channel().await;
        assert_eq!(
            Some(Err(moto_rt::Error::NotAllowed)),
            bounded_output(moto_io::net::vsock::availability(&client), DEADLINE_SECS).await
        );
        drain_host_channel(client, driver_task).await;
    });
    std::process::exit(0)
}

fn spawn_child(mode: &str, port: u16, caps: u64) {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([mode, &port.to_string()])
        .env(MOTOR_OS_CAPS_ENV_KEY, format!("0x{caps:x}"))
        .status()
        .unwrap();
    assert_eq!(Some(0), status.code(), "{mode}");
}

/// Echoes bytes until the peer closes.
fn echo(mut stream: std::net::TcpStream) {
    let mut byte = [0_u8];
    while stream.read(&mut byte).unwrap() == 1 {
        stream.write_all(&byte).unwrap();
    }
}

/// Repeated denials neither stall authorized loopback traffic nor keep new
/// authorized clients out.
pub fn test_admission() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // The streaming client below, then the without-vsock child.
    let acceptor = std::thread::spawn(move || {
        let mut echoes = Vec::new();
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            echoes.push(std::thread::spawn(move || echo(stream)));
        }
        for echo in echoes {
            echo.join().unwrap();
        }
    });

    let stop = Arc::new(AtomicBool::new(false));
    let exchanges = Arc::new(AtomicUsize::new(0));
    let streaming = {
        let stop = stop.clone();
        let exchanges = exchanges.clone();
        std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            let mut byte = [0_u8];
            while !stop.load(Ordering::Acquire) {
                stream.write_all(b"s").unwrap();
                stream.read_exact(&mut byte).unwrap();
                exchanges.fetch_add(1, Ordering::AcqRel);
            }
        })
    };

    spawn_child(
        DENIED_CHILD,
        port,
        CAP_SPAWN | CAP_INTERACTIVE | CAP_VSOCK | CAP_FS_WRITE,
    );
    spawn_child(
        WITHOUT_VSOCK_CHILD,
        port,
        CAP_SPAWN | CAP_INTERACTIVE | CAP_NET | CAP_FS_WRITE,
    );

    let after_children = exchanges.load(Ordering::Acquire);
    let progressed = exchanges.clone();
    with_deadline("authorized loopback traffic", move || {
        while progressed.load(Ordering::Acquire) <= after_children {
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    stop.store(true, Ordering::Release);
    streaming.join().unwrap();
    acceptor.join().unwrap();
    println!("net_caps::test_admission PASS");
}
