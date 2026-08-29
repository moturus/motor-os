//! Loopback close-race reproducer (perf run 2026-08-28). Not a test:
//! `systest close-race [iters]` -- a server accepts, reads "ping", writes
//! "pong" and drops the stream; the client must read "pong", never an RST.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

pub fn run(args: &[String]) {
    let iters: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..iters {
            let (mut stream, _) = listener.accept().unwrap();
            let mut ping = [0_u8; 4];
            if stream.read_exact(&mut ping).is_err() {
                continue;
            }
            let _ = stream.write_all(b"pong");
            drop(stream);
        }
    });
    let (mut ok, mut reset, mut timeout, mut other) = (0_u64, 0_u64, 0_u64, 0_u64);
    let start = std::time::Instant::now();
    for i in 0..iters {
        let it_start = std::time::Instant::now();
        let mut stream = match TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5))
        {
            Ok(s) => s,
            Err(e) => {
                println!("close-race: connect failed at iteration {i}: {e:?}");
                break;
            }
        };
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        stream.write_all(b"ping").unwrap();
        let mut pong = [0_u8; 4];
        match stream.read_exact(&mut pong) {
            Ok(()) if &pong == b"pong" => ok += 1,
            Ok(()) => other += 1,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => reset += 1,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                timeout += 1;
                println!("close-race: read timed out at iteration {i}");
            }
            Err(e) => {
                other += 1;
                println!("close-race: read error at iteration {i}: {e:?}");
            }
        }
        let it = it_start.elapsed();
        if it > std::time::Duration::from_millis(20) {
            println!("close-race: iteration {i} took {it:?}");
        }
        if (i + 1) % 500 == 0 {
            println!("close-race: {} done", i + 1);
        }
    }
    server.join().unwrap();
    println!(
        "close-race: {iters} iterations in {:?}: ok {ok}, ConnectionReset {reset}, timeouts {timeout}, other {other}",
        start.elapsed()
    );
}

/// Child-process variant: a fresh listener per iteration, the client in a
/// child process (the shape of the debug-build failures). Exit codes from
/// the child: 0 pong, 2 ConnectionReset, 3 other.
pub fn run_child_mode(args: &[String]) {
    let iters: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(200);
    let exe = std::env::current_exe().unwrap();
    let (mut ok, mut reset, mut other) = (0_u64, 0_u64, 0_u64);
    let start = std::time::Instant::now();
    for i in 0..iters {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut child = std::process::Command::new(&exe)
            .arg("close-race-client")
            .arg(addr.to_string())
            .spawn()
            .unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let mut ping = [0_u8; 4];
        stream.read_exact(&mut ping).unwrap();
        stream.write_all(b"pong").unwrap();
        drop(stream);
        drop(listener);
        match child.wait().unwrap().code() {
            Some(0) => ok += 1,
            Some(2) => {
                reset += 1;
                println!("close-race-child: ConnectionReset at iteration {i}");
            }
            c => {
                other += 1;
                println!("close-race-child: child exit {c:?} at iteration {i}");
            }
        }
    }
    println!(
        "close-race-child: {iters} iterations in {:?}: ok {ok}, ConnectionReset {reset}, other {other}",
        start.elapsed()
    );
}

pub fn run_client(args: &[String]) {
    let addr: std::net::SocketAddr = args[2].parse().unwrap();
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.write_all(b"ping").unwrap();
    let mut pong = [0_u8; 4];
    match stream.read_exact(&mut pong) {
        Ok(()) if &pong == b"pong" => std::process::exit(0),
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => std::process::exit(2),
        _ => std::process::exit(3),
    }
}
