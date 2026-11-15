//! Host probe for 100 TCP forwards through OpenSSH's local Unix listener.
#[cfg(unix)]
use std::io::{self, BufRead, BufReader, Read};
#[cfg(unix)]
use std::net::Shutdown;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
fn main() -> io::Result<()> {
    let path = std::env::args_os().nth(1).expect("local forwarding socket");
    let mut forwards = Vec::with_capacity(100);
    for _ in 0..100 {
        let mut socket = UnixStream::connect(&path)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut banner = String::new();
        BufReader::new(&mut socket).read_line(&mut banner)?;
        assert!(
            banner.starts_with("SSH-2.0-"),
            "unexpected SSH banner: {banner:?}"
        );
        forwards.push(socket);
    }
    // Every target is waiting for client identification: none may have closed
    // while later forwards were opening. Hold all sockets until this check.
    for socket in &mut forwards {
        socket.set_nonblocking(true)?;
        match socket.read(&mut [0]) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            other => panic!("forward closed or sent unexpected data: {other:?}"),
        }
    }
    // Wait for the target to close after EOF. A later shell write is then
    // ordered after the server has processed forwarding EOFs.
    for socket in &forwards {
        socket.set_nonblocking(false)?;
        socket.shutdown(Shutdown::Write)?;
    }
    for socket in &mut forwards {
        assert_eq!(
            socket.read(&mut [0])?,
            0,
            "unexpected target data after EOF"
        );
    }
    println!("100 simultaneous forwards PASS");
    Ok(())
}

#[cfg(not(unix))]
fn main() {}
