//! Connect to a private SSH banner through a SOCKS5 proxy; host and guest use std.
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1);
    let proxy = args.next().expect("proxy address");
    let port: u16 = args
        .next()
        .expect("target port")
        .parse()
        .expect("numeric port");
    assert!(args.next().is_none(), "unexpected argument");
    let mut socket = TcpStream::connect(proxy)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    socket.write_all(&[5, 1, 0])?;
    let mut method = [0; 2];
    socket.read_exact(&mut method)?;
    assert_eq!(method, [5, 0]);
    let port = port.to_be_bytes();
    socket.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, port[0], port[1]])?;
    let mut response = [0; 10];
    socket.read_exact(&mut response)?;
    assert_eq!(response, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    let mut banner = String::new();
    BufReader::new(&mut socket)
        .take(256)
        .read_line(&mut banner)?;
    assert!(
        banner.starts_with("SSH-2.0-") && banner.ends_with('\n'),
        "invalid SSH banner: {banner:?}"
    );
    socket.shutdown(Shutdown::Write)?;
    assert_eq!(socket.read(&mut [0])?, 0, "target did not close after EOF");
    println!("SOCKS forwarding PASS");
    Ok(())
}
