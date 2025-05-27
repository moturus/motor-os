use std::io::Read;
use std::io::Result;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpStream;

pub fn run(port: u16) -> ! {
    match do_run(port) {
        Ok(_) => std::process::exit(0),
        Err(err) => {
            eprintln!("{} error: {:?}", crate::binary_name(), err);
            std::process::exit(1)
        }
    }
}

fn do_run(port: u16) -> Result<()> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
    let listener = std::net::TcpListener::bind(addr)?;

    println!(
        "{} server: listening on 0.0.0.0:{}\n",
        crate::binary_name(),
        port
    );

    for tcp_stream in listener.incoming().flatten() {
        let _ = std::thread::spawn(|| {
            let _ = handle_connection(tcp_stream);
        });
    }

    unreachable!()
}

fn handle_connection(mut tcp_stream: TcpStream) -> Result<()> {
    tcp_stream.set_nodelay(true).unwrap();
    let mut buf: [u8; 1500] = [0; 1500];

    // "Authenticate" the client.
    tcp_stream.read_exact(&mut buf[0..crate::MAGIC_BYTES_CLIENT.len()])?;

    if crate::MAGIC_BYTES_CLIENT != &buf[0..crate::MAGIC_BYTES_CLIENT.len()] {
        return Ok(()); // Doesn't matter if we return Ok or Err.
    }
    tcp_stream.write_all(crate::MAGIC_BYTES_SERVER)?;

    // Figure out which test we are doing.
    let mut cmd: u64 = 0;
    let buf: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(&mut cmd as *mut u64 as usize as *mut u8, 8) };
    tcp_stream.read_exact(buf)?;
    match cmd {
        crate::CMD_TCP_RR => {
            do_rr(tcp_stream)?;
        }
        crate::CMD_TCP_THROUGHPUT_OUT => {
            crate::do_throughput_read(tcp_stream, None);
        }
        crate::CMD_TCP_THROUGHPUT_IN => {
            crate::do_throughput_write(tcp_stream, None);
        }
        _ => {
            eprintln!("unrecognized command: {cmd}");
        }
    }

    Ok(())
}

fn do_rr(mut stream: TcpStream) -> Result<()> {
    let mut buf: [u8; 64] = [0; 64];

    loop {
        stream.read_exact(&mut buf)?;
        stream.write_all(&buf)?;
    }
}
