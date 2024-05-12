use std::io::ErrorKind;
use std::io::Read;
use std::io::Result;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;

pub fn run(args: &crate::Args) -> ! {
    match do_run(args) {
        Ok(_) => std::process::exit(0),
        Err(err) => {
            eprintln!("{} error: {:?}", crate::binary_name(), err);
            std::process::exit(1)
        }
    }
}

fn do_run(args: &crate::Args) -> Result<()> {
    use std::net::ToSocketAddrs;
    let addrs = args.client.as_ref().unwrap().to_socket_addrs()?;

    for addr in addrs {
        // return try_addr(addr, crate::CMD_TCP_THROUGHPUT_IN);
        if try_addr(addr, crate::CMD_TCP_RR, args).is_ok() {
            std::thread::sleep(Duration::from_millis(100));
            if try_addr(addr, crate::CMD_TCP_THROUGHPUT_OUT, args).is_ok() {
                std::thread::sleep(Duration::from_millis(100));
                return try_addr(addr, crate::CMD_TCP_THROUGHPUT_IN, args);
            }
        }
    }

    Err(ErrorKind::HostUnreachable.into())
}

fn try_addr(addr: SocketAddr, cmd: u64, args: &crate::Args) -> Result<()> {
    let mut buf: [u8; 1500] = [0; 1500];
    let mut tcp_stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1))?;
    tcp_stream.set_nodelay(true).unwrap();

    tcp_stream.write_all(crate::MAGIC_BYTES_CLIENT)?;
    tcp_stream.read_exact(&mut buf[0..crate::MAGIC_BYTES_SERVER.len()])?;

    if crate::MAGIC_BYTES_SERVER != &buf[0..crate::MAGIC_BYTES_SERVER.len()] {
        eprintln!("{} error: bad remote reply.", crate::binary_name());
        std::process::exit(1);
    }

    let buf: &[u8] =
        unsafe { core::slice::from_raw_parts(&cmd as *const u64 as usize as *const u8, 8) };
    tcp_stream.write_all(buf)?;

    match cmd {
        crate::CMD_TCP_RR => {
            do_rr(tcp_stream)?;
        }
        crate::CMD_TCP_THROUGHPUT_OUT => {
            crate::do_throughput_write(tcp_stream, "client => server", Some(args))?;
        }
        crate::CMD_TCP_THROUGHPUT_IN => {
            crate::do_throughput_read(tcp_stream, "server => client", Some(args))?;
        }
        _ => {
            panic!("unrecognized command: {}", cmd);
        }
    }

    Ok(())
}

fn do_rr(mut stream: TcpStream) -> Result<()> {
    let mut buf: [u8; 1500] = [0; 1500];
    const RR_DURATION: Duration = Duration::from_secs(3);
    println!(
        "{}: starting TCP round-robin test (64 byte buffers)...",
        crate::binary_name()
    );
    let mut rr_iters = 0_u64;
    let start = std::time::Instant::now();
    while start.elapsed() < RR_DURATION {
        rr_iters += 1;

        stream.write_all(&buf[0..64])?;
        stream.read_exact(&mut buf[0..64])?;
    }
    let stop = std::time::Instant::now();

    stream.shutdown(std::net::Shutdown::Both)?;
    core::mem::drop(stream);

    let iters_per_sec = (rr_iters as f64) / ((stop - start).as_secs_f64());
    println!(
        "\tRR done: {} iterations/sec; {:.3} usec/iteration.",
        iters_per_sec as u64,
        1_000_000_f64 / iters_per_sec
    );

    Ok(())
}
