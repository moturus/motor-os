use std::io::ErrorKind;
use std::io::Read;
use std::io::Result;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;
use std::time::Instant;

pub fn run(host_port: &str) -> ! {
    match do_run(host_port) {
        Ok(_) => std::process::exit(0),
        Err(err) => {
            eprintln!("{} error: {:?}", crate::binary_name(), err);
            std::process::exit(1)
        }
    }
}

fn do_run(host_port: &str) -> Result<()> {
    use std::net::ToSocketAddrs;
    let addrs = host_port.to_socket_addrs()?;

    for addr in addrs {
        // return try_addr(addr, crate::CMD_TCP_THROUGHPUT_IN);
        if try_addr(addr, crate::CMD_TCP_RR).is_ok() {
            std::thread::sleep(Duration::from_millis(100));
            if try_addr(addr, crate::CMD_TCP_THROUGHPUT_OUT).is_ok() {
                std::thread::sleep(Duration::from_millis(100));
                return try_addr(addr, crate::CMD_TCP_THROUGHPUT_IN);
            }
        }
    }

    Err(ErrorKind::HostUnreachable.into())
}

fn try_addr(addr: SocketAddr, cmd: u64) -> Result<()> {
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
            do_throughput_out(tcp_stream)?;
        }
        crate::CMD_TCP_THROUGHPUT_IN => {
            do_throughput_in(tcp_stream)?;
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

fn do_throughput_out(mut stream: TcpStream) -> std::io::Result<()> {
    let data = [0u8; 1024]; // Sample data buffer
    let mut total_bytes_sent = 0usize;
    const TP_DURATION: Duration = Duration::from_secs(3);
    println!(
        "{}: starting TCP throughput test (1k buffers)...",
        crate::binary_name()
    );

    let start = std::time::Instant::now();
    // for _ in 0..1000 {
    while start.elapsed() < TP_DURATION {
        match stream.write(&data) {
            Ok(bytes_sent) => total_bytes_sent += bytes_sent,
            Err(e) => {
                eprintln!("Failed to write to socket: {}", e);
                return Ok(());
            }
        }
    }

    stream.flush().unwrap();
    stream.shutdown(std::net::Shutdown::Both).unwrap();

    let duration = start.elapsed();
    let rate = total_bytes_sent as f64 / duration.as_secs_f64() / (1024.0 * 1024.0);
    println!(
        "\tThroughput client => server done: {:.2}MB sent; {:.2?} MiB/sec.",
        (total_bytes_sent as f64) / (1024.0 * 1024.0),
        rate
    );

    Ok(())
}

fn do_throughput_in(mut stream: TcpStream) -> Result<()> {
    let mut buffer = [0; 2048];
    let start_time = Instant::now();
    let mut total_bytes_read = 0usize;

    loop {
        let bytes_read = match stream.read(&mut buffer) {
            Ok(n) => n,
            Err(_) => break,
        };
        if bytes_read == 0 {
            break;
        }
        total_bytes_read += bytes_read;
    }

    let duration = start_time.elapsed();
    let rate = total_bytes_read as f64 / duration.as_secs_f64() / (1024.0 * 1024.0);
    println!(
        "\tThroughput server => client done: {:.2}MB received; {:.2?} MiB/sec.",
        total_bytes_read as f64 / (1024.0 * 1024.0),
        rate
    );

    Ok(())
}
