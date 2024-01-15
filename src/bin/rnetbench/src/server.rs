use std::io::ErrorKind;
use std::io::Read;
use std::io::Result;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;
use std::time::Instant;

const TIMEOUT: Duration = Duration::from_secs(1);
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

    for tcp_stream in listener.incoming() {
        handle_connection(tcp_stream?)?;
    }

    unreachable!()
}

fn handle_connection(mut tcp_stream: TcpStream) -> Result<()> {
    println!("{}: got a connection.", crate::binary_name());
    tcp_stream.set_nodelay(true).unwrap();
    let mut buf: [u8; 1500] = [0; 1500];
    // tcp_stream.set_read_timeout(Some(TIMEOUT))?;
    // tcp_stream.set_write_timeout(Some(TIMEOUT))?;

    // "Authenticate" the client.
    tcp_stream.read_exact(&mut buf[0..crate::MAGIC_BYTES_CLIENT.len()])?;

    if crate::MAGIC_BYTES_CLIENT != &buf[0..crate::MAGIC_BYTES_CLIENT.len()] {
        eprintln!("{} error: bad client.", crate::binary_name());
        std::process::exit(1);
    }
    tcp_stream.write_all(crate::MAGIC_BYTES_SERVER)?;

    // Figure out which test are we doing.
    let mut cmd: u64 = 0;
    let buf: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(&mut cmd as *mut u64 as usize as *mut u8, 8) };
    tcp_stream.read_exact(buf)?;
    match cmd {
        crate::CMD_TCP_RR => {
            do_rr(tcp_stream)?;
        }
        crate::CMD_TCP_THROUGHPUT => {
            do_throughput(tcp_stream)?;
        }
        _ => {
            panic!("unrecognized command: {}", cmd);
        }
    }

    Ok(())
}

fn do_rr(mut stream: TcpStream) -> Result<()> {
    let mut buf: [u8; 64] = [0; 64];
    let start_time = Instant::now();
    let mut total_iterations = 0usize;

    loop {
        if let Err(err) = stream.read_exact(&mut buf) {
            if err.kind() == ErrorKind::UnexpectedEof {
                break;
            }
            eprintln!("read error: {:?}", err);
            std::process::exit(1);
        }
        if let Err(err) = stream.write_all(&buf) {
            eprintln!("write error: {:?}", err);
            std::process::exit(1);
        }
        total_iterations += 1;
    }

    let duration = start_time.elapsed();
    println!(
        "RR done: {} iterations over {:.2?};",
        total_iterations, duration
    );
    let iters_per_sec = (total_iterations as f64) / (duration.as_secs_f64());
    println!(
        "\t{} iterations/sec; {:.3} usec/iteration.\n",
        iters_per_sec as u64,
        1_000_000_f64 / iters_per_sec
    );

    Ok(())
}

fn do_throughput(mut stream: TcpStream) -> Result<()> {
    let mut buffer = [0; 1024];
    let start_time = Instant::now();
    let mut total_bytes_read = 0usize;

    loop {
        let bytes_read = stream.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        total_bytes_read += bytes_read;
    }

    let duration = start_time.elapsed();
    println!(
        "Throughput done: received {} bytes over {:.2?};",
        total_bytes_read, duration
    );
    println!(
        "\t{:.2?} bytes/sec.\n",
        total_bytes_read as f64 / duration.as_secs_f64()
    );

    Ok(())
}
