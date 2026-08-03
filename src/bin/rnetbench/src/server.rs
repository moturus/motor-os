use std::io::Read;
use std::io::Result;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::TcpStream;
use std::time::Duration;

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

fn handle_connection(tcp_stream: TcpStream) -> Result<()> {
    handle_connection_with_timeout(tcp_stream, crate::HANDSHAKE_TIMEOUT)
}

pub(crate) fn handle_connection_with_timeout(
    mut tcp_stream: TcpStream,
    timeout: Duration,
) -> Result<()> {
    tcp_stream.set_nodelay(true)?;
    let deadline = std::time::Instant::now() + timeout;
    let io_deadline = crate::IoDeadline::new(&tcp_stream, deadline)?;
    let mut buf: [u8; 1500] = [0; 1500];

    // "Authenticate" the client.
    crate::handshake_io(
        tcp_stream.read_exact(&mut buf[0..crate::MAGIC_BYTES_CLIENT.len()]),
        deadline,
    )?;

    if crate::MAGIC_BYTES_CLIENT != &buf[0..crate::MAGIC_BYTES_CLIENT.len()] {
        return Ok(()); // Doesn't matter if we return Ok or Err.
    }
    crate::handshake_io(tcp_stream.write_all(crate::MAGIC_BYTES_SERVER), deadline)?;

    // Figure out which test we are doing, and the client's buffer size.
    let mut cmd: u64 = 0;
    let buf: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(&mut cmd as *mut u64 as usize as *mut u8, 8) };
    crate::handshake_io(tcp_stream.read_exact(buf), deadline)?;

    let mut buf_size: u64 = 0;
    let buf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(&mut buf_size as *mut u64 as usize as *mut u8, 8)
    };
    crate::handshake_io(tcp_stream.read_exact(buf), deadline)?;
    if buf_size < (crate::MIN_BUF_SIZE as u64) || buf_size > (crate::MAX_BUF_SIZE as u64) {
        eprintln!("bad buf_size: {buf_size}");
        return Ok(());
    }
    let buf_size = buf_size as usize;

    // Only the flow-completion command carries a byte count, and it rides after
    // the two standard fields, so every phase that predates it parses unchanged.
    let mut flow_bytes: u64 = 0;
    if cmd == crate::CMD_TCP_FLOW {
        let buf: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(&mut flow_bytes as *mut u64 as usize as *mut u8, 8)
        };
        crate::handshake_io(tcp_stream.read_exact(buf), deadline)?;
        if flow_bytes < (crate::MIN_FLOW_BYTES as u64)
            || flow_bytes > (crate::MAX_FLOW_BYTES as u64)
        {
            eprintln!("bad flow_bytes: {flow_bytes}");
            return Ok(());
        }
    }
    drop(io_deadline);

    match cmd {
        crate::CMD_TCP_RR => {
            // The RR phase normally ends with the client closing the
            // connection, i.e. with an Err: report stats before returning it.
            let stats = crate::stats::PhaseSnapshot::take();
            let result = do_rr(tcp_stream);
            stats.report("TCP RR");
            result?;
        }
        crate::CMD_TCP_THROUGHPUT_OUT => {
            let stats = crate::stats::PhaseSnapshot::take();
            crate::do_throughput_read(tcp_stream, buf_size, None);
            stats.report("client => server (local RX)");
        }
        crate::CMD_TCP_FLOW => {
            // No per-phase stats report here: a flow-completion run is hundreds
            // of connections and one report each would bury the output.
            crate::write_exact_pattern(&mut tcp_stream, buf_size, flow_bytes as usize)?;
            // Hold the connection open until the client's FIN, so the TIME-WAIT
            // stays on the client. Closing first would leave one here per flow.
            let mut sink = [0u8; 64];
            while tcp_stream.read(&mut sink)? > 0 {}
        }
        crate::CMD_TCP_THROUGHPUT_IN => {
            let stats = crate::stats::PhaseSnapshot::take();
            crate::do_throughput_write(tcp_stream, buf_size, None);
            stats.report("server => client (local TX)");
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
