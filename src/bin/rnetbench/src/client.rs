use std::io::Error;
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
    let mut last_error = None;

    for addr in addrs {
        let result = (|| {
            // Flow completion replaces the standard phases rather than joining
            // them: it opens hundreds of connections, which would change what
            // the duration-based phases after it were measuring.
            if args.flow_bytes.is_some() {
                return try_addr(addr, crate::CMD_TCP_FLOW, args);
            }
            try_addr(addr, crate::CMD_TCP_RR, args)?;
            std::thread::sleep(Duration::from_millis(100));
            try_addr(addr, crate::CMD_TCP_THROUGHPUT_OUT, args)?;
            std::thread::sleep(Duration::from_millis(100));
            try_addr(addr, crate::CMD_TCP_THROUGHPUT_IN, args)
        })();
        match result {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_error = Some(err);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| ErrorKind::HostUnreachable.into()))
}

fn handshake(addr: SocketAddr, cmd: u64, buf_size: u32) -> Result<TcpStream> {
    handshake_with_timeout(addr, cmd, buf_size, crate::HANDSHAKE_TIMEOUT)
}

pub(crate) fn handshake_with_timeout(
    addr: SocketAddr,
    cmd: u64,
    buf_size: u32,
    timeout: Duration,
) -> Result<TcpStream> {
    let deadline = std::time::Instant::now() + timeout;
    let mut buf: [u8; 1500] = [0; 1500];
    let mut tcp_stream = crate::handshake_io(TcpStream::connect_timeout(&addr, timeout), deadline)?;
    tcp_stream.set_nodelay(true)?;
    let io_deadline = crate::IoDeadline::new(&tcp_stream, deadline)?;

    crate::handshake_io(tcp_stream.write_all(crate::MAGIC_BYTES_CLIENT), deadline)?;
    crate::handshake_io(
        tcp_stream.read_exact(&mut buf[0..crate::MAGIC_BYTES_SERVER.len()]),
        deadline,
    )?;

    if crate::MAGIC_BYTES_SERVER != &buf[0..crate::MAGIC_BYTES_SERVER.len()] {
        return Err(Error::new(ErrorKind::InvalidData, "bad remote reply"));
    }

    let buf: &[u8] =
        unsafe { core::slice::from_raw_parts(&cmd as *const u64 as usize as *const u8, 8) };
    crate::handshake_io(tcp_stream.write_all(buf), deadline)?;

    let buf_size = buf_size as u64;
    let buf: &[u8] =
        unsafe { core::slice::from_raw_parts(&buf_size as *const u64 as usize as *const u8, 8) };
    crate::handshake_io(tcp_stream.write_all(buf), deadline)?;

    drop(io_deadline);
    Ok(tcp_stream)
}

fn try_addr(addr: SocketAddr, cmd: u64, args: &crate::Args) -> Result<()> {
    let stats = crate::stats::PhaseSnapshot::take();
    match cmd {
        crate::CMD_TCP_RR => {
            do_rr(
                handshake(addr, cmd, args.buf_size)?,
                Duration::from_secs(args.time as u64),
            )?;
            stats.report("TCP RR");
        }
        crate::CMD_TCP_THROUGHPUT_IN => {
            do_throughput_cmd(cmd, addr, args)?;
            stats.report("server => client (local RX)");
        }
        crate::CMD_TCP_THROUGHPUT_OUT => {
            do_throughput_cmd(cmd, addr, args)?;
            stats.report("client => server (local TX)");
        }
        crate::CMD_TCP_FLOW => {
            do_flow_cmd(addr, args)?;
            stats.report("flow completion, server => client");
        }
        _ => {
            panic!("unrecognized command: {cmd}");
        }
    }

    Ok(())
}

struct ThroughputResult {
    duration: std::time::Duration,
    bytes: usize,
}

impl ThroughputResult {
    fn new() -> Self {
        ThroughputResult {
            duration: Duration::new(0, 0),
            bytes: 0,
        }
    }
}

fn do_throughput_cmd(cmd: u64, addr: SocketAddr, args: &crate::Args) -> Result<()> {
    use std::sync::Arc;
    use std::sync::Mutex;

    let num_threads = args.parallel;
    let duration = std::time::Duration::from_secs(args.time as u64);

    let thread_func = move |arg: Arc<Mutex<ThroughputResult>>, args: crate::Args| -> Result<()> {
        let buf_size = args.buf_size as usize;
        let (duration, bytes) = match cmd {
            crate::CMD_TCP_THROUGHPUT_IN => crate::do_throughput_read(
                handshake(addr, cmd, args.buf_size)?,
                buf_size,
                Some(duration),
            ),
            crate::CMD_TCP_THROUGHPUT_OUT => crate::do_throughput_write(
                handshake(addr, cmd, args.buf_size)?,
                buf_size,
                Some(duration),
            ),
            _ => panic!(),
        };
        let mut res = arg.lock().unwrap();
        res.duration = duration;
        res.bytes = bytes;
        Ok(())
    };

    let mut results: Vec<Arc<Mutex<ThroughputResult>>> = Vec::new();
    let mut threads = Vec::new();

    for _ in 0..num_threads {
        let result = Arc::new(Mutex::new(ThroughputResult::new()));
        let cloned_args = args.clone();
        results.push(result.clone());
        threads.push(std::thread::spawn(move || thread_func(result, cloned_args)));
    }

    let mut thread_error = None;
    for thread in threads {
        match thread.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                thread_error.get_or_insert(err);
            }
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
    if let Some(err) = thread_error {
        return Err(err);
    }

    let mut total_duration = Duration::new(0, 0);
    let mut total_bytes = 0;

    for r in &results {
        let res = r.lock().unwrap();
        assert!(res.duration >= duration);
        if res.duration.as_secs_f64() >= duration.as_secs_f64() * 1.1 {
            eprintln!(
                "Bad runtime: {:.3} vs {:.3}. TCP queueing issues?",
                res.duration.as_secs_f64(),
                duration.as_secs_f64()
            );
        }

        total_duration += res.duration;
        total_bytes += res.bytes;
    }

    let rate = total_bytes as f64
        / (total_duration.as_secs_f64() / (num_threads as f64))
        / (1024.0 * 1024.0);
    let op = match cmd {
        crate::CMD_TCP_THROUGHPUT_IN => "Throughput server => client",
        crate::CMD_TCP_THROUGHPUT_OUT => "Throughput client => server",
        _ => panic!(),
    };

    println!(
        "{op} done: {:.2}MB sent; {:.2?} MiB/sec.",
        (total_bytes as f64) / (1024.0 * 1024.0),
        rate
    );

    if num_threads > 1 {
        for idx in 0..num_threads {
            let res = results[idx as usize].lock().unwrap();
            let rate = res.bytes as f64 / res.duration.as_secs_f64() / (1024.0 * 1024.0);
            println!(
                "    T{}: {:.2}MB sent; {:.2?} MiB/sec.",
                idx,
                (res.bytes as f64) / (1024.0 * 1024.0),
                rate
            );
        }
    }
    Ok(())
}

fn percentile(sorted: &[Duration], p: f64) -> f64 {
    // Nearest-rank on an already-sorted slice; the caller guarantees non-empty.
    let rank = ((p / 100.0) * (sorted.len() as f64)).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1].as_secs_f64() * 1_000_000.0
}

fn do_flow_cmd(addr: SocketAddr, args: &crate::Args) -> Result<()> {
    let flow_bytes = args.flow_bytes.expect("flow mode without a byte count") as usize;
    let buf_size = args.buf_size as usize;
    let mut samples: Vec<Duration> = Vec::with_capacity(args.flow_count as usize);

    println!(
        "{}: starting TCP flow-completion test ({} flows of {} bytes)...",
        crate::binary_name(),
        args.flow_count,
        flow_bytes
    );

    for _ in 0..args.flow_count {
        let mut stream = handshake(addr, crate::CMD_TCP_FLOW, args.buf_size)?;

        // The byte count rides after the two standard handshake fields, so the
        // phases that predate this one parse exactly as they did.
        let flow_bytes_u64 = flow_bytes as u64;
        let buf: &[u8] = unsafe {
            core::slice::from_raw_parts(&flow_bytes_u64 as *const u64 as usize as *const u8, 8)
        };
        stream.write_all(buf)?;

        // Timed from here rather than from `connect`: the three-way handshake
        // and the exchange above cost the same in every arm, and folding them
        // in only dilutes what this is for.
        let start = std::time::Instant::now();
        crate::read_exact_pattern(&mut stream, buf_size, flow_bytes)?;
        samples.push(start.elapsed());

        // Close from this side, so the TIME-WAIT accumulates on the client
        // rather than on the system under test -- hundreds of them there would
        // be a property of the benchmark and not of what it is measuring. The
        // server holds the connection open until it sees this FIN.
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut sink = [0u8; 64];
        while stream.read(&mut sink)? > 0 {}
    }

    samples.sort_unstable();
    println!(
        "\tFlow completion done: {} flows of {} bytes; p50 {:.3} usec; \
         p90 {:.3}; p99 {:.3}; min {:.3}; max {:.3}.",
        samples.len(),
        flow_bytes,
        percentile(&samples, 50.0),
        percentile(&samples, 90.0),
        percentile(&samples, 99.0),
        percentile(&samples, 0.0),
        percentile(&samples, 100.0),
    );
    println!(
        "\t(transfer only: connect and handshake are excluded, and the timer \
         stops on the last byte.)"
    );

    Ok(())
}

pub(crate) fn do_rr(mut stream: TcpStream, duration: Duration) -> Result<()> {
    let mut buf: [u8; 1500] = [0; 1500];
    println!(
        "{}: starting TCP round-robin test (64 byte buffers)...",
        crate::binary_name()
    );
    let mut rr_iters = 0_u64;
    let start = std::time::Instant::now();
    let deadline = crate::IoDeadline::new(&stream, start + duration)?;
    while start.elapsed() < duration {
        if let Err(err) = stream.write_all(&buf[0..64]) {
            if start.elapsed() < duration {
                return Err(err);
            }
            break;
        }
        if let Err(err) = stream.read_exact(&mut buf[0..64]) {
            if start.elapsed() < duration {
                return Err(err);
            }
            break;
        }
        rr_iters += 1;
    }
    drop(deadline);
    let stop = std::time::Instant::now();

    let _ = stream.shutdown(std::net::Shutdown::Both);
    core::mem::drop(stream);

    let iters_per_sec = (rr_iters as f64) / ((stop - start).as_secs_f64());
    println!(
        "\tRR done: {} iterations/sec; {:.3} usec/iteration.",
        iters_per_sec as u64,
        1_000_000_f64 / iters_per_sec
    );

    Ok(())
}
