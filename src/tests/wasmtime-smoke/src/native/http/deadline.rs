//! Optional request deadlines must release slots held by nonresponding guests.
use super::*;

pub(super) fn run(suite: &mut Suite) -> Result<()> {
    for (program, options) in [
        ("p2_cli_serve_sleep", "-S cli"),
        ("p3_cli_serve_sleep", "-W component-model-async -S p3,cli"),
    ] {
        let command = format!(
            "MOTOR_OS_CAPS=0x100 {RUNTIME} serve --allow-precompiled {options} \
             --addr 127.0.0.1:0 --shutdown-addr 127.0.0.1:0 \
             --max-concurrent-requests 2 --max-concurrent-connections 8"
        );
        suite.refusal(
            &format!("{program}-missing-epochs"),
            &format!("{command} -W timeout=1s {FIXTURES}/{program}.cwasm"),
            "epoch interruption",
        )?;
        suite.refusal(
            &format!("{program}-unexpected-epochs"),
            &format!("{command} {FIXTURES}/{program}-epoch.cwasm"),
            "epoch interruption",
        )?;
        let mut job = suite.start(
            &format!("{program}-deadline"),
            &format!("{command} -W timeout=1s {FIXTURES}/{program}-epoch.cwasm"),
            false,
        )?;
        let log = job.wait_stderr("Serving HTTP on http://")?;
        let addr = address(&log, "Serving HTTP on http://")?;
        let shutdown = address(&log, "Listening for shutdown on tcp://")?;
        let pid = runtime_pid(&job)?;
        if let Err(error) = exercise(addr) {
            let logs = job
                .logs()
                .map(|(out, err)| format!("{out}\n{err}"))
                .unwrap_or_else(|error| format!("could not read server logs: {error}"));
            return Err(format!("{program}: {error}\n{logs}").into());
        }
        drop(connect(shutdown)?);
        suite.wait(&mut job, 0)?;
        if process_active(pid)? {
            return Err(format!("{program}: runtime survived deadline shutdown").into());
        }
    }
    Ok(())
}

fn exercise(addr: SocketAddr) -> Result<()> {
    // A third request queues behind the two admitted handlers. A second round
    // then proves the expired handlers no longer occupy the request slots.
    for _ in 0..2 {
        thread::scope(|scope| -> Result<()> {
            let clients: Vec<_> = (0..3)
                .map(|_| scope.spawn(|| expires(addr).map_err(|e| e.to_string())))
                .collect();
            for client in clients {
                client.join().map_err(|_| "deadline client panicked")??;
            }
            Ok(())
        })?;
    }
    // Abandon two complete requests before any response. Subsequent traffic
    // and server shutdown must remain bounded even if handlers were admitted.
    for _ in 0..2 {
        drop(send(addr)?);
    }
    expires(addr)
}

fn send(addr: SocketAddr) -> Result<TcpStream> {
    let mut socket = connect(addr)?;
    write!(
        socket,
        "GET / HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;
    Ok(socket)
}

fn expires(addr: SocketAddr) -> Result<()> {
    let started = Instant::now();
    let socket = send(addr)?;
    let mut response = Vec::new();
    socket.take(8193).read_to_end(&mut response)?;
    if response.len() > 8192 {
        return Err("oversized timeout response".into());
    }
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("missing timeout response headers")?;
    let headers = std::str::from_utf8(&response[..end])?.to_ascii_lowercase();
    if !headers.starts_with("http/1.1 500 ") {
        return Err(format!("expected timeout HTTP 500: {headers}").into());
    }
    let length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .ok_or("missing timeout response length")?
        .parse::<usize>()?;
    if length != response.len() - end - 4 {
        return Err("truncated timeout response".into());
    }
    // Immediate instantiation or guest errors must not masquerade as timeouts.
    if started.elapsed() < Duration::from_millis(900) {
        return Err("sleeping handler returned before its one-second deadline".into());
    }
    println!(
        "PASS request-deadline: status=500 elapsed_ms={}",
        started.elapsed().as_millis()
    );
    Ok(())
}
