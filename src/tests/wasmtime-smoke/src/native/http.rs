//! Offline HTTP checks against installed `serve`, using published handlers.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use wasm_smoke_suite::{Job, Result, Suite, process_active, used_memory};

use super::{FIXTURES, RUNTIME, runtime_pid};

mod lifecycle;

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const RESPONSE_LIMIT: u64 = 1024 * 1024;
const CONCURRENCY: usize = 4;

pub(super) fn run(suite: &mut Suite) -> Result<()> {
    suite.refusal(
        "p3-default-disabled",
        &format!(
            "MOTOR_OS_CAPS=0x100 {RUNTIME} serve --allow-precompiled \
             -W component-model-async -S cli --addr 127.0.0.1:0 \
             {FIXTURES}/p3_cli_serve_hello_world.cwasm"
        ),
        "a matching implementation was not found in the linker",
    )?;
    for (program, p3, echo) in [
        ("p2_cli_serve_hello_world", false, false),
        ("p2_api_proxy_streaming", false, true),
        ("p3_cli_serve_hello_world", true, false),
        ("p3_http_echo", true, true),
    ] {
        let options = if p3 {
            "-W component-model-async -S p3,cli"
        } else {
            "-S cli"
        };
        // Echo runs without a terminal, so its shutdown cannot depend on Ctrl-C.
        let mut job = suite.start(
            program,
            &format!(
                "MOTOR_OS_CAPS=0x100 {RUNTIME} serve --allow-precompiled {options} \
                 --addr 127.0.0.1:0 --shutdown-addr 127.0.0.1:0 \
                 --max-concurrent-requests {CONCURRENCY} --max-concurrent-connections 8 \
                 {FIXTURES}/{program}.cwasm"
            ),
            !echo,
        )?;
        let log = job.wait_stderr("Serving HTTP on http://")?;
        let addr = address(&log, "Serving HTTP on http://")?;
        let shutdown = address(&log, "Listening for shutdown on tcp://")?;
        let pid = runtime_pid(&job)?;
        let body: Vec<_> = if echo {
            (0..256 * 1024).map(|i| (i % 251) as u8).collect()
        } else {
            Vec::new()
        };
        let expected = if echo {
            body.as_slice()
        } else {
            b"Hello, WASI!"
        };
        let mut peak = used_memory()?;
        let mut last = Instant::now();
        let mut gap = Duration::ZERO;
        // Hello crosses p3's default 128-request instance turnover; echoes
        // exceed socket buffers and require simultaneous reading and writing.
        let rounds = if echo { 4 } else { 36 };
        for round in 0..rounds {
            thread::scope(|scope| -> Result<()> {
                let jobs: Vec<_> = (0..CONCURRENCY)
                    .map(|client| {
                        let body = &body;
                        scope.spawn(move || {
                            request(addr, body, expected, (round + client) % 2 == 0).map_err(|e| {
                                format!("{program} round={round} client={client}: {e}")
                            })
                        })
                    })
                    .collect();
                while jobs.iter().any(|job| !job.is_finished()) {
                    peak = peak.max(used_memory()?);
                    let now = Instant::now();
                    gap = gap.max(now - last);
                    last = now;
                    thread::sleep(Duration::from_millis(10));
                }
                for job in jobs {
                    job.join().map_err(|_| "HTTP client panicked")??;
                }
                Ok(())
            })?;
        }
        if echo {
            if let Err(error) = lifecycle::run(addr, &body) {
                let logs = job
                    .logs()
                    .map(|(out, err)| format!("{out}\n{err}"))
                    .unwrap_or_else(|error| format!("could not read server logs: {error}"));
                return Err(format!("{program}: {error}\n{logs}").into());
            }
            drain_request(addr, Some(shutdown), &body, &mut job)?;
        } else {
            job.ctrl_c()?;
        }
        suite.wait(&mut job, 0)?;
        if process_active(pid)? {
            return Err(format!("{program}: runtime survived shutdown").into());
        }
        println!(
            "PASS {program}: requests={} concurrency={CONCURRENCY} \
             sampled_vm_peak_bytes={peak} max_gap_us={}",
            rounds * CONCURRENCY,
            gap.as_micros()
        );
    }
    // The foreground path must also drain a live response on its first Ctrl-C.
    for (program, options) in [
        ("p2_api_proxy_streaming", "-S cli"),
        ("p3_http_echo", "-W component-model-async -S p3,cli"),
    ] {
        let mut job = suite.start(
            &format!("{program}-active-ctrl-c"),
            &format!(
                "MOTOR_OS_CAPS=0x100 {RUNTIME} serve --allow-precompiled {options} \
                 --addr 127.0.0.1:0 --max-concurrent-requests {CONCURRENCY} \
                 {FIXTURES}/{program}.cwasm"
            ),
            true,
        )?;
        let log = job.wait_stderr("Serving HTTP on http://")?;
        let addr = address(&log, "Serving HTTP on http://")?;
        let pid = runtime_pid(&job)?;
        drain_request(addr, None, &vec![0x63; 256 * 1024], &mut job)?;
        suite.wait(&mut job, 0)?;
        if process_active(pid)? {
            return Err(format!("{program}: runtime survived active Ctrl-C").into());
        }
    }
    Ok(())
}

fn address(log: &str, prefix: &str) -> Result<SocketAddr> {
    let address = log
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .ok_or_else(|| format!("missing {prefix:?}: {log}"))?;
    Ok(address.trim_end_matches('/').parse()?)
}

fn request(addr: SocketAddr, body: &[u8], expected: &[u8], fragmented: bool) -> Result<()> {
    let socket = connect(addr)?;
    let mut writer = socket.try_clone()?;
    let headers = format!(
        "POST /echo HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    thread::scope(|scope| -> Result<()> {
        let sending = scope.spawn(|| -> std::io::Result<()> {
            if fragmented {
                for chunk in headers.as_bytes().chunks(7) {
                    writer.write_all(chunk)?;
                    thread::sleep(Duration::from_millis(1));
                }
            } else {
                writer.write_all(headers.as_bytes())?;
            }
            writer.write_all(body)
        });
        let mut response = Vec::new();
        socket.take(RESPONSE_LIMIT + 1).read_to_end(&mut response)?;
        sending.join().map_err(|_| "HTTP writer panicked")??;
        if response.len() as u64 > RESPONSE_LIMIT {
            return Err("HTTP response exceeded 1 MiB".into());
        }
        check_response(&response, expected)
    })
}

fn connect(addr: SocketAddr) -> Result<TcpStream> {
    let socket = TcpStream::connect_timeout(&addr, IO_TIMEOUT)?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.set_write_timeout(Some(IO_TIMEOUT))?;
    socket.set_nodelay(true)?;
    Ok(socket)
}

/// Keep a response in flight across shutdown, then finish its body. Receiving
/// its headers proves the handler has started before asking the server to drain.
fn drain_request(
    addr: SocketAddr,
    shutdown: Option<SocketAddr>,
    body: &[u8],
    job: &mut Job,
) -> Result<()> {
    let (socket, mut response) = begin_echo(addr, body.len(), &body[..1024])?;
    if let Some(shutdown) = shutdown {
        // A zero-transmit control connection may reset on Motor; accept is the
        // shutdown protocol. No response is required from the control listener.
        drop(connect(shutdown)?);
    } else {
        job.ctrl_c()?;
    }
    job.wait_stderr("Waiting for child tasks to exit")?;
    let mut writer = socket.try_clone()?;
    thread::scope(|scope| -> Result<()> {
        let sending = scope.spawn(|| writer.write_all(&body[1024..]));
        socket.take(RESPONSE_LIMIT + 1).read_to_end(&mut response)?;
        sending.join().map_err(|_| "shutdown writer panicked")??;
        if response.len() as u64 > RESPONSE_LIMIT {
            return Err("oversized HTTP response during shutdown".into());
        }
        check_response(&response, body)
    })
}

fn begin_echo(addr: SocketAddr, length: usize, prefix: &[u8]) -> Result<(TcpStream, Vec<u8>)> {
    let mut socket = connect(addr)?;
    write!(
        socket,
        "POST /echo HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {length}\r\n\r\n"
    )?;
    socket.write_all(prefix)?;
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() == 8192 {
            return Err("oversized HTTP headers".into());
        }
        let mut byte = [0];
        socket.read_exact(&mut byte)?;
        response.push(byte[0]);
    }
    Ok((socket, response))
}

// Only the HTTP/1.1 framing emitted by these fixtures is needed. Check framing
// as well as bytes, so a truncated response cannot count as a successful echo.
fn check_response(response: &[u8], expected: &[u8]) -> Result<()> {
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("missing HTTP headers")?;
    let headers = std::str::from_utf8(&response[..end])?.to_ascii_lowercase();
    if !headers.starts_with("http/1.1 200 ") {
        return Err(format!("unexpected HTTP status: {headers}").into());
    }
    let mut body = &response[end + 4..];
    if headers
        .lines()
        .any(|line| line == "transfer-encoding: chunked")
    {
        let mut offset = 0;
        loop {
            let end = body
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or("missing chunk length")?;
            let size = usize::from_str_radix(std::str::from_utf8(&body[..end])?, 16)?;
            body = &body[end + 2..];
            if size == 0 {
                if offset != expected.len() || body != b"\r\n" {
                    return Err("incomplete chunked response".into());
                }
                return Ok(());
            }
            let chunk = body.get(..size).ok_or("truncated HTTP chunk")?;
            let limit = offset.checked_add(size).ok_or("HTTP chunk overflow")?;
            if expected.get(offset..limit) != Some(chunk) {
                return Err("HTTP chunk bytes differ".into());
            }
            body = &body[size..];
            body = body
                .strip_prefix(b"\r\n")
                .ok_or("missing chunk terminator")?;
            offset = limit;
        }
    }
    let length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .ok_or("missing response length")?
        .parse::<usize>()?;
    if length != expected.len() || body != expected {
        return Err("HTTP response bytes differ".into());
    }
    Ok(())
}
