//! Outgoing HTTP has its own WASI grant; OS network authority still bounds it.
use std::io::ErrorKind;
use std::net::TcpListener;

use super::super::invocation;
use super::*;

pub(super) fn run(suite: &mut Suite) -> Result<()> {
    for (program, p3) in [
        ("p2_http_outbound_request_get", ""),
        (
            "p3_http_outbound_request_get",
            "-W component-model-async -S p3",
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let environment = format!("{p3} --env HTTP_SERVER={addr}");
        for (label, http) in [("default", ""), ("disabled", "-S http=n")] {
            suite.refusal(
                &format!("{program}-http-{label}"),
                &invocation(
                    "0x100",
                    &format!("{environment} {http} -S inherit-network=y,tcp=y,udp=y,allow-ip-name-lookup=y"),
                    program,
                ),
                "a matching implementation was not found in the linker",
            )?;
            no_connection(&listener)?;
        }
        let options =
            format!("{environment} -S http,inherit-network=n,tcp=n,udp=n,allow-ip-name-lookup=n");
        // The upstream guest unwraps the connection failure and traps. The
        // default HTTP hook maps connect errors to ConnectionRefused.
        let (_, err) = suite.command(
            &format!("{program}-no-cap-net"),
            &invocation("0", &options, program),
            -1,
        )?;
        if !err
            .to_ascii_lowercase()
            .replace('-', "")
            .contains("connectionrefused")
        {
            return Err(format!("{program}: missing connection refusal: {err}").into());
        }
        no_connection(&listener)?;
        thread::scope(|scope| -> Result<()> {
            let server = scope.spawn(|| serve_once(&listener).map_err(|e| e.to_string()));
            let result = suite.command(
                &format!("{program}-http-without-sockets"),
                &invocation("0x100", &options, program),
                0,
            );
            server.join().map_err(|_| "HTTP grant server panicked")??;
            result?;
            Ok(())
        })?;
        no_connection(&listener)?;
    }
    // This published fixture checks access-denied for both p2 and p3 binds.
    suite.command(
        "http-keeps-socket-denial",
        &invocation(
            "0x100",
            "-W component-model-async -S p3,http,tcp,inherit-network=n",
            "p3_cli_deny_listen",
        ),
        0,
    )?;
    Ok(())
}

fn no_connection(listener: &TcpListener) -> Result<()> {
    match listener.accept() {
        Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("unexpected HTTP connection reached the listener".into()),
    }
}

fn serve_once(listener: &TcpListener) -> Result<()> {
    let started = Instant::now();
    let mut socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error)
                if error.kind() == ErrorKind::WouldBlock && started.elapsed() < IO_TIMEOUT =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error.into()),
        }
    };
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(IO_TIMEOUT))?;
    socket.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() == 8192 {
            return Err("oversized outgoing HTTP request headers".into());
        }
        let mut byte = [0];
        socket.read_exact(&mut byte)?;
        request.push(byte[0]);
    }
    if !request.starts_with(b"GET /get?some=arg&goes=here HTTP/1.1\r\n") {
        return Err(format!(
            "unexpected outgoing HTTP request: {:?}",
            String::from_utf8_lossy(&request)
        )
        .into());
    }
    socket.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\
          x-wasmtime-test-method: GET\r\nx-wasmtime-test-uri: /get?some=arg&goes=here\r\n\r\n",
    )?;
    Ok(())
}
