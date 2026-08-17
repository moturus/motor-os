use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, Stream};

use crate::{
    CurlError, CurlResult, HttpsUrl, Options, TransferInfo, client_config, receive_response,
    write_request,
};

/// Run one transfer. `body` must be resolved by the caller (`main` reads
/// stdin for `--data-binary @-`): the request carries a Content-Length, so
/// the bytes have to exist before the first one is sent.
pub fn transfer(
    options: &Options,
    body: Option<&[u8]>,
    output: &mut impl Write,
) -> CurlResult<TransferInfo> {
    crate::verbose(1, "initializing transfer deadlines and URL");
    let started = Instant::now();
    let total_deadline = Deadline::after(started, options.max_time)?;
    let connect_deadline = total_deadline.min(Deadline::after(started, options.connect_timeout)?);
    let url = HttpsUrl::parse(&options.url)?;
    crate::verbose(
        1,
        &format!("parsed HTTPS endpoint {}:{}", url.host(), url.port()),
    );
    let config = client_config(options.ca_cert.as_deref())?;
    crate::verbose(1, "loaded TLS roots");
    let server_name = ServerName::try_from(url.host().to_owned())
        .map_err(|_| CurlError::new(CurlError::MALFORMED_URL, "invalid TLS server name"))?;

    crate::verbose(1, "resolving and connecting TCP");
    let socket = connect(&url, connect_deadline)?;
    crate::verbose(
        2,
        &format!(
            "TCP connected {:?} -> {:?}; starting TLS handshake",
            socket.local_addr(),
            socket.peer_addr()
        ),
    );
    let mut socket = TimedStream::new(socket, connect_deadline, options.connect_timeout);
    let mut connection = ClientConnection::new(config, server_name).map_err(|error| {
        CurlError::new(
            CurlError::TLS_CONNECT,
            format!("failed creating TLS connection: {error}"),
        )
    })?;
    connection.complete_io(&mut socket).map_err(|error| {
        CurlError::from_io(error, CurlError::TLS_CONNECT, "TLS handshake failed")
    })?;
    crate::verbose(1, "TLS handshake completed");
    if connection
        .alpn_protocol()
        .is_some_and(|protocol| protocol != b"http/1.1")
    {
        return Err(CurlError::new(
            CurlError::TLS_CONNECT,
            "server selected an unsupported application protocol",
        ));
    }

    socket.set_limits(total_deadline, options.speed_time);
    let mut stream = Stream::new(&mut connection, &mut socket);
    crate::verbose(
        1,
        &format!(
            "writing HTTP request with {} body bytes",
            body.map_or(0, <[u8]>::len)
        ),
    );
    write_request(&mut stream, &url, options, body)?;
    stream.flush().map_err(|error| {
        CurlError::from_io(error, CurlError::SEND, "failed sending HTTP request")
    })?;
    crate::verbose(1, "HTTP request flushed; waiting for response");
    let mut progress = SpeedOutput::new(output, options.speed_limit, options.speed_time);
    let response = receive_response(&mut stream, &url, options.include, &mut progress)?;
    crate::verbose(
        1,
        &format!(
            "HTTP response completed: status {}, {} body bytes",
            response.status, response.body_size
        ),
    );
    progress.finish()?;
    Ok(TransferInfo {
        response_code: response.status,
        url_effective: url.as_str().to_owned(),
        redirect_url: response.redirect_url,
        size_download: response.body_size,
    })
}

fn connect(url: &HttpsUrl, deadline: Deadline) -> CurlResult<TcpStream> {
    let addresses = resolve(url.host().to_owned(), url.port(), deadline)?;
    crate::verbose(1, &format!("DNS returned {} address(es)", addresses.len()));
    crate::verbose(
        2,
        &format!(
            "resolved addresses: {}",
            addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
    let mut last_error = None;
    for (index, address) in addresses.into_iter().enumerate() {
        crate::verbose(
            2,
            &format!("trying resolved address {}: {address}", index + 1),
        );
        match TcpStream::connect_timeout(&address, deadline.remaining()?) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    let error = last_error
        .ok_or_else(|| CurlError::new(CurlError::RESOLVE, "name resolved to no addresses"))?;
    Err(CurlError::from_io(
        error,
        CurlError::CONNECT,
        "failed connecting to server",
    ))
}

fn resolve(host: String, port: u16, deadline: Deadline) -> CurlResult<Vec<SocketAddr>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("curl-dns".into())
        .spawn(move || {
            let result = (host.as_str(), port)
                .to_socket_addrs()
                .map(|addresses| addresses.collect());
            let _ = sender.send(result);
        })
        .map_err(|error| {
            CurlError::new(
                CurlError::RESOLVE,
                format!("failed starting name resolution: {error}"),
            )
        })?;
    match receiver.recv_timeout(deadline.remaining()?) {
        Ok(Ok(addresses)) => Ok(addresses),
        Ok(Err(error)) => Err(CurlError::new(
            CurlError::RESOLVE,
            format!("failed resolving host: {error}"),
        )),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(CurlError::new(
            CurlError::TIMEOUT,
            "name resolution timed out",
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(CurlError::new(CurlError::RESOLVE, "name resolution failed"))
        }
    }
}

#[derive(Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn after(start: Instant, duration: Duration) -> CurlResult<Self> {
        start
            .checked_add(duration)
            .map(Self)
            .ok_or_else(|| CurlError::usage("timeout value is too large"))
    }

    fn min(self, other: Self) -> Self {
        Self(self.0.min(other.0))
    }

    fn remaining(self) -> CurlResult<Duration> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| CurlError::new(CurlError::TIMEOUT, "operation timed out"))
    }
}

struct TimedStream {
    socket: TcpStream,
    deadline: Deadline,
    stall: Duration,
}

impl TimedStream {
    fn new(socket: TcpStream, deadline: Deadline, stall: Duration) -> Self {
        Self {
            socket,
            deadline,
            stall,
        }
    }

    fn set_limits(&mut self, deadline: Deadline, stall: Duration) {
        self.deadline = deadline;
        self.stall = stall;
    }

    fn timeout(&self) -> io::Result<Duration> {
        self.deadline
            .remaining()
            .map(|remaining| remaining.min(self.stall))
            .map_err(|error| io::Error::new(io::ErrorKind::TimedOut, error))
    }
}

impl Read for TimedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.timeout()?))?;
        crate::verbose(
            3,
            &format!("socket read waiting (capacity {})", buffer.len()),
        );
        let result = self.socket.read(buffer);
        match &result {
            Ok(count) => crate::verbose(3, &format!("socket read returned {count} bytes")),
            Err(error) => crate::verbose(3, &format!("socket read failed: {error}")),
        }
        result
    }
}

impl Write for TimedStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.timeout()?))?;
        crate::verbose(
            3,
            &format!("socket write starting ({} bytes)", buffer.len()),
        );
        let result = self.socket.write(buffer);
        match &result {
            Ok(count) => crate::verbose(3, &format!("socket write accepted {count} bytes")),
            Err(error) => crate::verbose(3, &format!("socket write failed: {error}")),
        }
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.set_write_timeout(Some(self.timeout()?))?;
        crate::verbose(3, "socket flush starting");
        let result = self.socket.flush();
        match &result {
            Ok(()) => crate::verbose(3, "socket flush completed"),
            Err(error) => crate::verbose(3, &format!("socket flush failed: {error}")),
        }
        result
    }
}

struct SpeedOutput<'a, W> {
    output: &'a mut W,
    limit: u64,
    interval: Duration,
    started: Instant,
    bytes: u64,
}

impl<'a, W: Write> SpeedOutput<'a, W> {
    fn new(output: &'a mut W, limit: u64, interval: Duration) -> Self {
        Self {
            output,
            limit,
            interval,
            started: Instant::now(),
            bytes: 0,
        }
    }

    fn finish(&mut self) -> CurlResult<()> {
        self.check().map_err(|error| {
            CurlError::from_io(error, CurlError::LOCAL_WRITE, "download speed check failed")
        })
    }

    fn check(&mut self) -> io::Result<()> {
        let elapsed = self.started.elapsed();
        if elapsed >= self.interval {
            if u128::from(self.bytes) * 1_000_000_000 < u128::from(self.limit) * elapsed.as_nanos()
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "download stayed below the low-speed limit",
                ));
            }
            self.started = Instant::now();
            self.bytes = 0;
        }
        Ok(())
    }
}

impl<W: Write> Write for SpeedOutput<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.check()?;
        let count = self.output.write(buffer)?;
        self.bytes = self.bytes.saturating_add(count as u64);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_deadline_is_a_timeout() {
        let deadline = Deadline(Instant::now());
        let error = deadline.remaining().unwrap_err();
        assert_eq!(error.code(), CurlError::TIMEOUT);
    }

    #[test]
    fn low_speed_output_detects_an_expired_empty_window() {
        let mut output = Vec::new();
        let mut progress = SpeedOutput::new(&mut output, 1, Duration::from_nanos(1));
        std::thread::yield_now();
        let error = progress.write_all(b"x").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(output.is_empty());
    }
}
