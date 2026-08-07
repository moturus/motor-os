// Pure rust network performance benchmark.

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use clap::Parser;

mod client;
mod server;
mod stats;

#[derive(Parser, Debug, Clone)]
struct Args {
    #[arg(short, long, default_value_t = false)]
    server: bool,

    #[arg(short, long, default_value_t = 40000, requires = "server")]
    port: u16,

    #[arg(short, long, conflicts_with = "server")]
    client: Option<String>, // The host to connect to.

    #[arg(
        short,
        long,
        default_value_t = 5,
        conflicts_with = "server",
        requires = "client"
    )]
    time: u32, // The number of seconds to run a single test.

    #[arg(
        short = 'P',
        long,
        default_value_t = 1,
        conflicts_with = "server",
        requires = "client"
    )]
    parallel: u16, // The number of parallel streams/threads to run.

    // The app buffer size for the throughput tests, on both sides (it is
    // sent to the server during the handshake). The default (1KB, with
    // random write sizes 0..1024) deliberately stresses per-write costs;
    // large buffers (e.g. 65536) measure the pipe instead.
    #[arg(
        short = 'b',
        long,
        default_value_t = 1024,
        conflicts_with = "server",
        requires = "client"
    )]
    buf_size: u32,

    // Flow-completion mode. When set, the three standard phases are replaced
    // by repeated *fresh* connections each carrying exactly this many bytes
    // from the server. A congestion window is per-socket state, so the
    // duration-based phases above cannot see what a connection's opening round
    // trips cost: they pay that once and then amortise it over seconds. Only
    // the server-to-client direction is measured, because that is the one the
    // server's congestion control governs.
    #[arg(long, conflicts_with = "server", requires = "client")]
    flow_bytes: Option<u32>,

    // How many fresh connections a flow-completion run makes. A fixed count
    // rather than a duration, so that paired A/B arms do the same work.
    #[arg(
        long,
        default_value_t = 200,
        conflicts_with = "server",
        requires = "client"
    )]
    flow_count: u32,
}

const MIN_BUF_SIZE: u32 = 64;
const MAX_BUF_SIZE: u32 = 1024 * 1024;
const MIN_FLOW_BYTES: u32 = 1024;
const MAX_FLOW_BYTES: u32 = 16 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

static MAGIC_BYTES_CLIENT: &[u8] = b"rnetbench_magic_client";
static MAGIC_BYTES_SERVER: &[u8] = b"rnetbench_magic_server";
const CMD_TCP_RR: u64 = 1;
const CMD_TCP_THROUGHPUT_OUT: u64 = 2;
const CMD_TCP_THROUGHPUT_IN: u64 = 3;
const CMD_TCP_FLOW: u64 = 4;

fn handshake_io<T>(result: std::io::Result<T>, deadline: Instant) -> std::io::Result<T> {
    result.map_err(|err| {
        if Instant::now() >= deadline {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "rnetbench handshake timed out",
            )
        } else {
            err
        }
    })
}

fn binary_name() -> String {
    std::path::Path::new(std::env::args().next().unwrap().as_str())
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

// Intercept Ctrl+C ourselves if the OS does not do it for us.
#[cfg(target_os = "motor")]
fn input_listener(prog: String) {
    loop {
        let mut input = [0_u8; 16];
        let sz = std::io::stdin().read(&mut input).unwrap();
        if sz == 0 {
            // EOF: stdin is gone; no ^C can ever arrive.
            return;
        }
        for b in &input[0..sz] {
            if *b == 3 {
                println!("\n{prog}: caught ^C: exiting.");
                std::process::exit(0);
            }
        }
    }
}

fn main() {
    #[cfg(target_os = "motor")]
    std::thread::spawn(move || input_listener(binary_name()));

    let args = Args::parse();

    if args.buf_size < MIN_BUF_SIZE || args.buf_size > MAX_BUF_SIZE {
        eprintln!("error: --buf-size must be in [{MIN_BUF_SIZE}, {MAX_BUF_SIZE}]");
        std::process::exit(1);
    }

    if let Some(flow_bytes) = args.flow_bytes {
        if !(MIN_FLOW_BYTES..=MAX_FLOW_BYTES).contains(&flow_bytes) {
            eprintln!("error: --flow-bytes must be in [{MIN_FLOW_BYTES}, {MAX_FLOW_BYTES}]");
            std::process::exit(1);
        }
    }
    if args.flow_bytes.is_some() && args.flow_count == 0 {
        eprintln!("error: --flow-count must be at least 1");
        std::process::exit(1);
    }

    if args.server {
        server::run(args.port);
    } else if args.client.is_some() {
        client::run(&args);
    } else {
        eprintln!("error: either --server or --client argument is required");
    }
}

// The data stream is the repeating 0,1,..,255 pattern: the byte at stream
// offset i is (i & 0xff). The table holds the pattern with 256 bytes of
// lead-in, so that any chunk of up to buf_size bytes starting at any
// offset & 0xff is a subslice: chunks are filled and verified with one
// memcpy/memcmp instead of a per-byte loop (the per-byte version cost ~a
// CPU core at 570 MB/s, masking the OS numbers).
fn make_pattern(buf_size: usize) -> Vec<u8> {
    (0..(256 + buf_size)).map(|j| (j & 0xff) as u8).collect()
}

struct IoDeadline {
    cancel: Option<mpsc::Sender<()>>,
    watchdog: Option<std::thread::JoinHandle<()>>,
}

impl IoDeadline {
    fn new(stream: &TcpStream, deadline: Instant) -> std::io::Result<Self> {
        let stream = stream.try_clone()?;
        let (cancel, receiver) = mpsc::channel();
        let watchdog = std::thread::spawn(move || {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if matches!(
                receiver.recv_timeout(remaining),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        });

        Ok(IoDeadline {
            cancel: Some(cancel),
            watchdog: Some(watchdog),
        })
    }
}

impl Drop for IoDeadline {
    fn drop(&mut self) {
        let _ = self.cancel.take().unwrap().send(());
        self.watchdog.take().unwrap().join().unwrap();
    }
}

fn do_throughput_read(
    mut stream: TcpStream,
    buf_size: usize,
    duration: Option<Duration>,
) -> (Duration, usize) {
    let pattern = make_pattern(buf_size);
    let mut buffer = vec![0u8; buf_size];
    let mut total_bytes_read = 0usize;

    // println!("throughput read starting");
    let mut counter: usize = 0;
    let start = Instant::now();
    let deadline = duration.map(|duration| {
        IoDeadline::new(&stream, start + duration).expect("failed to clone benchmark socket")
    });
    loop {
        if let Some(duration) = duration {
            if start.elapsed() >= duration {
                break;
            }
        }
        let Ok(bytes_read) = stream.read(&mut buffer) else {
            break;
        };
        if bytes_read == 0 {
            break;
        }
        let expected = &pattern[(counter & 0xff)..][..bytes_read];
        if &buffer[0..bytes_read] != expected {
            for (k, b) in buffer[0..bytes_read].iter().enumerate() {
                if expected[k] != *b {
                    panic!("bad data: counter: {} data: {}", counter + k, *b);
                }
            }
        }
        counter += bytes_read;
        total_bytes_read += bytes_read;
        assert_eq!(total_bytes_read, counter);
    }

    drop(deadline);
    let _ = stream.flush();
    let duration = start.elapsed();
    let _ = stream.shutdown(std::net::Shutdown::Both);

    // println!("throughput read done");
    (duration, total_bytes_read)
}

fn rdrand() -> u64 {
    let mut val = 0_u64;
    unsafe {
        let result = core::arch::x86_64::_rdrand64_step(&mut val);
        assert_eq!(1, result);
        val
    }
}

fn do_throughput_write(
    mut stream: TcpStream,
    buf_size: usize,
    duration: Option<Duration>,
) -> (Duration, usize) {
    let pattern = make_pattern(buf_size);
    let mut data = vec![0u8; buf_size];
    let mut total_bytes_sent = 0usize;

    // println!("throughput write starting");
    let start = Instant::now();
    let deadline = duration.map(|duration| {
        IoDeadline::new(&stream, start + duration).expect("failed to clone benchmark socket")
    });
    let mut counter: usize = 0;
    'outer: loop {
        if let Some(duration) = duration {
            if start.elapsed() >= duration {
                break;
            }
        }

        assert_eq!(total_bytes_sent, counter);

        let len = (rdrand() as usize) % data.len();

        data[0..len].copy_from_slice(&pattern[(counter & 0xff)..][..len]);
        counter += len;

        let mut written = 0;
        while written < len {
            match stream.write(&data[written..len]) {
                Ok(n) => {
                    if n == 0 {
                        break 'outer;
                    }
                    total_bytes_sent += n;
                    written += n;
                }
                Err(_) => {
                    break 'outer;
                }
            }
        }
        assert_eq!(written, len);
    }

    drop(deadline);
    let _ = stream.flush();
    let duration = start.elapsed();
    let _ = stream.shutdown(std::net::Shutdown::Both);

    // println!("throughput write done");
    (duration, total_bytes_sent)
}

// The flow-completion pair, below, differs from the two above in the only way
// that matters here: it is bounded by a byte count rather than a clock, so both
// ends agree in advance on exactly how much crosses the connection and neither
// has to signal the end by closing. That is what lets the client stop its timer
// on the last byte and *then* close, keeping the TIME-WAIT on the client side.

fn write_exact_pattern(
    stream: &mut TcpStream,
    buf_size: usize,
    total: usize,
) -> std::io::Result<()> {
    let pattern = make_pattern(buf_size);
    let mut sent = 0usize;
    while sent < total {
        let len = buf_size.min(total - sent);
        stream.write_all(&pattern[(sent & 0xff)..][..len])?;
        sent += len;
    }
    stream.flush()
}

fn read_exact_pattern(
    stream: &mut TcpStream,
    buf_size: usize,
    total: usize,
) -> std::io::Result<()> {
    let pattern = make_pattern(buf_size);
    let mut buffer = vec![0u8; buf_size];
    let mut received = 0usize;
    while received < total {
        let want = buf_size.min(total - received);
        let n = stream.read(&mut buffer[..want])?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("flow ended after {received} of {total} bytes"),
            ));
        }
        if buffer[..n] != pattern[(received & 0xff)..][..n] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad data at flow offset {received}"),
            ));
        }
        received += n;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    const TEST_DURATION: Duration = Duration::from_millis(100);
    const PEER_FALLBACK: Duration = Duration::from_secs(2);

    // Every test binds port zero: a fixed port in the ephemeral range can be
    // taken by any concurrent outbound connection on the host, and each test
    // only ever dials `local_addr()` anyway.
    const TEST_ADDR: &str = "127.0.0.1:0";

    fn stalled_connection() -> (TcpStream, mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind(TEST_ADDR).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        let (release, wait) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let _peer = peer;
            let _ = wait.recv_timeout(PEER_FALLBACK);
        });
        (client, release, peer)
    }

    fn assert_deadline(elapsed: Duration) {
        assert!(elapsed >= TEST_DURATION);
        assert!(
            elapsed < Duration::from_secs(1),
            "blocking I/O exceeded its deadline: {elapsed:?}"
        );
    }

    #[test]
    fn timed_read_interrupts_blocking_io() {
        let (client, release, peer) = stalled_connection();
        let (elapsed, bytes) = do_throughput_read(client, 64, Some(TEST_DURATION));
        let _ = release.send(());
        peer.join().unwrap();

        assert_eq!(bytes, 0);
        assert_deadline(elapsed);
    }

    #[test]
    fn timed_write_interrupts_blocking_io() {
        let (client, release, peer) = stalled_connection();
        let (elapsed, bytes) =
            do_throughput_write(client, MAX_BUF_SIZE as usize, Some(TEST_DURATION));
        let _ = release.send(());
        peer.join().unwrap();

        assert!(bytes > 0);
        assert_deadline(elapsed);
    }

    #[test]
    fn rr_interrupts_blocking_io() {
        let (client, release, peer) = stalled_connection();
        let start = Instant::now();
        crate::client::do_rr(client, TEST_DURATION).unwrap();
        let elapsed = start.elapsed();
        let _ = release.send(());
        peer.join().unwrap();

        assert_deadline(elapsed);
    }

    #[test]
    fn client_handshake_times_out_on_silent_server() {
        let listener = TcpListener::bind(TEST_ADDR).unwrap();
        let addr = listener.local_addr().unwrap();
        let (release, wait) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let (peer, _) = listener.accept().unwrap();
            let _peer = peer;
            let _ = wait.recv_timeout(PEER_FALLBACK);
        });

        let start = Instant::now();
        let result =
            crate::client::handshake_with_timeout(addr, CMD_TCP_RR, MIN_BUF_SIZE, TEST_DURATION);
        let elapsed = start.elapsed();
        let _ = release.send(());
        peer.join().unwrap();

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert_deadline(elapsed);
    }

    #[test]
    fn server_handshake_times_out_on_silent_client() {
        let listener = TcpListener::bind(TEST_ADDR).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();

        let start = Instant::now();
        let result = crate::server::handle_connection_with_timeout(peer, TEST_DURATION);
        let elapsed = start.elapsed();
        drop(client);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert_deadline(elapsed);
    }

    #[test]
    fn handshake_deadlines_are_removed_before_the_benchmark() {
        let listener = TcpListener::bind(TEST_ADDR).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (peer, _) = listener.accept().unwrap();
            crate::server::handle_connection_with_timeout(peer, TEST_DURATION)
        });

        let mut client =
            crate::client::handshake_with_timeout(addr, CMD_TCP_RR, MIN_BUF_SIZE, TEST_DURATION)
                .unwrap();
        std::thread::sleep(TEST_DURATION * 2);

        let sent = [0x5a; 64];
        let mut received = [0; 64];
        client.write_all(&sent).unwrap();
        client.read_exact(&mut received).unwrap();
        assert_eq!(received, sent);

        drop(client);
        assert!(server.join().unwrap().is_err());
    }

    // The measurement rests on the byte count being exact at both ends: the
    // client stops its timer on the last byte rather than on a close, so a
    // server that sent one byte more or fewer would either hang the client or
    // stop the clock early.
    #[test]
    fn a_flow_carries_exactly_the_requested_bytes() {
        const FLOW_BYTES: usize = 8192;
        const BUF_SIZE: usize = 1024;

        let listener = TcpListener::bind(TEST_ADDR).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (peer, _) = listener.accept().unwrap();
            crate::server::handle_connection_with_timeout(peer, HANDSHAKE_TIMEOUT)
        });

        let mut client = crate::client::handshake_with_timeout(
            addr,
            CMD_TCP_FLOW,
            BUF_SIZE as u32,
            HANDSHAKE_TIMEOUT,
        )
        .unwrap();
        let flow_bytes = FLOW_BYTES as u64;
        let buf: &[u8] = unsafe {
            core::slice::from_raw_parts(&flow_bytes as *const u64 as usize as *const u8, 8)
        };
        client.write_all(buf).unwrap();

        read_exact_pattern(&mut client, BUF_SIZE, FLOW_BYTES).unwrap();

        // Nothing follows the count: the server is waiting on our FIN, not
        // sending. Reading to EOF after half-closing is what proves it.
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut sink = [0u8; 64];
        assert_eq!(client.read(&mut sink).unwrap(), 0);

        server.join().unwrap().unwrap();
    }

    #[test]
    fn a_truncated_flow_is_an_error_rather_than_a_short_read() {
        let (client, release, peer) = stalled_connection();
        let mut client = client;
        drop(release); // Drops the peer's end, so the read sees EOF immediately.
        peer.join().unwrap();

        let err = read_exact_pattern(&mut client, 1024, 8192).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
