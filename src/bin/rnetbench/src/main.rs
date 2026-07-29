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
}

const MIN_BUF_SIZE: u32 = 64;
const MAX_BUF_SIZE: u32 = 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

static MAGIC_BYTES_CLIENT: &[u8] = b"rnetbench_magic_client";
static MAGIC_BYTES_SERVER: &[u8] = b"rnetbench_magic_server";
const CMD_TCP_RR: u64 = 1;
const CMD_TCP_THROUGHPUT_OUT: u64 = 2;
const CMD_TCP_THROUGHPUT_IN: u64 = 3;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    const TEST_DURATION: Duration = Duration::from_millis(100);
    const PEER_FALLBACK: Duration = Duration::from_secs(2);

    fn stalled_connection() -> (TcpStream, mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
}
