// Pure rust network performance benchmark.

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

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

static MAGIC_BYTES_CLIENT: &[u8] = b"rnetbench_magic_client";
static MAGIC_BYTES_SERVER: &[u8] = b"rnetbench_magic_server";
const CMD_TCP_RR: u64 = 1;
const CMD_TCP_THROUGHPUT_OUT: u64 = 2;
const CMD_TCP_THROUGHPUT_IN: u64 = 3;

fn binary_name() -> String {
    std::path::Path::new(std::env::args().next().unwrap().as_str())
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

// Intercept Ctrl+C ourselves if the OS does not do it for us.
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

fn do_throughput_read(
    mut stream: TcpStream,
    buf_size: usize,
    client_args: Option<&Args>,
) -> (Duration, usize) {
    let pattern = make_pattern(buf_size);
    let mut buffer = vec![0u8; buf_size];
    let mut total_bytes_read = 0usize;
    let duration = client_args.map(|args| Duration::from_secs(args.time as u64));

    // println!("throughput read starting");
    let mut counter: usize = 0;
    let start = std::time::Instant::now();
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
    client_args: Option<&Args>,
) -> (Duration, usize) {
    let pattern = make_pattern(buf_size);
    let mut data = vec![0u8; buf_size];
    let mut total_bytes_sent = 0usize;
    let duration = client_args.map(|args| Duration::from_secs(args.time as u64));

    // println!("throughput write starting");
    let start = std::time::Instant::now();
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

    let _ = stream.flush();
    let duration = start.elapsed();
    let _ = stream.shutdown(std::net::Shutdown::Both);

    // println!("throughput write done");
    (duration, total_bytes_sent)
}
