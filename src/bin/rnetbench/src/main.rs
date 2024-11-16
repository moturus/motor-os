// Pure rust network performance benchmark.

#![feature(io_error_more)]

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

use clap::Parser;

mod client;
mod server;

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
}

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

    if args.server {
        server::run(args.port);
    } else if args.client.is_some() {
        client::run(&args);
    } else {
        eprintln!("error: either --server or --client argument is required");
    }
}

fn do_throughput_read(mut stream: TcpStream, client_args: Option<&Args>) -> (Duration, usize) {
    let mut buffer = [0; 1024];
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
        let bytes_read = match stream.read(&mut buffer) {
            Ok(n) => n,
            Err(_) => break,
        };
        if bytes_read == 0 {
            break;
        }
        for b in &buffer[0..bytes_read] {
            if ((counter & 0xff) as u8) != *b {
                panic!("bad data: counter: {counter} data: {}", *b);
            }
            counter += 1;
        }
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

fn do_throughput_write(mut stream: TcpStream, client_args: Option<&Args>) -> (Duration, usize) {
    let mut data = [0u8; 1024];
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

        for b in &mut data[0..len] {
            *b = (counter & 0xff) as u8;
            counter += 1;
        }

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
