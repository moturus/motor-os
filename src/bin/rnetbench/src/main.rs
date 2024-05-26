// Pure rust network performance benchmark.

#![feature(io_error_more)]

use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

use clap::Parser;

mod client;
mod server;

#[derive(Parser, Debug)]
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
    let mut buffer = [0; 1513];
    let mut total_bytes_read = 0usize;
    let duration = client_args.map(|args| Duration::from_secs(args.time as u64));

    // println!("throughput read starting");
    let mut counter: u8 = 0;
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
        for idx in 0..bytes_read {
            assert_eq!(counter, buffer[idx]);
            counter = counter.wrapping_add(1);
        }
        total_bytes_read += bytes_read;
    }

    let _ = stream.flush();
    let duration = start.elapsed();
    let _ = stream.shutdown(std::net::Shutdown::Both);

    (duration, total_bytes_read)
}

fn do_throughput_write(mut stream: TcpStream, client_args: Option<&Args>) -> (Duration, usize) {
    let mut data = [0u8; 1024];
    let mut total_bytes_sent = 0usize;
    let duration = client_args.map(|args| Duration::from_secs(args.time as u64));

    // println!("throughput write starting");
    let start = std::time::Instant::now();
    let mut counter: u8 = 0;
    'outer: loop {
        if let Some(duration) = duration {
            if start.elapsed() >= duration {
                break;
            }
        }
        for idx in 0..data.len() {
            data[idx] = counter;
            counter = counter.wrapping_add(1);
        }

        let mut written = 0;
        while written < data.len() {
            match stream.write(&data[written..]) {
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
    }

    let _ = stream.flush();
    let duration = start.elapsed();
    let _ = stream.shutdown(std::net::Shutdown::Both);

    (duration, total_bytes_sent)
}
