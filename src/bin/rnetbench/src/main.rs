// Pure rust network performance benchmark.
//
// With Alpine linux in the qemu guest running rnetbench server,
// and Ubuntu linux in the host running rnetbench client,
// round-robin is 19.8 us/roundtrip,
// and throughput is 615.8 MB/sec.
//
// On a baremetal Ubuntu Linux (loopback), RR is 6.5 us/roundtrip,
// and throughput is 520 MB/sec (throughput is slower!)

#![feature(io_error_more)]

use std::io::Read;
use std::io::Result;
use std::io::Write;
use std::time::Duration;
use std::{net::TcpStream, time::Instant};

mod client;
mod server;

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

fn print_usage_and_exit() -> ! {
    let prog = binary_name();
    println!("Usage:");
    println!("\t{} -s -p <PORT>     # Server.", prog);
    println!("\t{} -c <HOST:PORT>   # Client.", prog);

    std::process::exit(1)
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

    let args: Vec<String> = std::env::args().collect();

    if args.len() == 4 && args[1] == "-s" && args[2] == "-p" {
        let port = args[3].parse::<u16>();
        if port.is_err() {
            eprintln!("Error parsing the port number.");
            std::process::exit(1);
        }
        server::run(port.unwrap());
    }

    if args.len() == 3 && args[1] == "-c" {
        client::run(args[2].as_str());
    }

    print_usage_and_exit()
}

fn do_throughput_read(mut stream: TcpStream, what: &str) -> Result<()> {
    // Note: we use buffers of different size, to make things more interesting.
    let mut buffer = [0; 1513];
    let start_time = Instant::now();
    let mut total_bytes_read = 0usize;

    let mut counter: u8 = 0;
    loop {
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

    let duration = start_time.elapsed();
    let rate = total_bytes_read as f64 / duration.as_secs_f64() / (1024.0 * 1024.0);
    println!(
        "Throughput {} done: {:.2}MB received; {:.2?} MiB/sec.",
        what,
        total_bytes_read as f64 / (1024.0 * 1024.0),
        rate
    );

    Ok(())
}

fn do_throughput_write(mut stream: TcpStream, what: &str) -> std::io::Result<()> {
    let mut data = [0u8; 1011];
    let mut total_bytes_sent = 0usize;
    const TP_DURATION: Duration = Duration::from_secs(3);

    let start = std::time::Instant::now();
    let mut counter: u8 = 0;
    while start.elapsed() < TP_DURATION {
        for idx in 0..data.len() {
            data[idx] = counter;
            counter = counter.wrapping_add(1);
        }
        match stream.write_all(&data) {
            Ok(_) => total_bytes_sent += data.len(),
            Err(e) => {
                eprintln!("Failed to write to socket: {}", e);
                return Ok(());
            }
        }
    }

    stream.flush().unwrap();
    stream.shutdown(std::net::Shutdown::Both).unwrap();

    let duration = start.elapsed();
    let rate = total_bytes_sent as f64 / duration.as_secs_f64() / (1024.0 * 1024.0);
    println!(
        "Throughput {} done: {:.2}MB sent; {:.2?} MiB/sec.",
        what,
        (total_bytes_sent as f64) / (1024.0 * 1024.0),
        rate
    );

    Ok(())
}
