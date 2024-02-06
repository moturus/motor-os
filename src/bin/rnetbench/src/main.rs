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
    use std::io::Read;

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
