#![allow(unused)]
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::sync::{atomic::*, Arc};
use std::time::Duration;

fn handle_client(mut stream: std::net::TcpStream) {
    let mut data = [0 as u8; 17];
    while match stream.read(&mut data) {
        Ok(size) => {
            for byte in &mut data {
                *byte = 255 - *byte;
            }
            stream.write(&data[0..size]).unwrap();
            true
        }
        Err(_) => {
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            false
        }
    } {}
}

fn server_thread(start: Arc<AtomicBool>, stop: Arc<AtomicBool>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:3333").unwrap();
    assert!(std::net::TcpListener::bind("127.0.0.1:3333").is_err());
    start.store(true, Ordering::Release);

    // accept connections and process them, spawning a new thread for each one

    // let (stream, _) = listener.accept().unwrap();
    // handle_client(stream);
    for stream in listener.incoming() {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match stream {
            Ok(stream) => {
                std::thread::spawn(move || handle_client(stream));
            }
            Err(e) => {
                std::thread::sleep(std::time::Duration::from_secs(1));
                println!("Error: ----------- {} ----------------", e);
                panic!("{}", e)
                /* connection failed */
            }
        }
    }
}

fn client_iter() {
    let addrs: Vec<_> = "localhost:3333".to_socket_addrs().unwrap().collect();
    assert_eq!(addrs.len(), 1);
    let mut stream =
        std::net::TcpStream::connect_timeout(&addrs[0], Duration::from_millis(100)).unwrap();
    let tx: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    stream.write(&tx).unwrap();

    let mut rx = [0 as u8; 8];
    match stream.read_exact(&mut rx) {
        Ok(_) => {
            assert_eq!(rx, [254, 253, 252, 251, 250, 249, 248, 247]);
        }
        Err(e) => {
            println!("Failed to receive data: {}", e);
            panic!()
        }
    }
}

fn test_io_latency() {
    let addrs: Vec<_> = "localhost:3333".to_socket_addrs().unwrap().collect();
    assert_eq!(addrs.len(), 1);
    let stream =
        std::net::TcpStream::connect_timeout(&addrs[0], Duration::from_millis(100)).unwrap();

    // set_nodelay() is a good way to measure local I/O latency, as for the loopback
    // device it is a NOOP.
    let mut iters = 0_u64;
    const DUR: Duration = Duration::from_millis(500);
    let start = std::time::Instant::now();
    while start.elapsed() < DUR {
        stream.set_nodelay(true).unwrap();
        iters += 1;
    }

    let elapsed = start.elapsed();
    println!(
        "IO latency of TcpStream::set_nodelay(): {:.3} usec/IO",
        elapsed.as_secs_f64() * 1000.0 * 1000.0 / (iters as f64)
    );
}

pub fn test_tcp_loopback() {
    assert!(std::net::TcpStream::connect("localhost:3333").is_err());
    let start = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let start_server = start.clone();
    let stop_server = stop.clone();
    let server = std::thread::spawn(|| server_thread(start_server, stop_server));

    while !start.load(Ordering::Acquire) {
        core::hint::spin_loop()
    }

    client_iter();
    client_iter();
    client_iter();
    test_io_latency();

    stop.store(true, Ordering::Release);
    // Kick the listener.
    let _ = std::net::TcpStream::connect("localhost:3333").unwrap();
    server.join().unwrap();

    // Wrap the output in sleeps to avoid debug console output mangling.
    std::thread::sleep(std::time::Duration::from_millis(10));
    println!("test_tcp() PASS");
    std::thread::sleep(std::time::Duration::from_millis(10));
}

// pub fn test_wget() {
//     // let url = "1.1.1.1:80";
//     // let url = "10.0.2.10:10023";
//     let mut stream = std::net::TcpStream::connect(url).unwrap();
//     let request = "GET /\nHost: 1.1.1.1\nUser-Agent: *\nAccept: */*\n\n";
//     stream.write(request.as_bytes()).unwrap();

//     let mut rx = [0 as u8; 8];
//     match stream.read(&mut rx) {
//         Ok(_) => {
//             println!("test_wget(): got a response from {}", url);
//         }
//         Err(e) => {
//             println!("Failed to receive data: {}", e);
//             panic!()
//         }
//     }
// }
