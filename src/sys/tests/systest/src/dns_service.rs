//! Fixtures for the full test's DNS service checks: occupy the loopback DNS
//! port, and resolve a name through the VDSO client without network traffic.
use std::io::Write;
use std::net::{TcpListener, ToSocketAddrs, UdpSocket};

pub fn hold_port() -> ! {
    let address = "127.0.0.1:53";
    let _udp = UdpSocket::bind(address).unwrap();
    let _tcp = TcpListener::bind(address).unwrap();
    println!("holding {address} as pid {}", std::process::id());
    std::io::stdout().flush().unwrap();
    // Live until killed; the test's SSH session supplies no stdin to wait on.
    loop {
        std::thread::park();
    }
}

pub fn lookup(name: &str) {
    match (name, 0).to_socket_addrs() {
        Ok(addresses) => {
            for address in addresses {
                println!("{}", address.ip());
            }
        }
        Err(error) => {
            eprintln!("systest: {name}: {error}");
            std::process::exit(1);
        }
    }
}
