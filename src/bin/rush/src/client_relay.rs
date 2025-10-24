use std::{io::Read, io::Write, net::TcpStream, time::Duration};

pub struct ClientRelay {
    remote_conn: TcpStream,
}

impl ClientRelay {
    fn exit() -> ! {
        crate::exit(0)
    }

    fn exit_with_error() -> ! {
        eprintln!("\nrush: lost remote connection.");
        crate::exit(1)
    }

    pub fn run(&mut self) -> ! {
        /*
         * Instead of trying to carefully coordinate shutdown, which is difficult
         * because stdin().read is blocking, we simply exit the process.
         */
        crate::term::make_raw();
        let mut receiver = self.remote_conn.try_clone().unwrap();
        let _ = std::thread::spawn(move || {
            loop {
                let mut buf = [0_u8; 128];
                let mut done = false;
                let mut sz = match receiver.read(&mut buf) {
                    Ok(sz) => sz,
                    Err(err) => {
                        eprintln!("exit: remote read failed with {err:?}");
                        break;
                    }
                };
                if sz == 0 {
                    eprintln!("exit: remote read done");
                    break;
                }

                // The "server" side of rush sends 3u8 to indicate
                // it wants to end the session.
                if buf[sz - 1] == 3 {
                    // End of session.
                    sz -= 1;
                    if sz == 0 {
                        break;
                    }
                    done = true;
                }

                #[cfg(debug_assertions)]
                for c in &buf[0..sz] {
                    if *c == 3 {
                        eprintln!("\n\nrush: unexpected ^C.\n\n");
                        Self::exit()
                    }
                }

                std::io::stdout().write_all(&buf[0..sz]).unwrap();
                std::io::stdout().flush().unwrap();
                if done {
                    break;
                }
            }
            Self::exit()
        });

        loop {
            let mut buf = [0_u8; 128];
            let sz = std::io::stdin()
                .read(&mut buf)
                .map_err(|_| Self::exit_with_error())
                .unwrap();
            assert!(sz > 0);
            self.remote_conn
                .write(&buf[0..sz])
                .map_err(|_| Self::exit_with_error())
                .unwrap();
            self.remote_conn
                .flush()
                .map_err(|_| Self::exit_with_error())
                .unwrap();
        }
    }
}

pub fn connect_to(host_port: &str) -> ClientRelay {
    use std::net::ToSocketAddrs;

    let mut addresses = vec![];
    match host_port.to_socket_addrs() {
        Ok(addrs) => {
            for addr in addrs {
                addresses.push(addr);
            }
        }
        Err(_) => crate::print_usage_and_exit(1),
    }

    if addresses.len() != 1 {
        crate::print_usage_and_exit(1);
    }
    let addr = addresses[0];

    let mut remote_conn = match TcpStream::connect_timeout(&addr, Duration::new(1, 0)) {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("rush: error connecting to {host_port}: {err:?}.");
            std::process::exit(1);
        }
    };

    // Handshake.
    remote_conn.set_nodelay(true).unwrap();
    if remote_conn
        .write_all(crate::RUSH_HANDSHAKE.as_bytes())
        .is_err()
    {
        eprintln!("rush: handshake failed (1).");
        std::process::exit(1);
    }
    remote_conn.flush().unwrap();
    let mut buf = [0_u8; crate::RUSH_HANDSHAKE.len()];
    if let Err(err) = remote_conn.read_exact(&mut buf) {
        eprintln!("rush: handshake failed (2): {err:?}.");
        std::process::exit(1);
    }
    if buf != crate::RUSH_HANDSHAKE.as_bytes() {
        eprintln!("rush: handshake failed (3).");
        std::process::exit(1);
    }

    println!("rush: connected to {host_port}");
    ClientRelay { remote_conn }
}
