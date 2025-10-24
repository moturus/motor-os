use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    process::Child,
};

// Intercept Ctrl+C ourselves if the OS does not do it for us.
fn input_listener() {
    loop {
        let mut input = [0_u8; 16];
        let sz = std::io::stdin().read(&mut input).unwrap();
        for b in &input[0..sz] {
            if *b == 3 {
                println!("\nrush: caught ^C: exiting.");
                std::process::exit(0);
            }
        }
    }
}

pub fn run(port: u16) -> ! {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
    let listener = if let Ok(listener) = std::net::TcpListener::bind(addr) {
        listener
    } else {
        eprintln!("rush: TcpListener.bind('0.0.0.0:{port}') failed.");
        std::process::exit(1);
    };

    println!("rush server: listening on 0.0.0.0:{port}\n");

    std::thread::spawn(input_listener);

    for tcp_stream in listener.incoming() {
        handle_connection(tcp_stream);
    }

    unreachable!()
}

fn handle_connection(maybe_stream: std::io::Result<TcpStream>) {
    match maybe_stream {
        Ok(stream) => {
            let _ = std::thread::spawn(|| {
                server_thread(stream);
            });
        }
        Err(error) => eprintln!("rush: bad connection: {error:?}."),
    }
}

fn spawn_shell() -> Child {
    let self_cmd = std::env::args().next().unwrap();
    let mut command = std::process::Command::new(self_cmd.as_str());
    command.arg("-piped");
    command.stdin(std::process::Stdio::piped());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            eprintln!("rush: error spawning '{self_cmd}': {err:?}.");
            std::process::exit(1);
        }
    }
}

fn server_thread(mut client: TcpStream) {
    let mut buf = [0_u8; crate::RUSH_HANDSHAKE.len()];
    if client.read_exact(&mut buf).is_err() {
        eprintln!("rush: handshake failed (1).");
        return;
    }
    if buf != crate::RUSH_HANDSHAKE.as_bytes() {
        eprintln!("rush: handshake failed (2).");
        return;
    }
    if client.write_all(crate::RUSH_HANDSHAKE.as_bytes()).is_err() {
        eprintln!("rush: handshake failed (3).");
        return;
    }
    let _ = client.flush();

    let remote_addr = if let Ok(addr) = client.peer_addr() {
        addr
    } else {
        return;
    };
    println!("rush: new connection from {remote_addr:?}.");

    let mut shell = spawn_shell();
    client.set_nodelay(true).unwrap();

    // stdout
    let mut local_stdout = shell.stdout.take().unwrap();
    let mut remote_stdout = client.try_clone().unwrap();
    remote_stdout.set_nodelay(true).unwrap();
    let stdout_thread = std::thread::spawn(move || {
        let mut buf = [0_u8; 80];
        while let Ok(sz) = local_stdout.read(&mut buf) {
            if sz > 0 {
                if remote_stdout.write_all(&buf[0..sz]).is_err() {
                    break;
                }
            } else {
                break;
            }
        }

        // Signal the end of this session.
        let ctrl_c = [3_u8; 1];
        let _ = remote_stdout.write_all(&ctrl_c);
        let _ = remote_stdout.flush();
        // Use the connection to synchronize threads.
        let _ = remote_stdout.shutdown(std::net::Shutdown::Both);
    });

    // stderr
    let mut local_stderr = shell.stderr.take().unwrap();
    let mut remote_stderr = client.try_clone().unwrap();
    remote_stderr.set_nodelay(true).unwrap();
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = [0_u8; 80];
        while let Ok(sz) = local_stderr.read(&mut buf) {
            if sz > 0 {
                if remote_stderr.write_all(&buf[0..sz]).is_err() {
                    break;
                }
            } else {
                break;
            }
        }
    });

    // stdin
    let mut local_stdin = shell.stdin.take().unwrap();
    let mut remote_stdin = client.try_clone().unwrap();
    let stdin_thread = std::thread::spawn(move || {
        loop {
            let mut buf = [0_u8; 80];
            let sz = match remote_stdin.read(&mut buf) {
                Ok(sz) => sz,
                Err(err) => {
                    println!("Remote read failed with {err:?}");
                    break;
                }
            };

            if sz == 0 {
                break;
            }

            if local_stdin.write_all(&buf[0..sz]).is_err() {
                println!("Local write failed");
                break;
            }
            if local_stdin.flush().is_err() {
                println!("Local write failed");
                break;
            }
        }

        let _ = shell.kill();
        let _ = client.shutdown(std::net::Shutdown::Both);
        let _ = shell.wait().unwrap();
    });

    stdin_thread.join().unwrap();
    stdout_thread.join().unwrap();
    stderr_thread.join().unwrap();
    println!("rush: connection from {remote_addr:?} closed.");
}
