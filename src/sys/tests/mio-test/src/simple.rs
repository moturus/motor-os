// A simple test: a single TCP server/listener listens;
// NUM_CLIENTS connect to the server, write "ping";
// the server responds "pong".
const NUM_CLIENTS: usize = 4;

// This is a modified tcp_server.rs example from toko-rs/mio.
use mio::event::Event;
use mio::net::TcpListener;
use mio::{Events, Interest, Poll, Registry, Token};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

// Setup some tokens to allow us to identify which event is for which socket.
const SERVER: Token = Token(0);

// Some data we'll send over the connection.
const PING: &[u8] = b"ping";
const PONG: &[u8] = b"pong";

const ADDR: &str = "127.0.0.1:9000";

struct ClientConnection {
    stream: mio::net::TcpStream,
    ping: bool,
}

fn server_thread(ready: &AtomicBool) -> io::Result<()> {
    // Create a poll instance.
    let mut poll = Poll::new()?;
    // Create storage for events.
    let mut events = Events::with_capacity(128);

    // Setup the TCP server socket.
    let addr = ADDR.parse().unwrap();
    let mut server = TcpListener::bind(addr)?;

    // Register the server with poll we can receive events for it.
    poll.registry()
        .register(&mut server, SERVER, Interest::READABLE)?;

    // Map of `Token` -> `TcpStream`.
    let mut connections = HashMap::new();
    // Unique token for each incoming connection.
    let mut connection_token = Token(SERVER.0 + 1);

    ready.store(true, std::sync::atomic::Ordering::Release);

    let mut num_clients = 0;

    loop {
        if let Err(err) = poll.poll(&mut events, None) {
            if interrupted(&err) {
                continue;
            }
            return Err(err);
        }

        for event in events.iter() {
            match event.token() {
                SERVER => loop {
                    // Received an event for the TCP server socket, which
                    // indicates we can accept an connection.
                    let (mut connection, _address) = match server.accept() {
                        Ok((connection, address)) => (connection, address),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            // If we get a `WouldBlock` error we know our
                            // listener has no more incoming connections queued,
                            // so we can return to polling and wait for some
                            // more.
                            break;
                        }
                        Err(e) => {
                            // If it was any other kind of error, something went
                            // wrong and we terminate with an error.
                            return Err(e);
                        }
                    };

                    let token = next(&mut connection_token);
                    poll.registry()
                        .register(&mut connection, token, Interest::READABLE)?;

                    connections.insert(
                        token,
                        ClientConnection {
                            stream: connection,
                            ping: false,
                        },
                    );
                },
                token => {
                    // Maybe received an event for a TCP connection.
                    let done = if let Some(connection) = connections.get_mut(&token) {
                        handle_connection_event(poll.registry(), connection, event)?
                    } else {
                        // Sporadic events happen, we can safely ignore them.
                        false
                    };
                    if done {
                        if let Some(mut connection) = connections.remove(&token) {
                            poll.registry().deregister(&mut connection.stream)?;
                            num_clients += 1;
                            if num_clients == NUM_CLIENTS {
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }
}

fn next(current: &mut Token) -> Token {
    let next = current.0;
    current.0 += 1;
    Token(next)
}

/// Returns `true` if the connection is done.
fn handle_connection_event(
    registry: &Registry,
    connection: &mut ClientConnection,
    event: &Event,
) -> io::Result<bool> {
    if event.is_writable() {
        assert!(connection.ping);
        // We can (maybe) write to the connection.
        match connection.stream.write(PONG) {
            // We want to write the entire `DATA` buffer in a single go. If we
            // write less we'll return a short write error (same as
            // `io::Write::write_all` does).
            Ok(n) if n < PONG.len() => return Err(io::ErrorKind::WriteZero.into()),
            Ok(_) => {
                // After we've written something we'll reregister the connection
                // to only respond to readable events.
                registry.reregister(&mut connection.stream, event.token(), Interest::READABLE)?
            }
            // Would block "errors" are the OS's way of saying that the
            // connection is not actually ready to perform this I/O operation.
            Err(ref err) if would_block(err) => {}
            // Got interrupted (how rude!), we'll try again.
            Err(ref err) if interrupted(err) => {
                return handle_connection_event(registry, connection, event)
            }
            // Other errors we'll consider fatal.
            Err(err) => return Err(err),
        }
    }

    if event.is_readable() {
        let mut connection_closed = false;
        let mut received_data = vec![0; 4096];
        let mut bytes_read = 0;
        // We can (maybe) read from the connection.
        loop {
            match connection.stream.read(&mut received_data[bytes_read..]) {
                Ok(0) => {
                    // Reading 0 bytes means the other side has closed the
                    // connection or is done writing, then so are we.
                    connection_closed = true;
                    break;
                }
                Ok(n) => {
                    bytes_read += n;
                    if bytes_read == received_data.len() {
                        received_data.resize(received_data.len() + 1024, 0);
                    }
                }
                // Would block "errors" are the OS's way of saying that the
                // connection is not actually ready to perform this I/O operation.
                Err(ref err) if would_block(err) => break,
                Err(ref err) if interrupted(err) => continue,
                // Other errors we'll consider fatal.
                Err(err) => return Err(err),
            }
        }

        if !connection.ping && bytes_read > 0 {
            assert_eq!(bytes_read, PING.len());
            assert_eq!(&received_data[..bytes_read], PING);
            connection.ping = true;
            registry.reregister(&mut connection.stream, event.token(), Interest::WRITABLE)?
        }

        if connection_closed {
            return Ok(true);
        }
    }

    Ok(false)
}

fn would_block(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
}

fn interrupted(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}

fn client() -> io::Result<()> {
    let mut conn = std::net::TcpStream::connect(ADDR)?;
    conn.write_all(PING)?;

    let mut buf = [0_u8; PONG.len()];
    conn.read_exact(&mut buf)?;
    assert_eq!(buf, PONG);

    Ok(())
}

pub fn test() {
    let server_ready = AtomicBool::new(false);
    std::thread::scope(|s| {
        let server = s.spawn(|| server_thread(&server_ready).unwrap());
        while !server_ready.load(std::sync::atomic::Ordering::Relaxed) {
            core::hint::spin_loop();
        }

        let mut clients = Vec::with_capacity(NUM_CLIENTS);
        for _ in 0..NUM_CLIENTS {
            clients.push(std::thread::spawn(|| client().unwrap()));
        }

        for client in clients {
            client.join().unwrap();
        }
        server.join().unwrap();
    });

    std::thread::sleep(Duration::from_millis(100));
    println!("simple PASS");
    std::thread::sleep(Duration::from_millis(100));
}
