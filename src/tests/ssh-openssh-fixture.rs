// Host-only inetd adapter: kernel-assigned ports avoid racy port selection.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;

enum Event {
    Connection(std::io::Result<TcpStream>),
    Stop,
}

fn main() -> std::io::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    assert_eq!(args.len(), 4, "expected SSHD CONFIG LISTEN_IP");
    assert!(matches!(args[3].as_str(), "127.0.0.1" | "192.168.4.1"));
    let listener = TcpListener::bind((args[3].as_str(), 0))?;
    println!("PORT={}", listener.local_addr()?.port());
    std::io::stdout().flush()?;
    let (events, receiver) = mpsc::channel();
    let connections = events.clone();
    std::thread::spawn(move || {
        for socket in listener.incoming() {
            if connections.send(Event::Connection(socket)).is_err() {
                break;
            }
        }
    });
    std::thread::spawn(move || {
        let mut byte = [0];
        let _ = std::io::stdin().read(&mut byte);
        let _ = events.send(Event::Stop);
    });
    let mut children: Vec<Child> = Vec::new();
    let result = (|| {
        while let Ok(event) = receiver.recv() {
            let Event::Connection(socket) = event else {
                break;
            };
            let socket = socket?;
            let input: OwnedFd = socket.try_clone()?.into();
            let output: OwnedFd = socket.into();
            children.push(
                Command::new(&args[1])
                    .args(["-i", "-e", "-f", &args[2]])
                    .stdin(Stdio::from(input))
                    .stdout(Stdio::from(output))
                    .spawn()?,
            );
            for index in (0..children.len()).rev() {
                if children[index].try_wait()?.is_some() {
                    children.swap_remove(index);
                }
            }
        }
        Ok(())
    })();
    // The control pipe owns every inetd child, including a failed setup's.
    for mut child in children {
        if child.try_wait()?.is_none() {
            child.kill()?;
        }
        child.wait()?;
    }
    result
}
