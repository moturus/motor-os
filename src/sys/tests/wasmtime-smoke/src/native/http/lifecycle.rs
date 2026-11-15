//! Backpressure and peer cancellation through the real HTTP host and sockets.
use super::*;

pub(super) fn run(addr: SocketAddr, body: &[u8]) -> Result<()> {
    thread::scope(|scope| -> Result<()> {
        let clients: Vec<_> = (0..CONCURRENCY)
            .map(|_| scope.spawn(|| slow_reader(addr, body).map_err(|e| e.to_string())))
            .collect();
        for client in clients {
            client.join().map_err(|_| "slow reader panicked")??;
        }
        Ok(())
    })?;
    println!(
        "PASS slow-readers: concurrency={CONCURRENCY} body_bytes={}",
        body.len()
    );

    // More abandoned handlers than request slots: a fresh echo after each
    // disconnect must complete, and later server shutdown must join every task.
    for round in 0..3 {
        for stage in ["no-bytes", "headers", "upload", "response"] {
            disconnect(addr, body, stage)?;
            request(addr, b"still alive", b"still alive", false)
                .map_err(|e| format!("after {stage} disconnect, round {round}: {e}"))?;
        }
    }
    println!("PASS disconnects: 12 abandoned connections with successful follow-up echoes");
    Ok(())
}

fn slow_reader(addr: SocketAddr, body: &[u8]) -> Result<()> {
    let mut socket = connect(addr)?;
    let mut writer = socket.try_clone()?;
    thread::scope(|scope| -> Result<()> {
        let sending = scope.spawn(|| -> std::io::Result<()> {
            write!(writer, "POST /echo HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n", body.len())?;
            writer.write_all(body)
        });
        let mut response = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            let count = socket.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            if response.len() + count > RESPONSE_LIMIT as usize {
                return Err("slow response exceeded its bound".into());
            }
            response.extend_from_slice(&chunk[..count]);
            // Deliberately consume more slowly than the guest can produce.
            thread::sleep(Duration::from_millis(1));
        }
        sending
            .join()
            .map_err(|_| "slow reader's writer panicked")??;
        check_response(&response, body)
    })
}

fn disconnect(addr: SocketAddr, body: &[u8], stage: &str) -> Result<()> {
    match stage {
        // Zero-transmit close may reset on Motor; it is not an HTTP response.
        "no-bytes" => drop(connect(addr)?),
        "headers" => {
            let mut socket = connect(addr)?;
            socket.write_all(b"POST /echo HTTP/1.1\r\nHost:")?;
        }
        "upload" | "response" => {
            let (mut socket, _) = begin_echo(addr, body.len(), &body[..1024])?;
            if stage == "response" {
                // Observe response streaming before abandoning both directions.
                socket.read_exact(&mut [0])?;
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
