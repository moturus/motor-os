//! Standard-library UDP with a bounded receive channel for the host fixture.
use crate::peer::BUFFER_SIZE;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::Duration;

pub enum Event {
    Datagram(SocketAddr, Vec<u8>),
    Command(String),
}

pub struct Transport {
    socket: UdpSocket,
    running: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    reader: Option<JoinHandle<()>>,
}

impl Transport {
    pub fn bind(address: SocketAddr, events: SyncSender<Event>) -> io::Result<Self> {
        let socket = UdpSocket::bind(address)?;
        // The timeout only permits prompt shutdown/rebinding of the reader.
        // Main-loop timers use recv_timeout and are independent of UDP input.
        socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        let reader_socket = socket.try_clone()?;
        let running = Arc::new(AtomicBool::new(true));
        let dropped = Arc::new(AtomicU64::new(0));
        let reader_running = running.clone();
        let reader_dropped = dropped.clone();
        let reader = std::thread::spawn(move || {
            let mut buffer = [0; BUFFER_SIZE + 1];
            while reader_running.load(Ordering::Acquire) {
                match reader_socket.recv_from(&mut buffer) {
                    Ok((len, source)) => {
                        let event = Event::Datagram(source, buffer[..len].to_vec());
                        match events.try_send(event) {
                            Ok(()) => {}
                            Err(TrySendError::Full(_)) => {
                                reader_dropped.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySendError::Disconnected(_)) => break,
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => break,
                }
            }
            reader_running.store(false, Ordering::Release);
        });
        Ok(Self {
            socket,
            running,
            dropped,
            reader: Some(reader),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn send(&self, endpoint: SocketAddr, packet: &[u8]) -> io::Result<()> {
        match self.socket.send_to(packet, endpoint) {
            Ok(len) if len == packet.len() => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial UDP datagram",
            )),
            Err(error) => Err(error),
        }
    }

    pub fn running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        self.reader.take().unwrap().join().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;

    #[test]
    fn localhost_udp_and_oversize_detection() {
        let (sender, receiver) = sync_channel(64);
        let transport = Transport::bind("127.0.0.1:0".parse().unwrap(), sender).unwrap();
        let endpoint = transport.local_addr().unwrap();
        transport.send(endpoint, b"hello").unwrap();
        match receiver.recv_timeout(Duration::from_secs(1)).unwrap() {
            Event::Datagram(source, bytes) => {
                assert_eq!(source, endpoint);
                assert_eq!(bytes, b"hello");
            }
            _ => panic!("unexpected event"),
        }
        transport.send(endpoint, &[0; BUFFER_SIZE + 100]).unwrap();
        match receiver.recv_timeout(Duration::from_secs(1)).unwrap() {
            Event::Datagram(_, bytes) => assert_eq!(bytes.len(), BUFFER_SIZE + 1),
            _ => panic!("unexpected event"),
        }
        assert!(transport.running());
    }
}
