use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::time::Duration;
use moto_ipc::io_channel;
use moto_sys::ErrorCode;

#[cfg(debug_assertions)]
use super::util::moturus_log;

struct NetRuntime {
    channels: crate::mutex::Mutex<Vec<Arc<NetChannel>>>,
}

struct NetChannel {
    conn: io_channel::ClientConnection,
    tcp_sockets: crate::mutex::Mutex<BTreeMap<u64, Weak<TcpSocket>>>,
}

impl NetChannel {
    fn tcp_socket_dropped(&self, socket_handle: u64) {
        assert_eq!(
            0,
            self.tcp_sockets
                .lock()
                .remove(&socket_handle)
                .unwrap()
                .strong_count()
        );
    }
}

pub struct TcpSocket {
    channel: Arc<NetChannel>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    handle: u64,
}

impl Drop for TcpSocket {
    fn drop(&mut self) {
        self.channel.tcp_socket_dropped(self.handle);
    }
}

impl TcpSocket {
    pub fn connect(socket_addr: &SocketAddr) -> Result<Arc<TcpSocket>, ErrorCode> {
        todo!()
    }

    pub fn connect_timeout(
        socket_addr: &SocketAddr,
        timeout: Duration,
    ) -> Result<Arc<TcpSocket>, ErrorCode> {
        todo!()
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn read_timeout(&self) -> Result<Option<Duration>, ErrorCode> {
        todo!()
    }

    pub fn write_timeout(&self) -> Result<Option<Duration>, ErrorCode> {
        todo!()
    }

    pub fn peek(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        todo!()
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        todo!()
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        todo!()
    }

    pub fn peer_addr(&self) -> Result<SocketAddr, ErrorCode> {
        todo!()
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ErrorCode> {
        todo!()
    }

    pub fn shutdown(&self, read: bool, write: bool) -> Result<(), ErrorCode> {
        assert!(read || write);
        todo!()
    }

    pub fn set_linger(&self, dur: Option<Duration>) -> Result<(), ErrorCode> {
        if let Some(dur) = dur {
            if dur == Duration::ZERO {
                return Ok(());
            }
        }

        // At the moment, socket shutdown or drop drops all unsent bytes, which
        // corresponds to SO_LINGER(0). This may or may not be what the user
        // wants, but anything different requires changing sys-io code/logic,
        // at there are higher-priority work to do.
        Err(ErrorCode::NotImplemented)
    }

    pub fn linger(&self) -> Result<Option<Duration>, ErrorCode> {
        Ok(Some(Duration::ZERO)) // see set_linger() above.
    }

    pub fn set_nodelay(&self, nodelay: bool) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn nodelay(&self) -> Result<bool, ErrorCode> {
        todo!()
    }

    pub fn set_ttl(&self, ttl: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn ttl(&self) -> Result<u32, ErrorCode> {
        todo!()
    }

    pub fn take_error(&self) -> Result<Option<ErrorCode>, ErrorCode> {
        // We don't have this unixism.
        Ok(None)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), ErrorCode> {
        todo!()
    }
}

impl core::fmt::Debug for TcpSocket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

pub struct TcpListener {}

impl Drop for TcpListener {
    fn drop(&mut self) {
        todo!()
    }
}

impl TcpListener {
    pub fn bind(socket_addr: &SocketAddr) -> Result<TcpListener, ErrorCode> {
        todo!()
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ErrorCode> {
        todo!()
    }

    pub fn accept(&self) -> Result<(Arc<TcpSocket>, SocketAddr), ErrorCode> {
        todo!()
    }

    pub fn set_ttl(&self, ttl: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn ttl(&self) -> Result<u32, ErrorCode> {
        todo!()
    }

    pub fn set_only_v6(&self, _: bool) -> Result<(), ErrorCode> {
        Err(ErrorCode::NotImplemented) // This is deprected since Rust 1.16
    }

    pub fn only_v6(&self) -> Result<bool, ErrorCode> {
        Err(ErrorCode::NotImplemented) // This is deprected since Rust 1.16
    }

    pub fn take_error(&self) -> Result<Option<ErrorCode>, ErrorCode> {
        // We don't have this unixism.
        Ok(None)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), ErrorCode> {
        todo!()
    }
}

impl core::fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}
