use super::io_executor;
use super::net_async;
use alloc::sync::Arc;
use core::net::Ipv4Addr;
use core::net::Ipv6Addr;
use core::net::SocketAddr;
use core::net::SocketAddrV4;
use core::time::Duration;
use moto_sys::ErrorCode;

#[cfg(debug_assertions)]
use super::util::moturus_log;

pub struct TcpStream {
    async_inner: Arc<net_async::TcpStream>,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        if let Some(inner) = Arc::get_mut(&mut self.async_inner) {
            io_executor::block_on(inner.on_drop());
        }
    }
}

impl TcpStream {
    pub fn connect(socket_addr: &SocketAddr) -> Result<TcpStream, ErrorCode> {
        let async_inner = io_executor::block_on(net_async::TcpStream::connect(socket_addr))?;
        #[cfg(debug_assertions)]
        moturus_log!("tcp stream connected!");
        Ok(Self {
            async_inner: Arc::new(async_inner),
        })
    }

    pub fn connect_timeout(
        socket_addr: &SocketAddr,
        timeout: Duration,
    ) -> Result<TcpStream, ErrorCode> {
        let async_inner =
            io_executor::block_on(net_async::TcpStream::connect_timeout(socket_addr, timeout))?;
        #[cfg(debug_assertions)]
        moturus_log!("tcp stream connected!");
        Ok(Self {
            async_inner: Arc::new(async_inner),
        })
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), ErrorCode> {
        io_executor::block_on(self.async_inner.set_read_timeout(timeout))
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<(), ErrorCode> {
        io_executor::block_on(self.async_inner.set_write_timeout(timeout))
    }

    pub fn read_timeout(&self) -> Result<Option<Duration>, ErrorCode> {
        todo!()
    }

    pub fn write_timeout(&self) -> Result<Option<Duration>, ErrorCode> {
        todo!()
    }

    pub fn peek(&self, _: &mut [u8]) -> Result<usize, ErrorCode> {
        todo!()
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        io_executor::block_on(self.async_inner.read(buf))
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        io_executor::block_on(self.async_inner.write(buf))
    }

    pub fn peer_addr(&self) -> Result<SocketAddr, ErrorCode> {
        self.async_inner.peer_addr()
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ErrorCode> {
        self.async_inner.socket_addr()
    }

    pub fn shutdown(&self, read: bool, write: bool) -> Result<(), ErrorCode> {
        assert!(read || write);
        io_executor::block_on(self.async_inner.shutdown(read, write))
    }

    pub fn duplicate(&self) -> Result<TcpStream, ErrorCode> {
        Ok(TcpStream {
            async_inner: self.async_inner.clone(),
        })
    }

    pub fn set_linger(&self, _: Option<Duration>) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn linger(&self) -> Result<Option<Duration>, ErrorCode> {
        todo!()
    }

    pub fn set_nodelay(&self, nodelay: bool) -> Result<(), ErrorCode> {
        io_executor::block_on(self.async_inner.set_nodelay(nodelay))
    }

    pub fn nodelay(&self) -> Result<bool, ErrorCode> {
        todo!()
    }

    pub fn set_ttl(&self, _: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn ttl(&self) -> Result<u32, ErrorCode> {
        todo!()
    }

    pub fn take_error(&self) -> Result<Option<ErrorCode>, ErrorCode> {
        todo!()
    }

    pub fn set_nonblocking(&self, _: bool) -> Result<(), ErrorCode> {
        todo!()
    }
}

impl core::fmt::Debug for TcpStream {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

pub struct TcpListener {
    async_inner: net_async::TcpListener,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        io_executor::block_on(self.async_inner.on_drop());
    }
}

impl TcpListener {
    pub fn bind(socket_addr: &SocketAddr) -> Result<TcpListener, ErrorCode> {
        let async_inner = io_executor::block_on(net_async::TcpListener::bind(socket_addr))?;
        Ok(Self { async_inner })
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ErrorCode> {
        self.async_inner.socket_addr()
    }

    pub fn accept(&self) -> Result<(TcpStream, SocketAddr), ErrorCode> {
        let (inner_stream, addr) = io_executor::block_on(self.async_inner.accept())?;
        Ok((
            TcpStream {
                async_inner: Arc::new(inner_stream),
            },
            addr,
        ))
    }

    pub fn duplicate(&self) -> Result<TcpListener, ErrorCode> {
        todo!()
    }

    pub fn set_ttl(&self, _: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn ttl(&self) -> Result<u32, ErrorCode> {
        todo!()
    }

    pub fn set_only_v6(&self, _: bool) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn only_v6(&self) -> Result<bool, ErrorCode> {
        todo!()
    }

    pub fn take_error(&self) -> Result<Option<ErrorCode>, ErrorCode> {
        todo!()
    }

    pub fn set_nonblocking(&self, _: bool) -> Result<(), ErrorCode> {
        todo!()
    }
}

impl core::fmt::Debug for TcpListener {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

pub struct UdpSocket {}

impl UdpSocket {
    pub fn bind(_: &SocketAddr) -> Result<UdpSocket, ErrorCode> {
        todo!()
    }

    pub fn peer_addr(&self) -> Result<SocketAddr, ErrorCode> {
        todo!()
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ErrorCode> {
        todo!()
    }

    pub fn recv_from(&self, _: &mut [u8]) -> Result<(usize, SocketAddr), ErrorCode> {
        todo!()
    }

    pub fn peek_from(&self, _: &mut [u8]) -> Result<(usize, SocketAddr), ErrorCode> {
        todo!()
    }

    pub fn send_to(&self, _: &[u8], _: &SocketAddr) -> Result<usize, ErrorCode> {
        todo!()
    }

    pub fn duplicate(&self) -> Result<UdpSocket, ErrorCode> {
        todo!()
    }

    pub fn set_read_timeout(&self, _: Option<Duration>) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn set_write_timeout(&self, _: Option<Duration>) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn read_timeout(&self) -> Result<Option<Duration>, ErrorCode> {
        todo!()
    }

    pub fn write_timeout(&self) -> Result<Option<Duration>, ErrorCode> {
        todo!()
    }

    pub fn set_broadcast(&self, _: bool) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn broadcast(&self) -> Result<bool, ErrorCode> {
        todo!()
    }

    pub fn set_multicast_loop_v4(&self, _: bool) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn multicast_loop_v4(&self) -> Result<bool, ErrorCode> {
        todo!()
    }

    pub fn set_multicast_ttl_v4(&self, _: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn multicast_ttl_v4(&self) -> Result<u32, ErrorCode> {
        todo!()
    }

    pub fn set_multicast_loop_v6(&self, _: bool) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn multicast_loop_v6(&self) -> Result<bool, ErrorCode> {
        todo!()
    }

    pub fn join_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn join_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn leave_multicast_v4(&self, _: &Ipv4Addr, _: &Ipv4Addr) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn leave_multicast_v6(&self, _: &Ipv6Addr, _: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn set_ttl(&self, _: u32) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn ttl(&self) -> Result<u32, ErrorCode> {
        todo!()
    }

    pub fn take_error(&self) -> Result<Option<ErrorCode>, ErrorCode> {
        todo!()
    }

    pub fn set_nonblocking(&self, _: bool) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn recv(&self, _: &mut [u8]) -> Result<usize, ErrorCode> {
        todo!()
    }

    pub fn peek(&self, _: &mut [u8]) -> Result<usize, ErrorCode> {
        todo!()
    }

    pub fn send(&self, _: &[u8]) -> Result<usize, ErrorCode> {
        todo!()
    }

    pub fn connect(&self, _addr: &SocketAddr) -> Result<(), ErrorCode> {
        todo!()
    }
}

impl core::fmt::Debug for UdpSocket {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

pub struct LookupHost {
    addr: SocketAddr,
    next: Option<SocketAddr>,
}

impl LookupHost {
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    fn new(addr: SocketAddr) -> Self {
        Self {
            addr: addr.clone(),
            next: Some(addr),
        }
    }
}

impl Iterator for LookupHost {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<SocketAddr> {
        self.next.take()
    }
}

impl TryFrom<&str> for LookupHost {
    type Error = ErrorCode;

    fn try_from(v: &str) -> Result<LookupHost, ErrorCode> {
        // Split the string by ':' and convert the second part to u16.
        let (host, port_str) = v.rsplit_once(':').ok_or(ErrorCode::InvalidArgument)?;
        let port: u16 = port_str.parse().map_err(|_| ErrorCode::InvalidArgument)?;
        (host, port).try_into()
    }
}

impl<'a> TryFrom<(&'a str, u16)> for LookupHost {
    type Error = ErrorCode;

    fn try_from(host_port: (&'a str, u16)) -> Result<LookupHost, ErrorCode> {
        use core::str::FromStr;

        let (host, port) = host_port;

        if host == "localhost" {
            Ok(LookupHost::new(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                port,
            ))))
        } else if let Ok(addr_v4) = Ipv4Addr::from_str(host) {
            Ok(LookupHost::new(SocketAddr::V4(SocketAddrV4::new(
                addr_v4, port,
            ))))
        } else {
            #[cfg(debug_assertions)]
            crate::util::moturus_log!(
                "LookupHost::try_from: {}:{}: DNS lookup not implemented",
                host,
                port
            );
            Err(ErrorCode::NotImplemented)
        }
    }
}
