use super::io_executor;
use super::rt_api;
use core::net::SocketAddr;
use core::time::Duration;
use moto_ipc::io_channel;
use moto_sys::ErrorCode;

#[derive(Debug)]
pub struct TcpStream {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    handle: u64,
}

impl TcpStream {
    // Called by the enclosing sync TcpStream when it is dropped.
    pub async fn on_drop(&mut self) {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_STREAM_DROP;
        sqe.handle = self.handle;
        let cqe = io_executor::submit(sqe).await;
        assert!(cqe.status().is_ok());
        self.handle = 0;
    }

    pub async fn connect(socket_addr: &SocketAddr) -> Result<TcpStream, ErrorCode> {
        let sqe = rt_api::net::tcp_stream_connect_request(socket_addr);
        let cqe = io_executor::submit(sqe).await;
        if cqe.status().is_err() {
            return Err(cqe.status());
        }

        Ok(Self {
            local_addr: rt_api::net::get_socket_addr(&cqe.payload)?,
            remote_addr: *socket_addr,
            handle: cqe.handle,
        })
    }

    pub async fn connect_timeout(
        socket_addr: &SocketAddr,
        timeout: Duration,
    ) -> Result<TcpStream, ErrorCode> {
        let abs_timeout = moto_sys::time::Instant::now() + timeout;
        let sqe = rt_api::net::tcp_stream_connect_timeout_request(socket_addr, abs_timeout);
        let cqe = io_executor::submit(sqe).await;
        if cqe.status().is_err() {
            return Err(cqe.status());
        }

        Ok(Self {
            local_addr: rt_api::net::get_socket_addr(&cqe.payload)?,
            remote_addr: *socket_addr,
            handle: cqe.handle,
        })
    }

    pub async fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), ErrorCode> {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_STREAM_SET_OPTION;
        sqe.handle = self.handle;
        sqe.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_READ_TIMEOUT;
        sqe.payload.args_64_mut()[1] = match timeout {
            Some(dur) => {
                let nanos = dur.as_nanos();
                if nanos > (u64::MAX as u128) {
                    u64::MAX
                } else {
                    nanos as u64
                }
            }
            None => u64::MAX,
        };
        let cqe = io_executor::submit(sqe).await;

        if cqe.status().is_ok() {
            Ok(())
        } else {
            Err(cqe.status())
        }
    }

    pub async fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<(), ErrorCode> {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_STREAM_SET_OPTION;
        sqe.handle = self.handle;
        sqe.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_WRITE_TIMEOUT;
        sqe.payload.args_64_mut()[1] = match timeout {
            Some(dur) => {
                let nanos = dur.as_nanos();
                if nanos > (u64::MAX as u128) {
                    u64::MAX
                } else {
                    nanos as u64
                }
            }
            None => u64::MAX,
        };
        let cqe = io_executor::submit(sqe).await;

        if cqe.status().is_ok() {
            Ok(())
        } else {
            Err(cqe.status())
        }
    }

    pub async fn read_timeout(&self) -> Result<Option<Duration>, ErrorCode> {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_STREAM_GET_OPTION;
        sqe.handle = self.handle;
        sqe.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_READ_TIMEOUT;
        let cqe = io_executor::submit(sqe).await;

        if cqe.status().is_ok() {
            let res = cqe.payload.args_64()[0];
            if res == u64::MAX {
                Ok(None)
            } else {
                Ok(Some(Duration::from_nanos(res)))
            }
        } else {
            Err(cqe.status())
        }
    }

    pub async fn write_timeout(&self) -> Result<Option<Duration>, ErrorCode> {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_STREAM_GET_OPTION;
        sqe.handle = self.handle;
        sqe.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_WRITE_TIMEOUT;
        let cqe = io_executor::submit(sqe).await;

        if cqe.status().is_ok() {
            let res = cqe.payload.args_64()[0];
            if res == u64::MAX {
                Ok(None)
            } else {
                Ok(Some(Duration::from_nanos(res)))
            }
        } else {
            Err(cqe.status())
        }
    }

    pub async fn peek(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        let timestamp = moto_sys::time::Instant::now().as_u64();

        let num_blocks =
            io_executor::blocks_for_buf(io_channel::IoBuffer::MAX_NUM_BLOCKS >> 1, buf.len());
        let io_buffer = io_executor::get_io_buffer(num_blocks).await;

        let sqe = rt_api::net::tcp_stream_peek_request(self.handle, io_buffer, buf.len(), timestamp);
        let cqe = io_executor::submit(sqe).await;
        if cqe.status().is_err() {
            io_executor::put_io_buffer(io_buffer).await;
            return Err(cqe.status());
        }

        assert_eq!(cqe.payload.buffers()[0], io_buffer);
        let sz_read = cqe.payload.args_64()[1] as usize;
        assert!(sz_read <= buf.len());
        io_executor::consume_io_buffer(io_buffer, &mut buf[0..sz_read]).await;
        Ok(sz_read)
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        let timestamp = moto_sys::time::Instant::now().as_u64();

        let num_blocks =
            io_executor::blocks_for_buf(io_channel::IoBuffer::MAX_NUM_BLOCKS >> 1, buf.len());
        let io_buffer = io_executor::get_io_buffer(num_blocks).await;

        let sqe = rt_api::net::tcp_stream_read_request(self.handle, io_buffer, buf.len(), timestamp);
        let cqe = io_executor::submit(sqe).await;
        if cqe.status().is_err() {
            io_executor::put_io_buffer(io_buffer).await;
            return Err(cqe.status());
        }

        assert_eq!(cqe.payload.buffers()[0], io_buffer);
        let sz_read = cqe.payload.args_64()[1] as usize;
        assert!(sz_read <= buf.len());
        io_executor::consume_io_buffer(io_buffer, &mut buf[0..sz_read]).await;
        Ok(sz_read)
    }

    pub async fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        let timestamp = moto_sys::time::Instant::now().as_u64();

        let (buffer, sz) =
            io_executor::produce_io_buffer(io_channel::IoBuffer::MAX_NUM_BLOCKS >> 1, buf).await;

        let sqe = rt_api::net::tcp_stream_write_request(self.handle, buffer, sz, timestamp);
        let cqe = io_executor::submit(sqe).await;
        if cqe.status().is_err() {
            io_executor::put_io_buffer(buffer).await;
            return Err(cqe.status());
        }

        assert_eq!(cqe.payload.buffers()[0], buffer);
        io_executor::put_io_buffer(buffer).await;
        Ok(cqe.payload.args_64()[1] as usize)
    }

    pub fn peer_addr(&self) -> Result<SocketAddr, ErrorCode> {
        Ok(self.remote_addr)
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ErrorCode> {
        Ok(self.local_addr)
    }

    pub async fn shutdown(&self, read: bool, write: bool) -> Result<(), ErrorCode> {
        assert!(read || write);

        let mut option = 0_u64;
        if read {
            option |= rt_api::net::TCP_OPTION_SHUT_RD;
        }
        if write {
            option |= rt_api::net::TCP_OPTION_SHUT_WR;
        }

        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_STREAM_SET_OPTION;
        sqe.handle = self.handle;
        sqe.payload.args_64_mut()[0] = option;
        let cqe = io_executor::submit(sqe).await;

        if cqe.status().is_ok() {
            Ok(())
        } else {
            Err(cqe.status())
        }
    }

    pub async fn set_nodelay(&self, nodelay: bool) -> Result<(), ErrorCode> {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_STREAM_SET_OPTION;
        sqe.handle = self.handle;
        sqe.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_NODELAY;
        sqe.payload.args_64_mut()[1] = if nodelay { 1 } else { 0 };
        let cqe = io_executor::submit(sqe).await;

        if cqe.status().is_ok() {
            Ok(())
        } else {
            Err(cqe.status())
        }
    }

    pub async fn nodelay(&self) -> Result<bool, ErrorCode> {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_STREAM_GET_OPTION;
        sqe.handle = self.handle;
        sqe.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_NODELAY;
        let cqe = io_executor::submit(sqe).await;

        if cqe.status().is_ok() {
            let res = cqe.payload.args_64()[0];
            if res == 1 {
                Ok(true)
            } else if res == 0 {
                Ok(false)
            } else {
                panic!("Unexpected nodelay value: {}", res)
            }
        } else {
            Err(cqe.status())
        }
    }

    pub async fn set_ttl(&self, ttl: u32) -> Result<(), ErrorCode> {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_STREAM_SET_OPTION;
        sqe.handle = self.handle;
        sqe.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_TTL;
        sqe.payload.args_32_mut()[2] = ttl;
        let cqe = io_executor::submit(sqe).await;

        if cqe.status().is_ok() {
            Ok(())
        } else {
            Err(cqe.status())
        }
    }

    pub async fn ttl(&self) -> Result<u32, ErrorCode> {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_STREAM_GET_OPTION;
        sqe.handle = self.handle;
        sqe.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_TTL;
        let cqe = io_executor::submit(sqe).await;

        if cqe.status().is_ok() {
            Ok(cqe.payload.args_32()[0])
        } else {
            Err(cqe.status())
        }
    }

    pub async fn set_nonblocking(&self, nonblocking: bool) -> Result<(), ErrorCode> {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_STREAM_SET_OPTION;
        sqe.handle = self.handle;
        sqe.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_NONBLOCKING;
        sqe.payload.args_64_mut()[1] = if nonblocking { 1 } else { 0 };
        let cqe = io_executor::submit(sqe).await;

        if cqe.status().is_ok() {
            Ok(())
        } else {
            Err(cqe.status())
        }
    }
}

#[derive(Debug)]
pub struct TcpListener {
    pub socket_addr: SocketAddr,
    pub handle: u64,
}

impl TcpListener {
    // Called by the enclosing sync TcpListener when it is dropped.
    pub async fn on_drop(&mut self) {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_LISTENER_DROP;
        sqe.handle = self.handle;
        let cqe = io_executor::submit(sqe).await;
        assert!(cqe.status().is_ok());
        self.handle = 0;
    }

    pub async fn bind(socket_addr: &SocketAddr) -> Result<TcpListener, ErrorCode> {
        let sqe = rt_api::net::bind_tcp_listener_request(socket_addr);
        let cqe = io_executor::submit(sqe).await;
        if cqe.status().is_err() {
            return Err(cqe.status());
        }

        Ok(Self {
            socket_addr: *socket_addr,
            handle: cqe.handle,
        })
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ErrorCode> {
        Ok(self.socket_addr)
    }

    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr), ErrorCode> {
        let sqe = rt_api::net::accept_tcp_listener_request(self.handle);
        let cqe = io_executor::submit(sqe).await;
        if cqe.status().is_err() {
            return Err(cqe.status());
        }

        let remote_addr = rt_api::net::get_socket_addr(&cqe.payload).unwrap();

        Ok((
            TcpStream {
                local_addr: self.socket_addr,
                remote_addr,
                handle: cqe.handle,
            },
            remote_addr,
        ))
    }

    pub async fn set_ttl(&self, ttl: u32) -> Result<(), ErrorCode> {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_LISTENER_SET_OPTION;
        sqe.handle = self.handle;
        sqe.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_TTL;
        sqe.payload.args_32_mut()[2] = ttl;
        let cqe = io_executor::submit(sqe).await;

        if cqe.status().is_ok() {
            Ok(())
        } else {
            Err(cqe.status())
        }
    }

    pub async fn ttl(&self) -> Result<u32, ErrorCode> {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_LISTENER_GET_OPTION;
        sqe.handle = self.handle;
        sqe.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_TTL;
        let cqe = io_executor::submit(sqe).await;

        if cqe.status().is_ok() {
            Ok(sqe.payload.args_32()[0])
        } else {
            Err(cqe.status())
        }
    }

    pub async fn set_nonblocking(&self, nonblocking: bool) -> Result<(), ErrorCode> {
        let mut sqe = io_channel::QueueEntry::new();
        sqe.command = rt_api::net::CMD_TCP_LISTENER_SET_OPTION;
        sqe.handle = self.handle;
        sqe.payload.args_64_mut()[0] = rt_api::net::TCP_OPTION_NONBLOCKING;
        sqe.payload.args_64_mut()[1] = if nonblocking { 1 } else { 0 };
        let cqe = io_executor::submit(sqe).await;

        if cqe.status().is_ok() {
            Ok(())
        } else {
            Err(cqe.status())
        }
    }
}

/*
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
*/
