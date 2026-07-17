extern crate std;

use core::net::IpAddr;
use core::time::Duration;

use moto_ipc::io_channel;
use moto_rt::{Error, Result};
use moto_sys::{SysCpu, SysHandle};

pub struct IcmpEchoReply {
    pub source: IpAddr,
    pub icmp_bytes: u16,
    pub rtt: Duration,
}

pub struct IcmpEchoClient {
    conn: io_channel::ClientConnection,
    next_id: u64,
}

impl IcmpEchoClient {
    pub fn connect() -> Result<Self> {
        Ok(Self {
            conn: io_channel::ClientConnection::connect("sys-io")?,
            next_id: 1,
        })
    }

    fn wait_for_server(&self) -> Result<()> {
        let mut handles = [self.conn.server_handle()];
        SysCpu::wait(&mut handles, SysHandle::NONE, SysHandle::NONE, None).map_err(Error::from)
    }

    fn send(&self, msg: io_channel::Msg) -> Result<()> {
        loop {
            match self.conn.send(msg) {
                Ok(()) => {
                    self.conn.wake_server()?;
                    return Ok(());
                }
                Err(Error::NotReady) => self.wait_for_server()?,
                Err(err) => return Err(err),
            }
        }
    }

    fn recv(&self) -> Result<io_channel::Msg> {
        loop {
            match self.conn.recv() {
                Ok(msg) => return Ok(msg),
                Err(Error::NotReady) => self.wait_for_server()?,
                Err(err) => return Err(err),
            }
        }
    }

    pub fn echo(
        &mut self,
        destination: IpAddr,
        sequence: u16,
        data_len: u16,
        timeout: Duration,
    ) -> Result<IcmpEchoReply> {
        let mut req = crate::api_net::icmp_echo_request(destination, sequence, data_len, timeout)?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == 0 {
            self.next_id = 1;
        }
        req.id = id;

        self.send(req)?;
        let resp = self.recv()?;
        if resp.id != id || resp.command != crate::api_net::NetCmd::IcmpEcho as u16 {
            return Err(Error::InvalidData);
        }

        let decoded = crate::api_net::decode_icmp_echo_response(&resp)?;
        Ok(IcmpEchoReply {
            source: decoded.source,
            icmp_bytes: data_len + 8,
            rtt: Duration::from_nanos(decoded.rtt_ns),
        })
    }
}
