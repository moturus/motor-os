//! A dedicated, process-owned IP interface. Dropping it closes its channel.
use crate::ipc::io_channel::{self, IoPage, Msg, Receiver, Sender};
use crate::sys_io::{api_ip_device as api, api_net::NetCmd};
use core::task::{Context, Poll};
use moto_rt::{Error, Result};

pub struct IpDevice {
    sender: Sender,
    receiver: Receiver,
    mtu: usize,
}

pub struct PacketSender<'a> {
    sender: &'a Sender,
    mtu: usize,
}

pub struct PacketReceiver<'a> {
    receiver: &'a mut Receiver,
    mtu: usize,
}

impl IpDevice {
    /// Cancellation closes both channel halves, including while waiting for
    /// the registration reply. No partial registration outlives that channel.
    pub async fn register(config: &api::Registration) -> Result<Self> {
        config.validate()?;
        let (sender, mut receiver) = io_channel::connect("sys-io").map_err(connection_error)?;
        let page = sender
            .alloc_page(u64::MAX)
            .await
            .map_err(connection_error)?;
        let length = config.encode(page.bytes_mut())?;
        let page = IoPage::into_u16(page);
        let request = api::page_message(NetCmd::IpDeviceRegister, page, length)?;
        sender
            .send_with_owned_page(request, page)
            .await
            .map_err(connection_error)?;
        control_reply(&receiver.recv().await.map_err(connection_error)?, &request)?;
        Ok(Self {
            sender,
            receiver,
            mtu: config.mtu as usize,
        })
    }

    /// Borrow both directions for concurrent transfer. Neither half can
    /// outlive the owner or keep a dropped device registered.
    pub fn split(&mut self) -> (PacketSender<'_>, PacketReceiver<'_>) {
        (
            PacketSender {
                sender: &self.sender,
                mtu: self.mtu,
            },
            PacketReceiver {
                receiver: &mut self.receiver,
                mtu: self.mtu,
            },
        )
    }

    /// Terminal: consume the owner and drain any previously queued packets
    /// until sys-io confirms resource retirement. Cancellation closes it too.
    pub async fn unregister(mut self) -> Result<()> {
        let request = api::unregister_request();
        self.sender.send(request).await.map_err(connection_error)?;
        loop {
            let msg = self.receiver.recv().await.map_err(connection_error)?;
            if msg.command == NetCmd::IpDevicePacket.as_u16() {
                let _length = packet_length(&msg, self.mtu)?;
                drop(
                    self.receiver
                        .get_remote_page(msg.payload.shared_pages()[11])?,
                );
            } else {
                return control_reply(&msg, &request);
            }
        }
    }
}

impl PacketSender<'_> {
    pub async fn send(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() || packet.len() > self.mtu {
            return Err(Error::InvalidArgument);
        }
        let page = self
            .sender
            .alloc_page(u64::MAX)
            .await
            .map_err(connection_error)?;
        page.bytes_mut()[..packet.len()].copy_from_slice(packet);
        let page = IoPage::into_u16(page);
        let msg = api::page_message(NetCmd::IpDevicePacket, page, packet.len())?;
        self.sender
            .send_with_owned_page(msg, page)
            .await
            .map_err(connection_error)
    }
}

impl PacketReceiver<'_> {
    pub fn poll_receive(&mut self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<Result<usize>> {
        let msg = core::task::ready!(self.receiver.poll_recv(cx)).map_err(connection_error)?;
        let length = packet_length(&msg, self.mtu)?;
        let page = self
            .receiver
            .get_remote_page(msg.payload.shared_pages()[11])?;
        if length > bytes.len() {
            return Poll::Ready(Err(Error::InvalidArgument));
        }
        bytes[..length].copy_from_slice(&page.bytes()[..length]);
        Poll::Ready(Ok(length))
    }

    pub async fn receive(&mut self, bytes: &mut [u8]) -> Result<usize> {
        core::future::poll_fn(|cx| self.poll_receive(cx, bytes)).await
    }
}

fn packet_length(msg: &Msg, mtu: usize) -> Result<usize> {
    let length = api::page_length(msg)?;
    if msg.command != NetCmd::IpDevicePacket.as_u16() || msg.id != 0 || length > mtu {
        return Err(Error::InvalidData);
    }
    Ok(length)
}

fn control_reply(reply: &Msg, request: &Msg) -> Result<()> {
    if reply.id != request.id
        || reply.command != request.command
        || reply.handle != 0
        || reply.wake_handle != 0
        || reply.flags != 0
        || reply.payload.args_8().iter().any(|byte| *byte != 0)
    {
        return Err(Error::InvalidData);
    }
    reply.status()
}

// The kernel's wait/wake path reports a closed peer as a bad IPC handle.
// A provider sees a terminal connection error, as other native net clients do.
fn connection_error(error: Error) -> Error {
    if error == Error::BadHandle {
        Error::NotConnected
    } else {
        error
    }
}
