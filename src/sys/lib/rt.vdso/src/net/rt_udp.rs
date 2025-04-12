use core::net::SocketAddr;
use core::sync::atomic::*;
use moto_sys_io::api_net;
use moto_sys_io::api_net::IO_SUBCHANNELS;

use alloc::sync::{Arc, Weak};
use moto_rt::{mutex::Mutex, ErrorCode};

use crate::{posix::PosixFile, runtime::WaitObject};

use super::rt_net::{ChannelReservation, NetChannel};

pub struct UdpSocket {
    channel_reservation: ChannelReservation,
    local_addr: SocketAddr,
    handle: u64,
    wait_object: WaitObject,
    nonblocking: AtomicBool,
    subchannel_mask: u64, // Never changes.
    me: Weak<UdpSocket>,
}

impl UdpSocket {
    pub fn handle(&self) -> u64 {
        self.handle
    }

    pub fn weak(&self) -> Weak<Self> {
        self.me.clone()
    }

    fn channel(&self) -> &NetChannel {
        self.channel_reservation.channel()
    }

    pub fn bind(socket_addr: &SocketAddr) -> Result<Arc<UdpSocket>, ErrorCode> {
        let mut socket_addr = *socket_addr;
        if socket_addr.port() == 0 && socket_addr.ip().is_unspecified() {
            crate::moto_log!("we don't currently allow binding to 0.0.0.0:0");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut channel_reservation = super::rt_net::reserve_channel();
        channel_reservation.reserve_subchannel();
        let subchannel_mask = channel_reservation.subchannel_mask();
        let req =
            api_net::bind_udp_socket_request(&socket_addr, channel_reservation.subchannel_idx());
        let resp = channel_reservation.channel().send_receive(req);
        if resp.status() != moto_rt::E_OK {
            return Err(resp.status());
        }

        if socket_addr.port() == 0 {
            let actual_addr = api_net::get_socket_addr(&resp.payload);
            assert_eq!(socket_addr.ip(), actual_addr.ip());
            assert_ne!(0, actual_addr.port());
            socket_addr.set_port(actual_addr.port());
        }

        let udp_socket = Arc::new_cyclic(|me| UdpSocket {
            local_addr: socket_addr,
            channel_reservation,
            handle: resp.handle,
            nonblocking: AtomicBool::new(false),
            wait_object: WaitObject::new(moto_rt::poll::POLL_READABLE),
            subchannel_mask,
            me: me.clone(),
        });
        udp_socket.channel().udp_socket_created(&udp_socket);
        crate::net::rt_net::stats_udp_socket_created();

        #[cfg(debug_assertions)]
        crate::moto_log!(
            "{}:{} new UdpSocket {:?}",
            file!(),
            line!(),
            udp_socket.local_addr
        );

        Ok(udp_socket)
    }
}

impl PosixFile for UdpSocket {}
