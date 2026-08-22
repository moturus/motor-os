use std::collections::VecDeque;

use crate::iface::*;
use crate::phy::{self, Device, DeviceCapabilities, Medium, PacketMeta};
use crate::time::Instant;
use crate::wire::*;

pub(crate) fn setup<'a>(medium: Medium) -> (Interface, SocketSet<'a>, TestingDevice) {
    let mut device = TestingDevice::new(medium);

    let mut config = Config::new(match medium {
        #[cfg(feature = "medium-ethernet")]
        Medium::Ethernet => {
            HardwareAddress::Ethernet(EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]))
        }
        #[cfg(feature = "medium-ip")]
        Medium::Ip => HardwareAddress::Ip,
        #[cfg(feature = "medium-ieee802154")]
        Medium::Ieee802154 => HardwareAddress::Ieee802154(Ieee802154Address::Extended([
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        ])),
    });
    config.auto_icmp_echo_reply = true;
    // The fixture owns 127.0.0.1/8 below and several tests deliver traffic to
    // it, so it stands in for a loopback interface as well as an ordinary one.
    // Saying so keeps ingress from dropping that traffic; the tests that want
    // the drop build their own interface.
    #[cfg(feature = "proto-ipv4")]
    {
        config.loopback = true;
    }

    let mut iface = Interface::new(config, &mut device, Instant::ZERO);

    #[cfg(feature = "proto-ipv4")]
    {
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs.push(IpCidr::new(IpAddress::v4(192, 168, 1, 1), 24));
            ip_addrs.push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8));
        });
    }

    #[cfg(feature = "proto-ipv6")]
    {
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs.push(IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64));
            ip_addrs.push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128));
            ip_addrs.push(IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64));
        });
    }

    (iface, SocketSet::new(), device)
}

/// A testing device.
#[derive(Debug)]
pub struct TestingDevice {
    pub(crate) tx_queue: VecDeque<Vec<u8>>,
    pub(crate) rx_queue: VecDeque<(Vec<u8>, PacketMeta)>,
    /// When set, `transmit()` refuses once `tx_queue` holds this many
    /// frames, the way a full TX ring does.
    pub(crate) tx_capacity: Option<usize>,
    max_transmission_unit: usize,
    medium: Medium,
}

#[allow(clippy::new_without_default)]
impl TestingDevice {
    /// Creates a testing device.
    ///
    /// Every packet transmitted through this device will be received through it
    /// in FIFO order.
    pub fn new(medium: Medium) -> Self {
        TestingDevice {
            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),
            tx_capacity: None,
            max_transmission_unit: match medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => 1514,
                #[cfg(feature = "medium-ip")]
                Medium::Ip => 1500,
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => 1500,
            },
            medium,
        }
    }

    #[cfg(all(feature = "medium-ip", feature = "proto-ipv6"))]
    pub(crate) fn set_mtu(&mut self, mtu: usize) {
        self.max_transmission_unit = mtu;
    }

    /// Queues a frame for reception, with no device vouching for its L4
    /// checksum. This is what an ordinary peer's frame looks like.
    pub(crate) fn push_rx(&mut self, buffer: Vec<u8>) {
        self.rx_queue.push_back((buffer, PacketMeta::default()));
    }

    /// Queues a frame for reception carrying the device's L4 checksum verdict,
    /// the way a virtio-net header's flags do; see
    /// [`PacketMeta::l4_csum_vouched`].
    pub(crate) fn push_rx_vouched(&mut self, buffer: Vec<u8>, vouched: bool) {
        self.rx_queue
            .push_back((buffer, PacketMeta::default().with_l4_csum_vouched(vouched)));
    }
}

impl Device for TestingDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            medium: self.medium,
            max_transmission_unit: self.max_transmission_unit,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue.pop_front().map(move |(buffer, meta)| {
            let rx = RxToken { buffer, meta };
            let tx = TxToken {
                queue: &mut self.tx_queue,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if let Some(cap) = self.tx_capacity
            && self.tx_queue.len() >= cap
        {
            return None;
        }
        Some(TxToken {
            queue: &mut self.tx_queue,
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
    meta: PacketMeta,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }

    fn meta(&self) -> PacketMeta {
        self.meta
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}
