//! Bounded raw-IP queues shared by the encrypted and baseline transports.
use moto_netstack::phy::{self, Device, DeviceCapabilities, Medium};
use moto_netstack::time::Instant;
use std::collections::VecDeque;

pub const MTU: usize = 1420;
const QUEUE_LIMIT: usize = 64;

#[derive(Default)]
pub struct Link {
    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
}

impl Link {
    /// Transport input is untrusted, including in the unencrypted test mode.
    pub fn receive_packet(&mut self, packet: &[u8]) -> bool {
        if packet.is_empty() || packet.len() > MTU || self.input.len() == QUEUE_LIMIT {
            return false;
        }
        self.input.push_back(packet.to_vec());
        true
    }

    pub fn take_packet(&mut self) -> Option<Vec<u8>> {
        self.output.pop_front()
    }
}

impl Device for Link {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU;
        capabilities
    }

    fn receive(&mut self, _: Instant) -> Option<(Rx, Tx<'_>)> {
        if self.output.len() == QUEUE_LIMIT {
            return None;
        }
        let packet = self.input.pop_front()?;
        Some((Rx(packet), Tx(&mut self.output)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        (self.output.len() < QUEUE_LIMIT).then_some(Tx(&mut self.output))
    }
}

pub struct Rx(Vec<u8>);

impl phy::RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

pub struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        assert!(len <= MTU);
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phy::{RxToken, TxToken};

    #[test]
    fn bounded_queues_resume_after_output_drains() {
        let mut link = Link::default();
        let now = Instant::from_millis(0);
        assert!(!link.receive_packet(&[]));
        assert!(!link.receive_packet(&[0; MTU + 1]));
        for value in 0..QUEUE_LIMIT {
            assert!(link.receive_packet(&[value as u8]));
            link.transmit(now)
                .unwrap()
                .consume(1, |bytes| bytes[0] = value as u8);
        }
        assert!(!link.receive_packet(&[0]));
        assert!(link.transmit(now).is_none());
        assert!(link.receive(now).is_none()); // Receiving needs a reply token.
        for value in 0..QUEUE_LIMIT {
            assert_eq!(link.take_packet().unwrap(), [value as u8]);
            let (rx, _) = link.receive(now).unwrap();
            rx.consume(|bytes| assert_eq!(bytes, [value as u8]));
        }
        assert!(link.take_packet().is_none());
        assert!(link.receive(now).is_none());
        assert!(link.receive_packet(&[7; MTU]));
        let (rx, tx) = link.receive(now).unwrap();
        rx.consume(|bytes| assert_eq!(bytes, [7; MTU]));
        tx.consume(MTU, |bytes| bytes.fill(9));
        assert_eq!(link.take_packet().unwrap(), [9; MTU]);
    }
}
