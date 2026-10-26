//! Private, fixed-capacity packet storage between the netstack and IPC.
use super::stats::NetStats;
use moto_netstack::phy::{self, Device};
use moto_sdk::async_runtime::LocalNotify;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

pub(super) const QUEUE_SIZE: usize = 64;

struct Pool {
    free: Vec<Vec<u8>>,
    queued: VecDeque<(Vec<u8>, usize)>,
    ready: Rc<LocalNotify>,
    released: Option<Rc<LocalNotify>>,
    exhausted: bool,
    high_water: usize,
    allocated_bytes: u64,
    stats: Rc<NetStats>,
}

impl Pool {
    fn new(
        mtu: usize,
        ready: Rc<LocalNotify>,
        released: Option<Rc<LocalNotify>>,
        stats: Rc<NetStats>,
    ) -> std::io::Result<Self> {
        let reserve_error = |_| std::io::Error::from(std::io::ErrorKind::OutOfMemory);
        let mut free = Vec::new();
        free.try_reserve_exact(QUEUE_SIZE).map_err(reserve_error)?;
        let mut queued = VecDeque::new();
        queued
            .try_reserve_exact(QUEUE_SIZE)
            .map_err(reserve_error)?;
        for _ in 0..QUEUE_SIZE {
            let mut buffer = Vec::new();
            buffer.try_reserve_exact(mtu).map_err(reserve_error)?;
            buffer.resize(mtu, 0);
            free.push(buffer);
        }
        let allocated_bytes = (free.iter().map(Vec::capacity).sum::<usize>()
            + free.capacity() * std::mem::size_of::<Vec<u8>>()
            + queued.capacity() * std::mem::size_of::<(Vec<u8>, usize)>())
            as u64;
        stats
            .packet_buffer_bytes
            .set(stats.packet_buffer_bytes.get() + allocated_bytes);
        Ok(Self {
            free,
            queued,
            ready,
            released,
            exhausted: false,
            high_water: 0,
            allocated_bytes,
            stats,
        })
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.stats
            .packet_buffer_bytes
            .set(self.stats.packet_buffer_bytes.get() - self.allocated_bytes);
    }
}

/// Owning a token reserves a queue slot, even before it is filled. The same
/// guard holds an outbound packet while its IPC transfer waits for capacity.
pub(super) struct Token {
    buffer: Option<Vec<u8>>,
    length: usize,
    pool: Rc<RefCell<Pool>>,
}

impl Token {
    fn reserve(pool: &Rc<RefCell<Pool>>) -> Option<Self> {
        let mut state = pool.borrow_mut();
        let Some(buffer) = state.free.pop() else {
            state.exhausted = true;
            return None;
        };
        state.high_water = state.high_water.max(QUEUE_SIZE - state.free.len());
        let high_water = if state.released.is_some() {
            &state.stats.packet_tx_high_water
        } else {
            &state.stats.packet_rx_high_water
        };
        high_water.set(high_water.get().max(state.high_water as u64));
        Some(Self {
            buffer: Some(buffer),
            length: 0,
            pool: pool.clone(),
        })
    }

    fn pop(pool: &Rc<RefCell<Pool>>) -> Option<Self> {
        let (buffer, length) = pool.borrow_mut().queued.pop_front()?;
        Some(Self {
            buffer: Some(buffer),
            length,
            pool: pool.clone(),
        })
    }

    fn publish(mut self, length: usize) {
        let mut pool = self.pool.borrow_mut();
        pool.queued.push_back((self.buffer.take().unwrap(), length));
        pool.ready.notify_one();
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.buffer.as_ref().unwrap()[..self.length]
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            let mut pool = self.pool.borrow_mut();
            pool.free.push(buffer);
            if let Some(notify) = &pool.released {
                notify.notify_one();
            }
        }
    }
}

impl phy::RxToken for Token {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.bytes())
    }
}

impl phy::TxToken for Token {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, length: usize, f: F) -> R {
        let result = f(&mut self.buffer.as_mut().unwrap()[..length]);
        self.publish(length);
        result
    }
}

#[derive(Clone)]
pub(super) struct PacketDevice {
    mtu: usize,
    rx: Rc<RefCell<Pool>>,
    tx: Rc<RefCell<Pool>>,
    stats: Rc<NetStats>,
    pub(super) poll_ready: Rc<LocalNotify>,
    pub(super) tx_ready: Rc<LocalNotify>,
}

impl PacketDevice {
    pub(super) fn new(mtu: usize, stats: Rc<NetStats>) -> std::io::Result<Self> {
        if !(576..=moto_sdk::ipc::io_channel::PAGE_SIZE).contains(&mtu) {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let poll_ready = Rc::new(LocalNotify::new());
        let tx_ready = Rc::new(LocalNotify::new());
        Ok(Self {
            mtu,
            rx: Rc::new(RefCell::new(Pool::new(
                mtu,
                poll_ready.clone(),
                None,
                stats.clone(),
            )?)),
            tx: Rc::new(RefCell::new(Pool::new(
                mtu,
                tx_ready.clone(),
                Some(poll_ready.clone()),
                stats.clone(),
            )?)),
            stats,
            poll_ready,
            tx_ready,
        })
    }

    pub(super) fn submit(&self, bytes: &[u8]) {
        if bytes.len() > self.mtu {
            self.stats
                .packet_malformed
                .set(self.stats.packet_malformed.get().wrapping_add(1));
            return;
        }
        let Some(mut token) = Token::reserve(&self.rx) else {
            self.stats
                .packet_rx_dropped
                .set(self.stats.packet_rx_dropped.get().wrapping_add(1));
            return;
        };
        let private = &mut token.buffer.as_mut().unwrap()[..bytes.len()];
        private.copy_from_slice(bytes);
        if !valid_frame(private) {
            self.stats
                .packet_malformed
                .set(self.stats.packet_malformed.get().wrapping_add(1));
            return;
        }
        token.publish(bytes.len());
    }

    pub(super) fn take_outbound(&self) -> Option<Token> {
        Token::pop(&self.tx)
    }

    pub(super) fn take_exhausted(&self) -> bool {
        std::mem::take(&mut self.tx.borrow_mut().exhausted)
    }
}

impl Device for PacketDevice {
    type RxToken<'a> = Token;
    type TxToken<'a> = Token;

    fn capabilities(&self) -> phy::DeviceCapabilities {
        let mut caps = phy::DeviceCapabilities::default();
        caps.medium = phy::Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(QUEUE_SIZE);
        caps // Default software checksums; no offloads.
    }

    fn receive(&mut self, _: moto_netstack::time::Instant) -> Option<(Token, Token)> {
        if self.rx.borrow().queued.is_empty() {
            return None;
        }
        let tx = Token::reserve(&self.tx)?;
        Some((Token::pop(&self.rx).unwrap(), tx))
    }

    fn transmit(&mut self, _: moto_netstack::time::Instant) -> Option<Token> {
        Token::reserve(&self.tx)
    }
}

fn valid_frame(bytes: &[u8]) -> bool {
    match bytes.first().map(|byte| byte >> 4) {
        Some(4) if bytes.len() >= 20 => {
            let header = usize::from(bytes[0] & 15) * 4;
            let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
            header >= 20 && header <= total && total == bytes.len()
        }
        Some(6) if bytes.len() >= 40 => {
            usize::from(u16::from_be_bytes([bytes[4], bytes[5]])) + 40 == bytes.len()
        }
        _ => false,
    }
}

#[cfg(debug_assertions)]
pub(crate) mod self_test {
    use super::*;
    use crate::self_test::{SelfTest, st_assert, st_assert_eq};
    use futures::FutureExt;
    use moto_netstack::phy::{RxToken, TxToken};

    pub(crate) const TESTS: &[SelfTest] = &[(
        "net::packet_device::bounded_queues_own_storage_and_restore_capacity",
        bounded_queues_own_storage_and_restore_capacity,
    )];

    fn bounded_queues_own_storage_and_restore_capacity() -> Result<(), String> {
        let stats = Rc::new(NetStats::default());
        let mut device = PacketDevice::new(1420, stats.clone()).map_err(|e| e.to_string())?;
        st_assert!(stats.packet_buffer_bytes.get() >= (1420 * 128) as u64);
        let now = moto_netstack::time::Instant::now();
        let mut ipv4 = [0; 20];
        ipv4[0] = 0x45;
        ipv4[2..4].copy_from_slice(&20_u16.to_be_bytes());
        let mut reservations = Vec::new();
        for _ in 0..QUEUE_SIZE {
            reservations.push(device.transmit(now).unwrap());
        }
        st_assert!(device.transmit(now).is_none());
        st_assert!(device.take_exhausted());
        st_assert!(!device.take_exhausted());
        device.submit(&ipv4);
        st_assert!(device.receive(now).is_none()); // The RX reply also needs TX capacity.
        let _ = device.poll_ready.notified().now_or_never();
        let mut wake = Box::pin(device.poll_ready.notified());
        st_assert!(wake.as_mut().now_or_never().is_none());
        drop(reservations.pop());
        st_assert!(wake.now_or_never().is_some());
        let (rx, tx) = device.receive(now).unwrap();
        st_assert_eq!(RxToken::consume(rx, |bytes| bytes.to_vec()), ipv4);
        TxToken::consume(tx, ipv4.len(), |bytes| bytes.copy_from_slice(&ipv4));
        st_assert!(device.tx_ready.notified().now_or_never().is_some());
        let queued = device.take_outbound().unwrap();
        st_assert_eq!(queued.bytes(), ipv4.as_slice());
        st_assert!(device.transmit(now).is_none()); // Adapter owns the slot while sending.
        drop(queued);
        st_assert!(device.transmit(now).is_some());
        drop(reservations);
        for _ in 0..QUEUE_SIZE {
            device.submit(&ipv4);
        }
        device.submit(&ipv4);
        st_assert_eq!(stats.packet_rx_dropped.get(), 1);
        ipv4[0] = 0; // Mutating the source cannot change a queued packet.
        for _ in 0..QUEUE_SIZE {
            let (rx, tx) = device.receive(now).unwrap();
            st_assert_eq!(RxToken::consume(rx, |bytes| bytes[0]), 0x45);
            drop(tx);
        }
        st_assert!(device.receive(now).is_none());
        for packet in [&ipv4[..], &[0; 19][..], &[0; 1421][..]] {
            device.submit(packet);
        }
        st_assert_eq!(stats.packet_malformed.get(), 3);
        let mut ipv6 = [0; 40];
        ipv6[0] = 0x60;
        device.submit(&ipv6);
        let (rx, tx) = device.receive(now).unwrap();
        st_assert_eq!(RxToken::consume(rx, |bytes| bytes.len()), 40);
        drop(tx);
        ipv6[5] = 1; // Truncated payload.
        device.submit(&ipv6);
        st_assert_eq!(stats.packet_malformed.get(), 4);
        st_assert_eq!(device.rx.borrow().free.len(), QUEUE_SIZE);
        st_assert_eq!(device.tx.borrow().free.len(), QUEUE_SIZE);
        st_assert_eq!(device.rx.borrow().high_water, QUEUE_SIZE);
        st_assert_eq!(device.tx.borrow().high_water, QUEUE_SIZE);
        st_assert!(device.capabilities().checksum.ipv4.rx());
        st_assert!(device.capabilities().checksum.tcp.tx());
        st_assert_eq!(stats.packet_rx_high_water.get(), QUEUE_SIZE as u64);
        st_assert_eq!(stats.packet_tx_high_water.get(), QUEUE_SIZE as u64);
        drop(device);
        st_assert_eq!(stats.packet_buffer_bytes.get(), 0);
        Ok(())
    }
}
