//! Bounded decrypted output; a parked IPC send owns one of the same slots.
use crate::config::Result;
use crate::crypto::MTU;
use moto_sdk::io::ip_device::PacketSender;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::task::{Poll, Waker};

const CAPACITY: usize = 32;

struct Packet {
    bytes: Box<[u8]>,
    length: usize,
}

pub(super) struct Queue {
    free: Vec<Box<[u8]>>,
    packets: VecDeque<Packet>,
    writer: Option<Waker>,
}

impl Queue {
    pub(super) fn new() -> Result<Rc<RefCell<Self>>> {
        let mut free: Vec<Box<[u8]>> = Vec::new();
        free.try_reserve_exact(CAPACITY)
            .map_err(|_| "cannot reserve inner output")?;
        let mut packets = VecDeque::new();
        packets
            .try_reserve_exact(CAPACITY)
            .map_err(|_| "cannot reserve inner output")?;
        for _ in 0..CAPACITY {
            free.push(crate::schedule::buffer::<MTU>()?);
        }
        Ok(Rc::new(RefCell::new(Self {
            free,
            packets,
            writer: None,
        })))
    }

    pub(super) fn submit(&mut self, packet: &[u8]) -> bool {
        let Some(mut bytes) = self.free.pop() else {
            return false;
        };
        bytes[..packet.len()].copy_from_slice(packet);
        self.packets.push_back(Packet {
            bytes,
            length: packet.len(),
        });
        if let Some(writer) = self.writer.take() {
            writer.wake();
        }
        true
    }

    pub(super) async fn write(queue: Rc<RefCell<Self>>, sender: PacketSender<'_>) -> Result<()> {
        loop {
            let packet = std::future::poll_fn(|cx| {
                let mut queue = queue.borrow_mut();
                if let Some(packet) = queue.packets.pop_front() {
                    Poll::Ready(packet)
                } else {
                    queue.writer = Some(cx.waker().clone());
                    Poll::Pending
                }
            })
            .await;
            sender
                .send(&packet.bytes[..packet.length])
                .await
                .map_err(|_| "packet-device connection failed")?;
            queue.borrow_mut().free.push(packet.bytes);
        }
    }
}
