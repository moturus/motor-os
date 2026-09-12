//! Exercise the real queue with a memory-backed device, without touching hardware.
use super::*;
use std::cell::Cell;
use std::pin::Pin;
use std::task::{Context, ContextBuilder, LocalWake, LocalWaker, Poll, Waker};

struct Device {
    queue: Rc<RefCell<Virtqueue>>,
    // Keep the ring storage alive until after the queue and its references drop.
    _memory: IoBuf,
}

impl Device {
    fn new() -> Self {
        const SIZE: u16 = 8;
        let memory = IoBuf::new_from_size_align(4096).unwrap();
        let addr = memory.raw_ptr() as u64;
        // SAFETY: the owned, aligned page contains all three non-overlapping
        // rings. No device accesses it; this fixture outlives every completion.
        let descriptors = unsafe {
            std::ptr::write_bytes(addr as *mut u8, 0, 4096);
            std::slice::from_raw_parts_mut(addr as *mut VirtqDesc, SIZE as usize)
        };
        for (idx, desc) in descriptors.iter_mut().enumerate() {
            desc.next = (idx as u16 + 1) % SIZE;
        }
        let used_ring = VirtqUsed::from_addr(addr, SIZE);
        *used_ring.flags = 1; // Suppress doorbells; there is no PCI device.
        let header_buffers = (0..SIZE)
            .map(|_| HeaderBuffer {
                buf: IoBuf::new_from_size_align(16).unwrap(),
                consumed: 0,
                in_use_by_device: false,
                in_use_by_completion: false,
            })
            .collect();
        let queue = Virtqueue {
            virt_addr: addr,
            queue_size: SIZE,
            queue_num: 0,
            queue_notify_off: 0,
            device_kind: crate::VirtioDeviceKind::Block,
            descriptors,
            available_ring: VirtqAvail::from_addr(addr, SIZE),
            used_ring,
            free_head_idx: 0,
            next_used_idx: 0,
            wait_handle: SysHandle::NONE,
            header_buffers,
            notify_bar: std::ptr::null(),
            notify_offset: 0,
            queue_size_mask: SIZE - 1,
            last_kick_idx: 0,
            alloc_waiters: VecDeque::new(),
            completion_waiters: vec![None; SIZE as usize],
            virtio_f_event_idx_negotiated: false,
        };
        Self {
            queue: Rc::new(RefCell::new(queue)),
            _memory: memory,
        }
    }

    fn alloc(&self, len: u16) -> VqAlloc {
        VqAlloc::new(self.queue.clone(), len)
    }

    fn submit(&self, head: u16, len: u16, value: u32) -> VqCompletion<u32> {
        let data = vec![
            UserData {
                phys_addr: 0,
                len: 1
            };
            len as usize
        ];
        let completion = Virtqueue::add_buffs(self.queue.clone(), &data, len - 1, 1, head, value);
        let block = matches!(
            self.queue.borrow().device_kind,
            crate::VirtioDeviceKind::Block
        );
        if block {
            completion.expect_blk_status()
        } else {
            completion
        }
    }

    fn complete(&self, head: u16, consumed: u32, status: u8) {
        let mut queue = self.queue.borrow_mut();
        let mut tail = head;
        while queue.get_descriptor(tail).flags & VIRTQ_DESC_F_NEXT != 0 {
            tail = queue.get_descriptor(tail).next;
        }
        // SAFETY: aligned status storage belongs to this simulated device.
        unsafe {
            (queue.header_buffers[tail as usize].buf.raw_ptr_mut() as *mut u64)
                .write_volatile(status as u64);
            let idx = queue.used_ring.idx.read_volatile();
            let slot = (idx & queue.queue_size_mask) as usize;
            queue.used_ring.ring[slot] = VirtqUsedElem {
                id: head as u32,
                len: consumed,
            };
            (queue.used_ring.idx as *mut u16).write_volatile(idx.wrapping_add(1));
        }
    }

    fn reclaim(&self) {
        while self.queue.borrow_mut().reclaim_used().is_some() {}
    }
}

#[derive(Default)]
struct WakeCount(Cell<usize>);

impl LocalWake for WakeCount {
    fn wake(self: Rc<Self>) {
        self.0.set(self.0.get() + 1);
    }
}

fn poll_alloc(alloc: &mut VqAlloc, waker: &LocalWaker) -> Poll<u16> {
    let mut cx = ContextBuilder::from_waker(Waker::noop())
        .local_waker(waker)
        .build();
    Pin::new(alloc).poll(&mut cx)
}

fn ready_head(device: &Device, len: u16) -> u16 {
    match poll_alloc(&mut device.alloc(len), LocalWaker::noop()) {
        Poll::Ready(head) => head,
        Poll::Pending => panic!("expected enough free descriptors"),
    }
}

pub fn test_descriptor_waiters() {
    test_exhausted_self_link();
    test_mixed_chains();
    for block in [false, true] {
        let device = Device::new();
        if !block {
            device.queue.borrow_mut().device_kind = crate::VirtioDeviceKind::Net;
        }
        {
            let mut queue = device.queue.borrow_mut();
            queue.next_used_idx = u16::MAX;
            // SAFETY: the fixture owns the simulated device's ring.
            unsafe {
                (queue.used_ring.idx as *mut u16).write_volatile(u16::MAX);
            }
        }
        for status in [0, 1, 2] {
            let mut request = device.submit(ready_head(&device, 3), 3, 7);
            let first = Rc::new(WakeCount::default());
            let second = Rc::new(WakeCount::default());
            let first_waker = LocalWaker::from(first.clone());
            let second_waker = LocalWaker::from(second.clone());
            let mut first_cx = ContextBuilder::from_waker(Waker::noop())
                .local_waker(&first_waker)
                .build();
            let mut second_cx = ContextBuilder::from_waker(Waker::noop())
                .local_waker(&second_waker)
                .build();
            assert!(request.do_poll(&mut first_cx).is_pending());
            assert!(request.do_poll(&mut second_cx).is_pending());
            device.complete(request.chain_head, 23, status);
            device.reclaim();
            assert_eq!(first.0.get(), 0);
            assert_eq!(second.0.get(), 1);
            // The task design keeps descriptors until it drops the completion.
            assert!(
                device
                    .queue
                    .borrow_mut()
                    .alloc_descriptor_chain(6)
                    .is_none()
            );
            let Poll::Ready((data, result)) = request.do_poll(&mut second_cx) else {
                panic!("completed request was pending")
            };
            assert_eq!(data, 7);
            if block && status != 0 {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), 23);
            }
            drop(request);
            let full = device.submit(ready_head(&device, 8), 8, 8);
            device.complete(full.chain_head, 0, 0);
            drop(full);
        }
    }
}

fn test_exhausted_self_link() {
    let device = Device::new();
    let first = device.submit(ready_head(&device, 2), 2, 0);
    let second = device.submit(ready_head(&device, 2), 2, 0);
    for request in [first, second] {
        device.complete(request.chain_head, 0, 0);
        drop(request);
    }
    let first = device.submit(ready_head(&device, 3), 3, 0);
    let second = device.submit(ready_head(&device, 3), 3, 0);
    let third = device.submit(ready_head(&device, 2), 2, 0);
    device.complete(first.chain_head, 0, 0);
    drop(first);
    // The three free slots end in a self-link. Exhaustion must roll back
    // those three marks without disturbing either device-owned request.
    assert!(poll_alloc(&mut device.alloc(4), LocalWaker::noop()).is_pending());
    for request in [second, third] {
        device.complete(request.chain_head, 0, 0);
        drop(request);
    }
    let full = device.submit(ready_head(&device, 8), 8, 0);
    device.complete(full.chain_head, 0, 0);
    drop(full);
}

fn test_mixed_chains() {
    struct Request {
        completion: VqCompletion<u32>,
        descriptors: Vec<u16>,
        value: u32,
    }

    let device = Device::new();
    let mut pending: Vec<Request> = Vec::new();
    let mut finished = Vec::new();
    let mut random = 0xd1b54a32d192ed03u64;
    let mut cx = Context::from_waker(Waker::noop());
    for value in 0..2000u32 {
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        match random % 3 {
            0 => {
                let len = 2 + ((random >> 8) % 7) as u16;
                let in_use: usize = pending
                    .iter()
                    .chain(&finished)
                    .map(|r| r.descriptors.len())
                    .sum();
                let head = match poll_alloc(&mut device.alloc(len), LocalWaker::noop()) {
                    Poll::Ready(head) => {
                        assert!(in_use + len as usize <= 8);
                        head
                    }
                    Poll::Pending => {
                        assert!(in_use + len as usize > 8);
                        continue;
                    }
                };
                let mut descriptors = Vec::new();
                let mut curr = head;
                for _ in 0..len {
                    assert!(!descriptors.contains(&curr));
                    assert!(
                        pending
                            .iter()
                            .chain(&finished)
                            .all(|r| !r.descriptors.contains(&curr))
                    );
                    descriptors.push(curr);
                    curr = device.queue.borrow().get_descriptor(curr).next;
                }
                pending.push(Request {
                    completion: device.submit(head, len, value),
                    descriptors,
                    value,
                });
            }
            1 if !pending.is_empty() => {
                let request = pending.swap_remove((random >> 8) as usize % pending.len());
                device.complete(request.completion.chain_head, request.value + 4096, 0);
                device.reclaim();
                finished.push(request);
            }
            2 if !finished.is_empty() => {
                let mut request = finished.swap_remove((random >> 8) as usize % finished.len());
                if value.is_multiple_of(2) {
                    let Poll::Ready((data, result)) = request.completion.do_poll(&mut cx) else {
                        panic!("completed mixed-chain request lost its result");
                    };
                    assert_eq!(data, request.value);
                    assert_eq!(result.unwrap(), request.value + 4096);
                }
                // Half of the finished requests drop without ever being polled.
                drop(request);
            }
            _ => {}
        }
    }
    for request in pending {
        device.complete(request.completion.chain_head, request.value + 4096, 0);
        device.reclaim();
        finished.push(request);
    }
    for mut request in finished {
        let Poll::Ready((data, result)) = request.completion.do_poll(&mut cx) else {
            panic!("mixed-chain drain lost a result");
        };
        assert_eq!(data, request.value);
        assert_eq!(result.unwrap(), request.value + 4096);
    }
    let full = device.submit(ready_head(&device, 8), 8, 0);
    device.complete(full.chain_head, 0, 0);
    drop(full);
}

/// Run in a child process: dropping an unfinished DMA owner must abort.
pub fn test_premature_completion_drop(block: bool) {
    let device = Device::new();
    if !block {
        device.queue.borrow_mut().device_kind = crate::VirtioDeviceKind::Net;
    }
    let completion = device.submit(ready_head(&device, 3), 3, 0);
    drop(completion);
    panic!("premature completion drop was accepted");
}
