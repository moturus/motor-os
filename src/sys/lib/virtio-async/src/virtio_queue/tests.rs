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
    fn new(device_kind: crate::VirtioDeviceKind) -> Self {
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
            .map(|_| HeaderBuffer::new(device_kind).unwrap())
            .collect();
        let queue = Virtqueue {
            virt_addr: addr,
            queue_size: SIZE,
            queue_num: 0,
            queue_notify_off: 0,
            device_kind,
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
        self.complete_raw(u32::from(head), consumed, status);
    }

    fn complete_raw(&self, raw_head: u32, consumed: u32, status: u8) {
        let mut queue = self.queue.borrow_mut();
        if raw_head < u32::from(queue.queue_size) {
            let mut tail = raw_head as u16;
            while queue.get_descriptor(tail).flags & VIRTQ_DESC_F_NEXT != 0 {
                tail = queue.get_descriptor(tail).next;
            }
            // SAFETY: aligned status storage belongs to this simulated device.
            unsafe {
                (queue.header_buffers[tail as usize].buf.raw_ptr_mut() as *mut u64)
                    .write_volatile(status as u64);
            }
        }
        // SAFETY: the fixture owns the simulated device's ring.
        unsafe {
            let idx = queue.used_ring.idx.read_volatile();
            let slot = (idx & queue.queue_size_mask) as usize;
            queue.used_ring.ring[slot] = VirtqUsedElem {
                id: raw_head,
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
    test_used_id_boundary();
    test_header_buffers();
    test_vsock_tx();
    test_exhausted_self_link();
    test_mixed_chains();
    for block in [false, true] {
        let kind = if block {
            crate::VirtioDeviceKind::Block
        } else {
            crate::VirtioDeviceKind::Net
        };
        let device = Device::new(kind);
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

fn test_used_id_boundary() {
    let device = Device::new(crate::VirtioDeviceKind::Vsock);
    device.queue.borrow_mut().free_head_idx = 7;
    let mut completion = device.submit(ready_head(&device, 1), 1, 7);
    assert_eq!(completion.chain_head, device.queue.borrow().queue_size - 1);
    device.complete(completion.chain_head, 9, 0);
    device.reclaim();
    let mut cx = Context::from_waker(Waker::noop());
    let Poll::Ready((value, result)) = completion.do_poll(&mut cx) else {
        panic!("valid boundary used ID was not reclaimed")
    };
    assert_eq!(value, 7);
    assert_eq!(result.unwrap(), 9);
}

fn test_exhausted_self_link() {
    let device = Device::new(crate::VirtioDeviceKind::Block);
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

    let device = Device::new(crate::VirtioDeviceKind::Block);
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
    let kind = if block {
        crate::VirtioDeviceKind::Block
    } else {
        crate::VirtioDeviceKind::Net
    };
    let device = Device::new(kind);
    let completion = device.submit(ready_head(&device, 3), 3, 0);
    drop(completion);
    panic!("premature completion drop was accepted");
}

/// Run in a child process because Motor OS panics abort the process.
pub fn test_used_id_rejection(case: &str) {
    let device = Device::new(crate::VirtioDeviceKind::Vsock);
    let completion = device.submit(ready_head(&device, 1), 1, 0);
    let raw_head = match case {
        "queue-size" => u32::from(device.queue.borrow().queue_size),
        "u16-wrap" => 0x1_0000,
        "u32-max" => u32::MAX,
        _ => panic!("unknown used-ID rejection case"),
    };
    device.complete_raw(raw_head, 0, 0);
    device.reclaim();
    drop(completion);
    panic!("invalid used ID was accepted");
}

fn test_header_buffers() {
    for (kind, expected) in [
        (crate::VirtioDeviceKind::Block, 16),
        (crate::VirtioDeviceKind::Net, 16),
        (crate::VirtioDeviceKind::Vsock, 64),
    ] {
        let device = Device::new(kind);
        assert!(
            device
                .queue
                .borrow()
                .header_buffers
                .iter()
                .all(|header| header.buf.capacity() == expected)
        );
        let head = ready_head(&device, 1);
        let phys_addr = {
            let mut queue = device.queue.borrow_mut();
            let (header, phys_addr, _) = queue.get_buffer::<u64>(head);
            *header = 0;
            phys_addr
        };
        let completion = Virtqueue::add_buffs(
            device.queue.clone(),
            &[UserData { phys_addr, len: 8 }],
            0,
            1,
            head,
            (),
        );
        device.complete(head, 8, expected as u8);
        device.reclaim();
        assert_eq!(completion.read_header::<u64>(), expected as u64);
    }

    let device = Device::new(crate::VirtioDeviceKind::Vsock);
    let head = ready_head(&device, 1);
    let expected = crate::virtio_vsock::WireHeader::default();
    let phys_addr = {
        let mut queue = device.queue.borrow_mut();
        let (header, phys_addr, _) = queue.get_buffer::<crate::virtio_vsock::WireHeader>(head);
        *header = expected;
        phys_addr
    };
    let completion = Virtqueue::add_buffs(
        device.queue.clone(),
        &[UserData {
            phys_addr,
            len: crate::virtio_vsock::HEADER_LEN as u32,
        }],
        0,
        1,
        head,
        (),
    );
    device.complete(head, crate::virtio_vsock::HEADER_LEN as u32, 0);
    device.reclaim();
    assert_eq!(
        completion.read_header::<crate::virtio_vsock::WireHeader>(),
        expected
    );
}

fn test_vsock_tx() {
    use crate::virtio_vsock::{RawHeader, try_post_tx, validate_payload_dma};

    let device = Device::new(crate::VirtioDeviceKind::Vsock);
    let reset = RawHeader {
        src_cid: 0x7856_3412,
        dst_cid: 2,
        src_port: 0x0403_0201,
        dst_port: 0x0807_0605,
        len: 0,
        socket_type: 0x0201,
        operation: 3,
        flags: 0,
        buf_alloc: 0x4433_2211,
        fwd_cnt: 0x8877_6655,
    };
    let control = match try_post_tx(device.queue.clone(), reset, None) {
        Ok(completion) => completion,
        Err(_) => panic!("valid header-only vsock TX was rejected"),
    };
    let head = control.vq_completion.chain_head;
    let queue = device.queue.borrow();
    let descriptor = queue.get_descriptor(head);
    assert_eq!(
        descriptor.addr,
        queue.header_buffers[head as usize].buf.phys_addr() as u64
    );
    assert_eq!(descriptor.len, 44);
    assert_eq!(descriptor.flags, 0);
    assert_eq!(
        &<IoBuf as AsRef<[u8]>>::as_ref(&queue.header_buffers[head as usize].buf)[..44],
        &[
            0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0,
            0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ]
    );
    drop(queue);
    device.complete(head, 0, 0);
    drop(control);

    for flags in 0..=3 {
        let shutdown = RawHeader {
            socket_type: 1,
            operation: 4,
            flags,
            ..reset
        };
        let completion = try_post_tx(device.queue.clone(), shutdown, None)
            .unwrap_or_else(|(err, _)| panic!("valid shutdown rejected: {err}"));
        device.complete(completion.vq_completion.chain_head, 0, 0);
        drop(completion);
    }

    let mut payload = IoBuf::new_from_size_align(4096).unwrap();
    payload.set_len(3);
    <IoBuf as AsMut<[u8]>>::as_mut(&mut payload)[..3].copy_from_slice(&[7, 8, 9]);
    let payload_ptr = payload.raw_ptr();
    let payload_phys = payload.phys_addr() as u64;
    let mut data_header = reset;
    data_header.socket_type = 1;
    data_header.operation = 5;
    data_header.len = 3;
    let mut completion = match try_post_tx(device.queue.clone(), data_header, Some(payload)) {
        Ok(completion) => completion,
        Err(_) => panic!("valid data vsock TX was rejected"),
    };
    let head = completion.vq_completion.chain_head;
    let queue = device.queue.borrow();
    let header_desc = queue.get_descriptor(head);
    let data_desc = queue.get_descriptor(header_desc.next);
    assert_eq!(
        (header_desc.len, header_desc.flags),
        (44, VIRTQ_DESC_F_NEXT)
    );
    assert_eq!(
        (data_desc.addr, data_desc.len, data_desc.flags),
        (payload_phys, 3, 0)
    );
    let encoded: &[u8] = queue.header_buffers[head as usize].buf.as_ref();
    assert_eq!(&encoded[24..28], &[3, 0, 0, 0]);
    drop(queue);
    device.complete(head, 0, 2);
    device.reclaim();
    let mut cx = Context::from_waker(Waker::noop());
    let Poll::Ready((returned, result)) = Pin::new(&mut completion).poll(&mut cx) else {
        panic!("completed vsock TX was pending")
    };
    let returned = returned.unwrap();
    assert!(result.is_ok());
    assert_eq!(returned.raw_ptr(), payload_ptr);
    assert_eq!(&<IoBuf as AsRef<[u8]>>::as_ref(&returned)[..3], &[7, 8, 9]);
    drop(completion);

    let blocker = device.submit(ready_head(&device, 8), 8, 0);
    let before = unsafe { *device.queue.borrow().available_ring.next_available_idx };
    let mut rejected = IoBuf::new_from_size_align(4096).unwrap();
    rejected.set_len(3);
    let rejected_ptr = rejected.raw_ptr();
    let error = match try_post_tx(device.queue.clone(), data_header, Some(rejected)) {
        Err(error) => error,
        Ok(_) => panic!("full TX queue accepted another packet"),
    };
    assert_eq!(error.0.kind(), ErrorKind::WouldBlock);
    assert_eq!(error.1.unwrap().raw_ptr(), rejected_ptr);
    assert!(
        device
            .queue
            .borrow()
            .header_buffers
            .iter()
            .all(|header| header.in_use_by_device)
    );
    assert_eq!(
        unsafe { *device.queue.borrow().available_ring.next_available_idx },
        before
    );
    device.complete(blocker.chain_head, 0, 0);
    drop(blocker);

    let before_invalid = unsafe { *device.queue.borrow().available_ring.next_available_idx };
    let valid_empty = RawHeader {
        socket_type: 1,
        operation: 5,
        ..reset
    };
    for invalid in [
        RawHeader {
            src_cid: 1_u64 << 32,
            ..valid_empty
        },
        RawHeader {
            dst_cid: 1_u64 << 32,
            ..valid_empty
        },
        RawHeader {
            operation: 8,
            ..valid_empty
        },
        RawHeader {
            operation: 1,
            flags: 1,
            ..valid_empty
        },
        RawHeader {
            operation: 4,
            flags: 4,
            ..valid_empty
        },
        RawHeader {
            socket_type: 2,
            operation: 1,
            ..valid_empty
        },
        RawHeader {
            len: 1,
            ..valid_empty
        },
    ] {
        let error = match try_post_tx(device.queue.clone(), invalid, None) {
            Err(error) => error,
            Ok(_) => panic!("invalid TX header was accepted"),
        };
        assert_eq!(error.0.kind(), ErrorKind::InvalidInput);
        assert!(error.1.is_none());
    }
    assert_eq!(validate_payload_dma(4096, 4096, 4096).unwrap(), 4096);
    assert!(validate_payload_dma(4096, 1, 1).is_err());
    assert!(validate_payload_dma(4096, 0, 0).is_err());
    assert!(validate_payload_dma(4096, 4097, 0).is_err());
    let mut invalid = IoBuf::new_from_size_align(64).unwrap();
    invalid.set_len(3);
    let error = match try_post_tx(device.queue.clone(), data_header, Some(invalid)) {
        Err(error) => error,
        Ok(_) => panic!("invalid TX payload was accepted"),
    };
    assert_eq!(error.0.kind(), ErrorKind::InvalidInput);
    assert_eq!(error.1.unwrap().capacity(), 64);
    let mut empty = IoBuf::new_from_size_align(4096).unwrap();
    empty.set_len(0);
    data_header.len = 0;
    let error = match try_post_tx(device.queue.clone(), data_header, Some(empty)) {
        Err(error) => error,
        Ok(_) => panic!("empty TX payload was accepted"),
    };
    assert_eq!(error.0.kind(), ErrorKind::InvalidInput);
    assert_eq!(error.1.unwrap().len(), 0);
    data_header.operation = 1;
    data_header.len = 4096;
    let payload = IoBuf::new_from_size_align(4096).unwrap();
    let payload_ptr = payload.raw_ptr();
    let error = match try_post_tx(device.queue.clone(), data_header, Some(payload)) {
        Err(error) => error,
        Ok(_) => panic!("control payload was accepted"),
    };
    assert_eq!(error.0.kind(), ErrorKind::InvalidInput);
    assert_eq!(error.1.unwrap().raw_ptr(), payload_ptr);
    assert_eq!(
        unsafe { *device.queue.borrow().available_ring.next_available_idx },
        before_invalid
    );
    let full = device.submit(ready_head(&device, 8), 8, 0);
    device.complete(full.chain_head, 0, 0);
    drop(full);
}

/// Run in a child process because Motor OS panics abort the process.
pub fn test_header_layout_rejection(case: &str) {
    match case {
        "get-buffer-size" => {
            let device = Device::new(crate::VirtioDeviceKind::Block);
            let head = ready_head(&device, 1);
            let _ = device.queue.borrow_mut().get_buffer::<[u8; 17]>(head);
        }
        "read-header-size" => {
            let device = Device::new(crate::VirtioDeviceKind::Vsock);
            let head = ready_head(&device, 1);
            let completion = device.submit(head, 1, 0);
            device.complete(head, 0, 0);
            device.reclaim();
            let _: [u8; 65] = completion.read_header();
        }
        "alignment" => assert_header_layout::<u32>(64, 1),
        _ => panic!("unknown header-layout rejection case"),
    }
    panic!("invalid header layout was accepted");
}
