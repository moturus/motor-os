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
        Self::with_size(device_kind, 8)
    }

    fn with_size(device_kind: crate::VirtioDeviceKind, size: u16) -> Self {
        assert!(size.is_power_of_two() && size <= 256);
        let queue_sz = u64::from(size);
        let ring_size = super::super::align_up(18 * queue_sz + 4, 4) + 32 * queue_sz;
        let allocation_size = usize::try_from(ring_size)
            .unwrap()
            .next_power_of_two()
            .max(4096);
        let memory = IoBuf::new_from_size_align(allocation_size).unwrap();
        let addr = memory.raw_ptr() as u64;
        // SAFETY: the owned, aligned allocation contains all three
        // non-overlapping rings and outlives every completion.
        let descriptors = unsafe {
            std::ptr::write_bytes(addr as *mut u8, 0, allocation_size);
            std::slice::from_raw_parts_mut(addr as *mut VirtqDesc, size as usize)
        };
        for (idx, desc) in descriptors.iter_mut().enumerate() {
            desc.next = (idx as u16 + 1) % size;
        }
        let used_ring = VirtqUsed::from_addr(addr, size);
        *used_ring.flags = 1; // Suppress doorbells; there is no PCI device.
        let header_buffers = (0..size)
            .map(|_| HeaderBuffer::new(device_kind).unwrap())
            .collect();
        let queue = Virtqueue {
            virt_addr: addr,
            queue_size: size,
            queue_num: 0,
            queue_notify_off: 0,
            device_kind,
            descriptors,
            available_ring: VirtqAvail::from_addr(addr, size),
            used_ring,
            free_head_idx: 0,
            next_used_idx: 0,
            wait_handle: RaiiHandle::from(SysHandle::NONE),
            tasks_started: false,
            header_buffers,
            notify_bar: std::ptr::null(),
            notify_offset: 0,
            queue_size_mask: size - 1,
            last_kick_idx: 0,
            alloc_waiters: VecDeque::new(),
            completion_waiters: vec![None; size as usize],
            ordered_consumer_claimed: false,
            ordered_waiter: None,
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

    fn submit_deferred(&self, head: u16, value: u32) -> VqCompletion<u32> {
        Virtqueue::add_buffs_deferred(
            self.queue.clone(),
            &[UserData {
                phys_addr: 0,
                len: 1,
            }],
            0,
            1,
            head,
            value,
        )
    }

    fn complete(&self, head: u16, consumed: u32, status: u8) {
        self.complete_raw(u32::from(head), consumed, status);
    }

    fn complete_raw(&self, raw_head: u32, consumed: u32, status: u8) {
        {
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
        }
        self.publish_used_raw(raw_head, consumed);
    }

    fn publish_used(&self, head: u16, consumed: u32) {
        self.publish_used_raw(u32::from(head), consumed);
    }

    fn publish_used_raw(&self, raw_head: u32, consumed: u32) {
        let mut queue = self.queue.borrow_mut();
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

fn poll_ordered(cursor: &mut OrderedCompletions, waker: &LocalWaker) -> Poll<u16> {
    let mut cx = ContextBuilder::from_waker(Waker::noop())
        .local_waker(waker)
        .build();
    cursor.poll_next(&mut cx)
}

fn ready_head(device: &Device, len: u16) -> u16 {
    match poll_alloc(&mut device.alloc(len), LocalWaker::noop()) {
        Poll::Ready(head) => head,
        Poll::Pending => panic!("expected enough free descriptors"),
    }
}

pub fn test_descriptor_waiters() {
    test_block_seg_max();
    test_notifications();
    test_queue_task_start();
    test_ordered_completions();
    test_opportunistic_reclaim_rearms();
    test_ordered_waiter();
    test_used_id_boundary();
    test_header_buffers();
    test_vsock_rx();
    test_vsock_rx_pool();
    test_vsock_events();
    test_vsock_tx();
    test_vsock_tx_pool();
    test_vsock_pool_preparation();
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

fn test_notifications() {
    for (queue_num, event_idx, suppressed) in [
        (0, false, false),
        (1, false, false),
        (2, false, true),
        (1, true, true),
        (2, true, false),
    ] {
        let mut notify_memory = IoBuf::new_from_size_align(16).unwrap();
        // SAFETY: initialize the bytes observed below before constructing the
        // test BAR; the allocation remains owned through every volatile access.
        unsafe { notify_memory.raw_ptr_mut().write_bytes(0xa5, 16) };
        // SAFETY: 16-byte-aligned `notify_memory` is mapped and writable, and is
        // dropped after the queue and boxed BAR below.
        let notify_bar = Box::new(unsafe {
            PciBar::from_test_mapping(
                notify_memory.raw_ptr() as u64,
                notify_memory.capacity() as u64,
            )
        });
        let device = Device::new(crate::VirtioDeviceKind::Vsock);
        {
            let mut queue = device.queue.borrow_mut();
            queue.queue_num = queue_num;
            if event_idx {
                queue.set_f_event_idx_negotiated();
                // SAFETY: the fixture owns the used ring storage.
                unsafe {
                    (queue.used_ring.avail_event as *mut u16).write_volatile(if suppressed {
                        1
                    } else {
                        0
                    });
                }
            } else {
                *queue.used_ring.flags = u16::from(suppressed);
            }
            queue.set_notify_params(&*notify_bar, 8);
        }

        let head = ready_head(&device, 1);
        let completion = device.submit(head, 1, 0);
        let bytes: &[u8] = notify_memory.as_ref();
        let expected = if suppressed { 0xa5a5 } else { queue_num };
        assert_eq!(
            u16::from_le_bytes(bytes[8..10].try_into().unwrap()),
            expected
        );
        assert!(bytes[..8].iter().all(|byte| *byte == 0xa5));
        assert!(bytes[10..16].iter().all(|byte| *byte == 0xa5));

        device.complete(head, 1, 0);
        device.reclaim();
        drop(completion);
        drop(device);
        drop(notify_bar);
        drop(notify_memory);
    }

    for (queue_num, event_idx, suppressed, start_idx) in [
        (0, false, false, 0),
        (1, false, true, 0),
        (2, true, false, 0),
        (1, true, true, 0),
        (2, true, false, u16::MAX - 1),
        (1, true, true, u16::MAX - 1),
    ] {
        let mut notify_memory = IoBuf::new_from_size_align(16).unwrap();
        // SAFETY: the allocation remains live through all volatile accesses.
        unsafe { notify_memory.raw_ptr_mut().write_bytes(0xa5, 16) };
        // SAFETY: the owned allocation is aligned, mapped, writable, and
        // outlives the queue's raw BAR pointer.
        let notify_bar = Box::new(unsafe {
            PciBar::from_test_mapping(
                notify_memory.raw_ptr() as u64,
                notify_memory.capacity() as u64,
            )
        });
        let device = Device::new(crate::VirtioDeviceKind::Vsock);
        let new_idx = start_idx.wrapping_add(2);
        {
            let mut queue = device.queue.borrow_mut();
            queue.queue_num = queue_num;
            queue.last_kick_idx = start_idx;
            // SAFETY: the fixture owns the available ring storage.
            unsafe {
                queue
                    .available_ring
                    .next_available_idx
                    .write_volatile(start_idx);
            }
            if event_idx {
                queue.set_f_event_idx_negotiated();
                // SAFETY: the fixture owns the used ring storage.
                unsafe {
                    (queue.used_ring.avail_event as *mut u16).write_volatile(if suppressed {
                        new_idx
                    } else {
                        start_idx
                    });
                }
            } else {
                *queue.used_ring.flags = u16::from(suppressed);
            }
            queue.set_notify_params(&*notify_bar, 8);
        }

        let first_head = ready_head(&device, 1);
        let first = device.submit_deferred(first_head, 10);
        let second_head = ready_head(&device, 1);
        let second = device.submit_deferred(second_head, 11);
        {
            let queue = device.queue.borrow();
            // SAFETY: the fixture owns the available ring storage.
            assert_eq!(
                unsafe { queue.available_ring.next_available_idx.read_volatile() },
                new_idx
            );
            assert_eq!(
                queue.available_ring.ring[(start_idx & queue.queue_size_mask) as usize],
                first_head
            );
            assert_eq!(
                queue.available_ring.ring
                    [(start_idx.wrapping_add(1) & queue.queue_size_mask) as usize],
                second_head
            );
        }
        let bytes: &[u8] = notify_memory.as_ref();
        assert!(bytes.iter().all(|byte| *byte == 0xa5));

        device.queue.borrow_mut().kick_deferred();
        if suppressed {
            let bytes: &[u8] = notify_memory.as_ref();
            assert!(bytes.iter().all(|byte| *byte == 0xa5));
            let queue = &mut *device.queue.borrow_mut();
            if event_idx {
                // SAFETY: the fixture owns the used ring storage.
                unsafe {
                    (queue.used_ring.avail_event as *mut u16).write_volatile(start_idx);
                }
            } else {
                *queue.used_ring.flags = 0;
            }
            queue.kick_deferred();
        }
        let bytes: &[u8] = notify_memory.as_ref();
        assert_eq!(
            u16::from_le_bytes(bytes[8..10].try_into().unwrap()),
            queue_num
        );
        assert!(bytes[..8].iter().all(|byte| *byte == 0xa5));
        assert!(bytes[10..16].iter().all(|byte| *byte == 0xa5));

        // A second kick without another publication must not touch MMIO.
        // SAFETY: the fixture owns the initialized notification storage.
        unsafe { notify_memory.raw_ptr_mut().add(8).write_bytes(0xa5, 2) };
        device.queue.borrow_mut().kick_deferred();
        let bytes: &[u8] = notify_memory.as_ref();
        assert!(bytes.iter().all(|byte| *byte == 0xa5));

        device.complete(first_head, 1, 0);
        device.complete(second_head, 1, 0);
        device.reclaim();
        drop(first);
        drop(second);
        drop(device);
        drop(notify_bar);
        drop(notify_memory);
    }
}

fn test_block_seg_max() {
    for queue_size in [1, 2, 4] {
        for offered in [0, 1, usize::MAX] {
            assert_eq!(
                crate::virtio_blk::effective_seg_max(queue_size, offered)
                    .unwrap_err()
                    .kind(),
                ErrorKind::InvalidData
            );
        }
    }

    for (queue_size, offered, expected) in [
        (8, 0, 1),
        (8, 1, 1),
        (8, 2, 2),
        (8, usize::MAX, 2),
        (256, 0, 1),
        (256, 1, 1),
        (256, 126, 126),
        (256, usize::MAX, 126),
    ] {
        assert_eq!(
            crate::virtio_blk::effective_seg_max(queue_size, offered).unwrap(),
            expected
        );
    }
}

fn assert_handle_closed(handle: SysHandle) {
    match moto_sys::SysObj::dup(handle) {
        Err(error) => assert_eq!(error, moto_rt::E_BAD_HANDLE),
        Ok(duplicate) => {
            moto_sys::SysObj::put(duplicate).unwrap();
            panic!("queue wait handle remained open");
        }
    }
}

fn test_queue_task_start() {
    use moto_sys::{SysCpu, SysObj};

    for (vectors, required, accepted) in [
        (None, 3, false),
        (Some(0), 3, false),
        (Some(2), 3, false),
        (Some(3), 3, true),
        (Some(4), 3, true),
        (Some(1), 1, true),
    ] {
        assert_eq!(
            crate::virtio_device::validate_msix_vectors(vectors, required).is_ok(),
            accepted
        );
    }

    let unstarted = Device::new(crate::VirtioDeviceKind::Vsock);
    let (wake_unstarted, wait_unstarted) =
        SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0)
            .expect("failed to create unstarted queue wait pair");
    unstarted.queue.borrow_mut().set_wait_handle(wait_unstarted);
    drop(unstarted);
    assert_handle_closed(wait_unstarted);
    SysObj::put(wake_unstarted).unwrap();

    let first = Device::new(crate::VirtioDeviceKind::Vsock);
    let second = Device::new(crate::VirtioDeviceKind::Vsock);
    let (wake_first, wait_first) = SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0)
        .expect("failed to create first queue wait pair");
    let (wake_second, wait_second) = SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0)
        .expect("failed to create second queue wait pair");
    first.queue.borrow_mut().set_wait_handle(wait_first);
    let queues = [first.queue.clone(), second.queue.clone()];
    let strong_counts = queues.each_ref().map(Rc::strong_count);
    assert_eq!(
        Virtqueue::start_tasks(&queues).unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(queues.each_ref().map(Rc::strong_count), strong_counts);
    assert!(queues.iter().all(|queue| !queue.borrow().tasks_started));

    second.queue.borrow_mut().set_wait_handle(wait_second);
    let mut first_completion = first.submit(ready_head(&first, 1), 1, 7);
    first.complete(first_completion.chain_head, 9, 0);
    assert_eq!(first.queue.borrow().next_used_idx, 0);

    let mut runtime = moto_async::LocalRuntime::new();
    runtime.block_on(async {
        Virtqueue::start_tasks(&queues).unwrap();
        assert_eq!(
            Virtqueue::start_tasks(&queues).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        let (value, used_len) = std::future::poll_fn(|cx| first_completion.do_poll(cx)).await;
        assert_eq!((value, used_len.unwrap()), (7, 9));

        moto_async::yield_now().await;
        let mut signaled = first.submit(ready_head(&first, 1), 1, 11);
        first.complete(signaled.chain_head, 13, 0);
        SysCpu::wake(wake_first).unwrap();
        let (value, used_len) = std::future::poll_fn(|cx| signaled.do_poll(cx)).await;
        assert_eq!((value, used_len.unwrap()), (11, 13));
    });
    drop(first_completion);
    drop(runtime);
    drop(queues);
    drop(first);
    drop(second);
    for wait_handle in [wait_first, wait_second] {
        assert_handle_closed(wait_handle);
    }
    SysObj::put(wake_first).unwrap();
    SysObj::put(wake_second).unwrap();
}

fn test_ordered_completions() {
    let device = Device::new(crate::VirtioDeviceKind::Vsock);
    let start = u16::MAX - 3;
    {
        let mut queue = device.queue.borrow_mut();
        queue.next_used_idx = start;
        // SAFETY: the fixture owns the simulated device's ring.
        unsafe {
            (queue.used_ring.idx as *mut u16).write_volatile(start);
            queue
                .available_ring
                .next_available_idx
                .write_volatile(start);
        }
    }
    let mut ordered = Virtqueue::ordered_completions(device.queue.clone());
    let mut completions = Vec::new();
    for value in 0..8 {
        let head = ready_head(&device, 1);
        completions.push(Some(device.submit(head, 1, value)));
    }
    let completion_order = [7, 6, 5, 4, 3, 2, 1, 0];
    for index in completion_order {
        let completion = completions[index].as_ref().unwrap();
        device.complete(completion.chain_head, index as u32 + 20, 0);
    }
    device.reclaim();
    let reclaimed = device.queue.borrow().next_used_idx;
    assert_eq!(reclaimed, start.wrapping_add(8));

    // Polling the individual futures in submission order does not change the
    // order retained by the used ring.
    let mut cx = Context::from_waker(Waker::noop());
    for (value, completion) in completions.iter_mut().enumerate() {
        let Poll::Ready((data, result)) = completion.as_mut().unwrap().do_poll(&mut cx) else {
            panic!("precompleted request was pending")
        };
        assert_eq!(data, value as u32);
        assert_eq!(result.unwrap(), value as u32 + 20);
    }
    for (position, index) in completion_order.into_iter().enumerate() {
        let expected = completions[index].as_ref().unwrap().chain_head;
        assert_eq!(
            poll_ordered(&mut ordered, LocalWaker::noop()),
            Poll::Ready(expected)
        );
        if position == 0 {
            assert!(
                device
                    .queue
                    .borrow_mut()
                    .alloc_descriptor_chain(1)
                    .is_none()
            );
        }
        drop(completions[index].take());
    }
    assert_eq!(device.queue.borrow().next_used_idx, reclaimed);

    // Only after ordered handling releases the old pool may a descriptor be
    // reused and complete into the wrapped ring.
    let reused = device.submit(ready_head(&device, 1), 1, 99);
    let reused_head = reused.chain_head;
    device.complete(reused_head, 7, 0);
    device.reclaim();
    assert_eq!(
        poll_ordered(&mut ordered, LocalWaker::noop()),
        Poll::Ready(reused_head)
    );
    drop(reused);
}

fn test_opportunistic_reclaim_rearms() {
    for event_idx in [false, true] {
        let device = Device::new(crate::VirtioDeviceKind::Net);
        // Retaining the completion keeps every descriptor unavailable after
        // VqAlloc opportunistically reclaims it.
        let mut completion = device.submit(ready_head(&device, 8), 8, 7);
        if event_idx {
            device.queue.borrow_mut().set_f_event_idx_negotiated();
        }
        device.publish_used(completion.chain_head, 8);
        assert!(poll_alloc(&mut device.alloc(1), LocalWaker::noop()).is_pending());
        {
            let queue = device.queue.borrow();
            if event_idx {
                // SAFETY: the fixture owns the simulated device's ring.
                assert_eq!(
                    unsafe { queue.available_ring.used_event.read_volatile() },
                    1,
                    "allocator reclaim must re-arm EVENT_IDX"
                );
            } else {
                // The batch helper must restore callbacks after draining.
                assert_eq!(
                    unsafe { (queue.available_ring.flags as *const u16).read_volatile() },
                    0
                );
            }
        }

        let mut cx = Context::from_waker(Waker::noop());
        let Poll::Ready((value, used)) = completion.do_poll(&mut cx) else {
            panic!("allocator did not reclaim the used chain")
        };
        assert_eq!((value, used.unwrap()), (7, 8));
        drop(completion);
    }

    // Dropping an already-used, unpolled completion is the other production
    // opportunistic-reclaim path. Exercise the u16 cursor wrap as well.
    let device = Device::new(crate::VirtioDeviceKind::Net);
    {
        let mut queue = device.queue.borrow_mut();
        queue.next_used_idx = u16::MAX;
        // SAFETY: the fixture owns the simulated device's rings.
        unsafe {
            (queue.used_ring.idx as *mut u16).write_volatile(u16::MAX);
            queue
                .available_ring
                .next_available_idx
                .write_volatile(u16::MAX);
            queue.available_ring.used_event.write_volatile(u16::MAX);
        }
    }
    let completion = device.submit(ready_head(&device, 1), 1, 9);
    device.queue.borrow_mut().set_f_event_idx_negotiated();
    device.publish_used(completion.chain_head, 1);
    drop(completion);
    let queue = device.queue.borrow();
    assert_eq!(queue.next_used_idx, 0);
    // SAFETY: the fixture owns the simulated device's ring.
    assert_eq!(
        unsafe { queue.available_ring.used_event.read_volatile() },
        0,
        "completion drop must re-arm EVENT_IDX across wraparound"
    );
}

fn test_ordered_waiter() {
    let device = Device::new(crate::VirtioDeviceKind::Vsock);
    let mut ordered = Virtqueue::ordered_completions(device.queue.clone());
    let first = Rc::new(WakeCount::default());
    let second = Rc::new(WakeCount::default());
    let first_waker = LocalWaker::from(first.clone());
    let second_waker = LocalWaker::from(second.clone());
    assert!(poll_ordered(&mut ordered, &first_waker).is_pending());
    assert!(poll_ordered(&mut ordered, &second_waker).is_pending());
    let completion = device.submit(ready_head(&device, 1), 1, 0);
    device.complete(completion.chain_head, 0, 0);
    assert!(poll_ordered(&mut ordered, &second_waker).is_pending());
    device.reclaim();
    assert_eq!((first.0.get(), second.0.get()), (0, 1));
    assert_eq!(
        poll_ordered(&mut ordered, &second_waker),
        Poll::Ready(completion.chain_head)
    );
    drop(completion);
    assert!(poll_ordered(&mut ordered, &second_waker).is_pending());
    drop(ordered);
    let queue = device.queue.borrow();
    assert!(queue.ordered_consumer_claimed);
    assert!(queue.ordered_waiter.is_none());
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

/// Run in a child process: the device-lifetime RX owner is not cancellable.
pub fn test_premature_rx_pool_drop() {
    let device = Device::new(crate::VirtioDeviceKind::Vsock);
    let pool = crate::virtio_vsock::PreparedRxPool::new(device.queue.clone())
        .unwrap()
        .publish_deferred();
    drop(pool);
    panic!("premature vsock RX pool drop was accepted");
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

/// Run in a child process because Motor OS panics abort the process.
pub fn test_ordered_completion_rejection(case: &str) {
    let device = Device::new(crate::VirtioDeviceKind::Vsock);
    let mut ordered = Virtqueue::ordered_completions(device.queue.clone());
    match case {
        "duplicate" => {
            let _duplicate = Virtqueue::ordered_completions(device.queue.clone());
        }
        "busy" => {
            let other = Device::new(crate::VirtioDeviceKind::Vsock);
            let _completion = other.submit(ready_head(&other, 1), 1, 0);
            let _ordered = Virtqueue::ordered_completions(other.queue.clone());
        }
        "device-overrun" => {
            let idx = ordered
                .next_used_idx
                .wrapping_add(device.queue.borrow().queue_size + 1);
            let queue = device.queue.borrow_mut();
            // SAFETY: the fixture owns the simulated device's ring.
            unsafe { (queue.used_ring.idx as *mut u16).write_volatile(idx) };
            drop(queue);
            let _ = poll_ordered(&mut ordered, LocalWaker::noop());
        }
        "reclaimer-overrun" => {
            let mut queue = device.queue.borrow_mut();
            let idx = ordered.next_used_idx.wrapping_add(queue.queue_size + 1);
            queue.next_used_idx = idx;
            // SAFETY: the fixture owns the simulated device's ring.
            unsafe { (queue.used_ring.idx as *mut u16).write_volatile(idx) };
            drop(queue);
            let _ = poll_ordered(&mut ordered, LocalWaker::noop());
        }
        _ => panic!("unknown ordered-completion rejection case"),
    }
    panic!("invalid ordered completion use was accepted");
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

fn rx_header(payload_len: u32, operation: u16) -> [u8; crate::virtio_vsock::HEADER_LEN] {
    let mut header = [0; crate::virtio_vsock::HEADER_LEN];
    header[0..8].copy_from_slice(&2_u64.to_le_bytes());
    header[8..16].copy_from_slice(&0x7856_3412_u64.to_le_bytes());
    header[16..20].copy_from_slice(&0x0403_0201_u32.to_le_bytes());
    header[20..24].copy_from_slice(&0x0807_0605_u32.to_le_bytes());
    header[24..28].copy_from_slice(&payload_len.to_le_bytes());
    header[28..30].copy_from_slice(&1_u16.to_le_bytes());
    header[30..32].copy_from_slice(&operation.to_le_bytes());
    header[36..40].copy_from_slice(&0x4433_2211_u32.to_le_bytes());
    header[40..44].copy_from_slice(&0x8877_6655_u32.to_le_bytes());
    header
}

fn write_rx_header(device: &Device, head: u16, header: &[u8; 44]) {
    let mut queue = device.queue.borrow_mut();
    let scratch: &mut [u8] = queue.header_buffers[head as usize].buf.as_mut();
    scratch[..44].copy_from_slice(header);
}

fn write_event(device: &Device, head: u16, event: u32) {
    let mut queue = device.queue.borrow_mut();
    let scratch: &mut [u8] = queue.header_buffers[head as usize].buf.as_mut();
    scratch[..4].copy_from_slice(&event.to_le_bytes());
}

fn available_head(device: &Device, idx: u16) -> u16 {
    let queue = device.queue.borrow();
    let slot = idx & queue.queue_size_mask;
    // SAFETY: the fixture owns the simulated driver's available ring.
    unsafe { core::ptr::addr_of!(queue.available_ring.ring[slot as usize]).read_volatile() }
}

fn rx_payload_phys(device: &Device, head: u16) -> u64 {
    let queue = device.queue.borrow();
    let payload = queue.get_descriptor(queue.get_descriptor(head).next);
    payload.addr
}

fn test_vsock_rx() {
    use crate::virtio_vsock::{DecodeErrorKind, Operation, PacketHeader, try_post_rx};

    let device = Device::new(crate::VirtioDeviceKind::Vsock);
    {
        let mut queue = device.queue.borrow_mut();
        for header in &mut queue.header_buffers {
            let scratch: &mut [u8] = header.buf.as_mut();
            scratch[..crate::virtio_vsock::HEADER_LEN].fill(0xa5);
        }
    }
    let mut payload = IoBuf::new_from_size_align(4096).unwrap();
    payload.set_len(3);
    <IoBuf as AsMut<[u8]>>::as_mut(&mut payload).fill(0xaa);
    let payload_ptr = payload.raw_ptr_mut();
    let payload_phys = payload.phys_addr() as u64;
    let rx = try_post_rx(device.queue.clone(), payload)
        .unwrap_or_else(|(err, _)| panic!("valid RX buffer rejected: {err}"));
    let head = rx.head();
    {
        let queue = device.queue.borrow();
        let header_desc = queue.get_descriptor(head);
        let payload_desc = queue.get_descriptor(header_desc.next);
        let header_phys = queue.header_buffers[head as usize].buf.phys_addr() as u64;
        assert_eq!(
            (header_desc.addr, header_desc.len, header_desc.flags),
            (header_phys, 44, 3)
        );
        assert_eq!(
            (payload_desc.addr, payload_desc.len, payload_desc.flags),
            (payload_phys, 4096, 2)
        );
        let scratch: &[u8] = queue.header_buffers[head as usize].buf.as_ref();
        assert!(scratch[..44].iter().all(|byte| *byte == 0));
        assert!(queue.header_buffers[head as usize].in_use_by_completion);
    }
    write_rx_header(&device, head, &rx_header(3, 5));
    // SAFETY: the completion owns this posted page; the fixture is the device.
    unsafe { std::ptr::copy_nonoverlapping([7, 8, 9].as_ptr(), payload_ptr, 3) };
    device.complete(head, 47, 0);
    device.reclaim();
    let (payload, decoded) = rx.finish_ordered(head);
    assert_eq!(payload.raw_ptr(), payload_ptr);
    assert_eq!(<IoBuf as AsRef<[u8]>>::as_ref(&payload), &[7, 8, 9]);
    assert_eq!(
        decoded.unwrap(),
        PacketHeader {
            src_cid: 2,
            dst_cid: 0x7856_3412,
            src_port: 0x0403_0201,
            dst_port: 0x0807_0605,
            len: 3,
            socket_type: crate::virtio_vsock::SocketType::Stream,
            operation: Operation::ReadWrite,
            flags: 0,
            buf_alloc: 0x4433_2211,
            fwd_cnt: 0x8877_6655,
        }
    );

    let mut full_payload = IoBuf::new_from_size_align(4096).unwrap();
    full_payload.set_len(4096);
    <IoBuf as AsMut<[u8]>>::as_mut(&mut full_payload).fill(0x55);
    let full_ptr = full_payload.raw_ptr_mut();
    let full = try_post_rx(device.queue.clone(), full_payload)
        .unwrap_or_else(|(err, _)| panic!("full-capacity RX buffer rejected: {err}"));
    let head = full.head();
    write_rx_header(&device, head, &rx_header(4096, 5));
    // SAFETY: the completion owns this posted page; the fixture is the device.
    unsafe {
        full_ptr.write(1);
        full_ptr.add(4095).write(2);
    }
    device.complete(head, 44 + 4096, 0);
    device.reclaim();
    let (full_payload, decoded) = full.finish_ordered(head);
    assert_eq!(decoded.unwrap().len, 4096);
    assert_eq!(full_payload.len(), 4096);
    let full_bytes: &[u8] = full_payload.as_ref();
    assert_eq!((full_bytes[0], full_bytes[4095]), (1, 2));

    let control = try_post_rx(
        device.queue.clone(),
        IoBuf::new_from_size_align(4096).unwrap(),
    )
    .unwrap_or_else(|(err, _)| panic!("control RX buffer rejected: {err}"));
    let head = control.head();
    write_rx_header(&device, head, &rx_header(0, 1));
    device.complete(head, 44, 0);
    device.reclaim();
    let (payload, decoded) = control.finish_ordered(head);
    assert_eq!(decoded.unwrap().operation, Operation::Request);
    assert_eq!(payload.len(), 0);

    for (header_len, used_len, expected, expected_raw_len) in [
        (0, 43, DecodeErrorKind::ShortHeader, None),
        (
            0,
            44 + 4096 + 1,
            DecodeErrorKind::UsedLengthExceedsCapacity,
            Some(0),
        ),
        (
            4097,
            44 + 4096,
            DecodeErrorKind::PayloadExceedsCapacity,
            Some(4097),
        ),
        (3, 46, DecodeErrorKind::TruncatedPayload, Some(3)),
    ] {
        let mut payload = IoBuf::new_from_size_align(4096).unwrap();
        payload.set_len(3);
        <IoBuf as AsMut<[u8]>>::as_mut(&mut payload)[..3].copy_from_slice(&[4, 5, 6]);
        let ptr = payload.raw_ptr();
        let rx = try_post_rx(device.queue.clone(), payload)
            .unwrap_or_else(|(err, _)| panic!("malformed RX fixture rejected: {err}"));
        let head = rx.head();
        write_rx_header(&device, head, &rx_header(header_len, 5));
        device.complete(head, used_len, 0);
        device.reclaim();
        let (payload, error) = rx.finish_ordered(head);
        let error = error.unwrap_err();
        assert_eq!(error.kind, expected);
        assert_eq!(error.raw.map(|raw| raw.len), expected_raw_len);
        assert_eq!(payload.raw_ptr(), ptr);
        assert_eq!(payload.len(), 0);
    }

    let before = unsafe { *device.queue.borrow().available_ring.next_available_idx };
    let mut invalid = IoBuf::new_from_size_align(64).unwrap();
    invalid.set_len(3);
    <IoBuf as AsMut<[u8]>>::as_mut(&mut invalid)[..3].copy_from_slice(&[1, 2, 3]);
    let invalid_ptr = invalid.raw_ptr();
    let (error, invalid) = match try_post_rx(device.queue.clone(), invalid) {
        Err(rejected) => rejected,
        Ok(_) => panic!("invalid RX buffer was accepted"),
    };
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(invalid.raw_ptr(), invalid_ptr);
    assert_eq!(<IoBuf as AsRef<[u8]>>::as_ref(&invalid), &[1, 2, 3]);
    assert_eq!(
        unsafe { *device.queue.borrow().available_ring.next_available_idx },
        before
    );

    let blocker = device.submit(ready_head(&device, 8), 8, 0);
    let mut rejected = IoBuf::new_from_size_align(4096).unwrap();
    rejected.set_len(1);
    <IoBuf as AsMut<[u8]>>::as_mut(&mut rejected)[0] = 9;
    let rejected_ptr = rejected.raw_ptr();
    let before = unsafe { *device.queue.borrow().available_ring.next_available_idx };
    let (error, rejected) = match try_post_rx(device.queue.clone(), rejected) {
        Err(rejected) => rejected,
        Ok(_) => panic!("full RX queue accepted another buffer"),
    };
    assert_eq!(error.kind(), ErrorKind::WouldBlock);
    assert_eq!(rejected.raw_ptr(), rejected_ptr);
    assert_eq!(<IoBuf as AsRef<[u8]>>::as_ref(&rejected), &[9]);
    assert_eq!(
        unsafe { *device.queue.borrow().available_ring.next_available_idx },
        before
    );
    device.complete(blocker.chain_head, 0, 0);
    drop(blocker);
}

fn test_vsock_rx_pool() {
    use crate::virtio_vsock::{DecodeErrorKind, Operation, PreparedRxPool};

    let tiny = Device::with_size(crate::VirtioDeviceKind::Vsock, 1);
    let error = match PreparedRxPool::new(tiny.queue.clone()) {
        Err(error) => error,
        Ok(_) => panic!("one-descriptor RX queue was accepted"),
    };
    assert_eq!(error.kind(), ErrorKind::InvalidInput);

    let large = Device::with_size(crate::VirtioDeviceKind::Vsock, 256);
    let prepared = PreparedRxPool::new(large.queue.clone()).unwrap();
    assert_eq!(prepared.pages().len(), 64);
    assert_eq!(
        unsafe { *large.queue.borrow().available_ring.next_available_idx },
        0
    );
    let large_pool = prepared.publish_deferred();
    assert_eq!(
        unsafe { *large.queue.borrow().available_ring.next_available_idx },
        64
    );
    for idx in 0..64 {
        large.complete(available_head(&large, idx), 0, 0);
    }
    drop(large_pool);

    let device = Device::new(crate::VirtioDeviceKind::Vsock);
    let start = u16::MAX - 2;
    {
        let mut queue = device.queue.borrow_mut();
        queue.next_used_idx = start;
        // SAFETY: the fixture owns both simulated ring indices.
        unsafe {
            (queue.used_ring.idx as *mut u16).write_volatile(start);
            queue
                .available_ring
                .next_available_idx
                .write_volatile(start);
        }
    }
    let prepared = PreparedRxPool::new(device.queue.clone()).unwrap();
    assert_eq!(prepared.pages().len(), 4);
    let pages: Vec<(u64, *mut u8)> = prepared
        .pages()
        .iter()
        .map(|page| (page.phys_addr() as u64, page.raw_ptr() as *mut u8))
        .collect();
    assert_eq!(
        unsafe { *device.queue.borrow().available_ring.next_available_idx },
        start
    );
    let mut pool = prepared.publish_deferred();
    let published = start.wrapping_add(4);
    assert_eq!(
        unsafe { *device.queue.borrow().available_ring.next_available_idx },
        published
    );
    assert!(
        device
            .queue
            .borrow_mut()
            .alloc_descriptor_chain(1)
            .is_none()
    );

    let heads: [u16; 4] =
        core::array::from_fn(|idx| available_head(&device, start.wrapping_add(idx as u16)));
    for (index, head) in heads.into_iter().enumerate() {
        assert_eq!(rx_payload_phys(&device, head), pages[index].0);
    }
    let order = [3, 1, 2, 0];
    for (position, index) in order.into_iter().enumerate() {
        let head = heads[index];
        let (header_len, used_len) = match position {
            0 => (1, 45),
            1 => (3, 46),
            2 => (4096, 44 + 4096),
            _ => (0, 44),
        };
        let operation = if position == 3 { 1 } else { 5 };
        write_rx_header(&device, head, &rx_header(header_len, operation));
        // SAFETY: the fixture is the device and these posted pages are writable.
        unsafe {
            match position {
                0 => pages[index].1.write(0x30),
                1 => pages[index].1.write_bytes(0x31, 2),
                2 => {
                    pages[index].1.write_bytes(0x32, 4096);
                    pages[index].1.add(4095).write(0x7f);
                }
                _ => {}
            }
        }
        device.complete(head, used_len, 0);
    }
    device.reclaim();

    for (position, index) in order.into_iter().enumerate() {
        let before_repost = published.wrapping_add(position as u16);
        let mut cx = ContextBuilder::from_waker(Waker::noop())
            .local_waker(LocalWaker::noop())
            .build();
        let result = pool.poll_consume(
            &mut cx,
            |decoded, bytes| {
                assert_eq!(
                    unsafe { *device.queue.borrow().available_ring.next_available_idx },
                    before_repost
                );
                match position {
                    0 => assert_eq!((decoded.unwrap().len, bytes), (1, &[0x30][..])),
                    1 => {
                        let error = decoded.unwrap_err();
                        assert_eq!(error.kind, DecodeErrorKind::TruncatedPayload);
                        assert_eq!(error.raw.unwrap().len, 3);
                        assert!(bytes.is_empty());
                    }
                    2 => {
                        assert_eq!(decoded.unwrap().len, 4096);
                        assert_eq!((bytes[0], bytes[4095]), (0x32, 0x7f));
                    }
                    _ => {
                        assert_eq!(decoded.unwrap().operation, Operation::Request);
                        assert!(bytes.is_empty());
                    }
                }
                position
            },
            || true,
        );
        assert_eq!(result, Poll::Ready(position));
        let reposted = available_head(&device, before_repost);
        assert_eq!(rx_payload_phys(&device, reposted), pages[index].0);
    }
    assert!(
        device
            .queue
            .borrow_mut()
            .alloc_descriptor_chain(1)
            .is_none()
    );

    let pending_head = available_head(&device, published);
    write_rx_header(&device, pending_head, &rx_header(0, 1));
    let wake = Rc::new(WakeCount::default());
    let local_waker = LocalWaker::from(wake.clone());
    let mut cx = ContextBuilder::from_waker(Waker::noop())
        .local_waker(&local_waker)
        .build();
    assert!(pool.poll_consume(&mut cx, |_, _| (), || true).is_pending());
    device.complete(pending_head, 44, 0);
    assert!(pool.poll_consume(&mut cx, |_, _| (), || true).is_pending());
    device.reclaim();
    assert_eq!(wake.0.get(), 1);
    assert_eq!(
        pool.poll_consume(
            &mut cx,
            |decoded, bytes| {
                assert_eq!(decoded.unwrap().operation, Operation::Request);
                assert!(bytes.is_empty());
            },
            || false,
        ),
        Poll::Ready(())
    );
    assert_eq!(
        unsafe { *device.queue.borrow().available_ring.next_available_idx },
        published.wrapping_add(4)
    );

    let current = published.wrapping_add(1);
    for offset in 0..3 {
        device.complete(available_head(&device, current.wrapping_add(offset)), 0, 0);
    }
    drop(pool);
}

fn test_vsock_events() {
    use crate::virtio_vsock::{Event, EventError, PreparedEventPool, try_post_event};

    let device = Device::new(crate::VirtioDeviceKind::Vsock);
    for header in &mut device.queue.borrow_mut().header_buffers {
        <IoBuf as AsMut<[u8]>>::as_mut(&mut header.buf)[..8].fill(0xa5);
    }
    let completion = try_post_event(device.queue.clone()).unwrap();
    let head = completion.head();
    {
        let queue = device.queue.borrow();
        let descriptor = queue.get_descriptor(head);
        let scratch = &queue.header_buffers[head as usize].buf;
        assert_eq!(
            (descriptor.addr, descriptor.len, descriptor.flags),
            (scratch.phys_addr() as u64, 4, VIRTQ_DESC_F_WRITE)
        );
        assert_eq!(
            &<IoBuf as AsRef<[u8]>>::as_ref(scratch)[..8],
            &[0, 0, 0, 0, 0xa5, 0xa5, 0xa5, 0xa5]
        );
    }
    write_event(&device, head, 0);
    device.publish_used(head, 4);
    device.reclaim();
    assert_eq!(completion.finish_ordered(head), Ok(Event::TransportReset));

    for (event, used_len, expected) in [
        (0x7856_3412, 4, Err(EventError::Unknown(0x7856_3412))),
        (0, 3, Err(EventError::InvalidLength)),
        (0, 5, Err(EventError::InvalidLength)),
    ] {
        let completion = try_post_event(device.queue.clone()).unwrap();
        let head = completion.head();
        write_event(&device, head, event);
        device.publish_used(head, used_len);
        device.reclaim();
        assert_eq!(completion.finish_ordered(head), expected);
    }

    let blocker = device.submit(ready_head(&device, 8), 8, 0);
    let before = unsafe { *device.queue.borrow().available_ring.next_available_idx };
    let error = match try_post_event(device.queue.clone()) {
        Err(error) => error,
        Ok(_) => panic!("full event queue accepted another buffer"),
    };
    assert_eq!(error.kind(), ErrorKind::WouldBlock);
    assert_eq!(
        unsafe { *device.queue.borrow().available_ring.next_available_idx },
        before
    );
    device.complete(blocker.chain_head, 0, 0);
    drop(blocker);

    let one = Device::with_size(crate::VirtioDeviceKind::Vsock, 1);
    assert_eq!(PreparedEventPool::new(one.queue.clone()).unwrap().len(), 1);

    let device = Device::new(crate::VirtioDeviceKind::Vsock);
    let prepared = PreparedEventPool::new(device.queue.clone()).unwrap();
    assert_eq!(prepared.len(), 4);
    assert_eq!(
        unsafe { *device.queue.borrow().available_ring.next_available_idx },
        0
    );
    let mut pool = prepared.publish_deferred();
    assert_eq!(
        unsafe { *device.queue.borrow().available_ring.next_available_idx },
        4
    );
    let heads: [u16; 4] = core::array::from_fn(|idx| available_head(&device, idx as u16));
    let order = [3, 1, 2, 0];
    for (position, index) in order.into_iter().enumerate() {
        let head = heads[index];
        write_event(&device, head, if position == 1 { 7 } else { 0 });
        device.publish_used(head, if position == 2 { 3 } else { 4 });
    }
    device.reclaim();
    for (position, index) in order.into_iter().enumerate() {
        let before_repost = 4 + position as u16;
        let mut cx = ContextBuilder::from_waker(Waker::noop())
            .local_waker(LocalWaker::noop())
            .build();
        assert_eq!(
            pool.poll_consume(
                &mut cx,
                |event| {
                    assert_eq!(
                        unsafe { *device.queue.borrow().available_ring.next_available_idx },
                        before_repost
                    );
                    match position {
                        1 => assert_eq!(event, Err(EventError::Unknown(7))),
                        2 => assert_eq!(event, Err(EventError::InvalidLength)),
                        _ => assert_eq!(event, Ok(Event::TransportReset)),
                    }
                    position
                },
                || true,
            ),
            Poll::Ready(position)
        );
        let reposted = available_head(&device, before_repost);
        assert_eq!(reposted, heads[index]);
        let queue = device.queue.borrow();
        let scratch: &[u8] = queue.header_buffers[reposted as usize].buf.as_ref();
        assert_eq!(&scratch[..4], &[0; 4]);
    }

    let pending_head = available_head(&device, 4);
    write_event(&device, pending_head, 0);
    let wake = Rc::new(WakeCount::default());
    let local_waker = LocalWaker::from(wake.clone());
    let mut cx = ContextBuilder::from_waker(Waker::noop())
        .local_waker(&local_waker)
        .build();
    assert!(pool.poll_consume(&mut cx, |_| (), || true).is_pending());
    device.publish_used(pending_head, 4);
    assert!(pool.poll_consume(&mut cx, |_| (), || true).is_pending());
    device.reclaim();
    assert_eq!(wake.0.get(), 1);
    let repost = Cell::new(true);
    assert_eq!(
        pool.poll_consume(
            &mut cx,
            |event| {
                assert_eq!(event, Ok(Event::TransportReset));
                repost.set(false);
            },
            || repost.get(),
        ),
        Poll::Ready(())
    );
    assert_eq!(
        unsafe { *device.queue.borrow().available_ring.next_available_idx },
        8
    );
    for idx in 5..8 {
        device.publish_used(available_head(&device, idx), 0);
    }
    drop(pool);
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

fn test_vsock_tx_pool() {
    use crate::virtio_vsock::{RawHeader, TxPool};

    let tiny = Device::new(crate::VirtioDeviceKind::Vsock);
    let error = match TxPool::new(tiny.queue.clone()) {
        Err(error) => error,
        Ok(_) => panic!("tiny queue accepted a vsock TX pool"),
    };
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    let large = Device::with_size(crate::VirtioDeviceKind::Vsock, 256);
    let pool = TxPool::new(large.queue.clone()).unwrap();
    assert_eq!(pool.pages().len(), 64);
    drop(pool);

    let device = Device::with_size(crate::VirtioDeviceKind::Vsock, 16);
    let mut pool = TxPool::new(device.queue.clone()).unwrap();
    assert_eq!(pool.pages().len(), 4);
    let page_addresses: Vec<_> = pool
        .pages()
        .iter()
        .map(|page| (page.phys_addr() as u64, page.raw_ptr()))
        .collect();
    let control = RawHeader {
        src_cid: 3,
        dst_cid: 2,
        src_port: 0x0403_0201,
        dst_port: 0x0807_0605,
        len: 0,
        socket_type: 1,
        operation: 3,
        flags: 0,
        buf_alloc: 0x4433_2211,
        fwd_cnt: 0x8877_6655,
    };
    let mut data = RawHeader {
        operation: 5,
        len: 3,
        ..control
    };

    let empty_wake = Rc::new(WakeCount::default());
    let empty_waker = LocalWaker::from(empty_wake.clone());
    let mut empty_cx = ContextBuilder::from_waker(Waker::noop())
        .local_waker(&empty_waker)
        .build();
    assert!(pool.poll_reclaim_one(&mut empty_cx).is_pending());
    pool.try_submit(data, &[7, 8, 9]).unwrap();
    assert_eq!(empty_wake.0.get(), 1);
    let data_head = available_head(&device, 0);
    let queue = device.queue.borrow();
    let header = queue.get_descriptor(data_head);
    let payload = queue.get_descriptor(header.next);
    assert_eq!((header.len, header.flags), (44, VIRTQ_DESC_F_NEXT));
    assert_eq!((payload.len, payload.flags), (3, 0));
    let payload_ptr = page_addresses
        .iter()
        .find_map(|(phys, ptr)| (*phys == payload.addr).then_some(*ptr))
        .expect("TX descriptor did not use a prepared page");
    // SAFETY: the matching prepared page remains owned by `pool`'s
    // completion, and only the initialized descriptor length is read.
    assert_eq!(
        unsafe { std::slice::from_raw_parts(payload_ptr, 3) },
        &[7, 8, 9]
    );
    let encoded: &[u8] = queue.header_buffers[data_head as usize].buf.as_ref();
    assert_eq!(&encoded[24..32], &[3, 0, 0, 0, 1, 0, 5, 0]);
    drop(queue);

    let nonempty_wake = Rc::new(WakeCount::default());
    let nonempty_waker = LocalWaker::from(nonempty_wake.clone());
    let mut nonempty_cx = ContextBuilder::from_waker(Waker::noop())
        .local_waker(&nonempty_waker)
        .build();
    assert!(pool.poll_reclaim_one(&mut nonempty_cx).is_pending());
    pool.try_submit(control, &[]).unwrap();
    assert_eq!(nonempty_wake.0.get(), 1);
    let control_head = available_head(&device, 1);

    assert!(pool.poll_reclaim_one(&mut nonempty_cx).is_pending());
    device.publish_used(control_head, 0);
    assert!(pool.poll_reclaim_one(&mut nonempty_cx).is_pending());
    device.reclaim();
    assert_eq!(nonempty_wake.0.get(), 2);
    assert!(matches!(
        pool.poll_reclaim_one(&mut nonempty_cx),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(pool.counts(), (3, 1));
    assert_eq!(
        unsafe { std::slice::from_raw_parts(payload_ptr, 3) },
        &[7, 8, 9]
    );
    device.publish_used(data_head, 0);
    device.reclaim();
    assert!(matches!(
        pool.poll_reclaim_one(&mut nonempty_cx),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(pool.counts(), (4, 0));

    let before = unsafe { *device.queue.borrow().available_ring.next_available_idx };
    let counts = pool.counts();
    for (len, bytes) in [(4, &[1, 2, 3][..]), (4097, &[0; 4097][..])] {
        data.len = len;
        assert_eq!(
            pool.try_submit(data, bytes).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(pool.counts(), counts);
        assert_eq!(
            unsafe { *device.queue.borrow().available_ring.next_available_idx },
            before
        );
    }

    data.len = 1;
    for byte in 0..4 {
        pool.try_submit(data, &[byte]).unwrap();
    }
    assert_eq!(pool.counts(), (0, 4));
    let mut in_flight_pages: Vec<_> = (2..6)
        .map(|idx| rx_payload_phys(&device, available_head(&device, idx)))
        .collect();
    in_flight_pages.sort_unstable();
    in_flight_pages.dedup();
    assert_eq!(in_flight_pages.len(), 4);
    let before = unsafe { *device.queue.borrow().available_ring.next_available_idx };
    assert_eq!(
        pool.try_submit(data, &[9]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    assert_eq!(
        unsafe { *device.queue.borrow().available_ring.next_available_idx },
        before
    );
    for _ in 0..8 {
        pool.try_submit(control, &[]).unwrap();
    }
    assert_eq!(
        pool.try_submit(control, &[]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    for idx in 2..14 {
        device.complete(available_head(&device, idx), 0, 0);
    }
    device.reclaim();
    for _ in 0..12 {
        assert!(matches!(
            pool.poll_reclaim_one(&mut nonempty_cx),
            Poll::Ready(Ok(()))
        ));
    }
    assert_eq!(pool.counts(), (4, 0));

    for _ in 0..16 {
        pool.try_submit(control, &[]).unwrap();
    }
    assert_eq!(pool.counts(), (4, 16));
    let before = unsafe { *device.queue.borrow().available_ring.next_available_idx };
    assert_eq!(
        pool.try_submit(data, &[9]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    assert_eq!(pool.counts(), (4, 16));
    assert_eq!(
        unsafe { *device.queue.borrow().available_ring.next_available_idx },
        before
    );
    for idx in 14..30 {
        device.complete(available_head(&device, idx), 0, 0);
    }
    device.reclaim();
    for _ in 0..16 {
        assert!(matches!(
            pool.poll_reclaim_one(&mut nonempty_cx),
            Poll::Ready(Ok(()))
        ));
    }
    assert_eq!(pool.counts(), (4, 0));
}

fn test_vsock_pool_preparation() {
    use crate::virtio_vsock::prepare_pools;

    let available_idx = |device: &Device| {
        // SAFETY: the fixture owns and retains the available ring storage.
        unsafe {
            device
                .queue
                .borrow()
                .available_ring
                .next_available_idx
                .read_volatile()
        }
    };
    let mut notify_memory = IoBuf::new_from_size_align(16).unwrap();
    // SAFETY: this initialized mapping outlives every queue and BAR access.
    unsafe { notify_memory.raw_ptr_mut().write_bytes(0xa5, 16) };
    let notify_bar =
        Box::new(unsafe { PciBar::from_test_mapping(notify_memory.raw_ptr() as u64, 16) });
    let rx = Device::with_size(crate::VirtioDeviceKind::Vsock, 2);
    let tx = Device::with_size(crate::VirtioDeviceKind::Vsock, 16);
    let events = Device::with_size(crate::VirtioDeviceKind::Vsock, 1);
    for (device, queue_num, offset) in [(&rx, 0, 8), (&events, 2, 10)] {
        let mut queue = device.queue.borrow_mut();
        queue.queue_num = queue_num;
        *queue.used_ring.flags = 0;
        queue.set_notify_params(&*notify_bar, offset);
    }
    let queues = [rx.queue.clone(), tx.queue.clone(), events.queue.clone()];

    for invalid in [&queues[..0], &queues[..2]] {
        let error = match prepare_pools(invalid) {
            Err(error) => error,
            Ok(_) => panic!("incomplete vsock queue set was accepted"),
        };
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }
    let extra = [
        rx.queue.clone(),
        tx.queue.clone(),
        events.queue.clone(),
        events.queue.clone(),
    ];
    let error = match prepare_pools(&extra) {
        Err(error) => error,
        Ok(_) => panic!("extra vsock queue was accepted"),
    };
    assert_eq!(error.kind(), ErrorKind::InvalidData);

    let small_rx = Device::with_size(crate::VirtioDeviceKind::Vsock, 1);
    let small_tx = Device::new(crate::VirtioDeviceKind::Vsock);
    for (invalid, label) in [
        (
            [
                small_rx.queue.clone(),
                tx.queue.clone(),
                events.queue.clone(),
            ],
            "RX",
        ),
        (
            [
                rx.queue.clone(),
                small_tx.queue.clone(),
                events.queue.clone(),
            ],
            "TX",
        ),
    ] {
        let error = match prepare_pools(&invalid) {
            Err(error) => error,
            Ok(_) => panic!("undersized vsock {label} queue was accepted"),
        };
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }
    for device in [&rx, &tx, &events, &small_rx, &small_tx] {
        assert_eq!(available_idx(device), 0);
    }

    let (prepared_rx, tx_pool, prepared_events) = prepare_pools(&queues).unwrap();
    assert_eq!(prepared_rx.pages().len(), 1);
    assert_eq!(tx_pool.pages().len(), 4);
    assert_eq!(prepared_events.len(), 1);
    for device in [&rx, &tx, &events] {
        assert_eq!(available_idx(device), 0);
    }

    let event_pool = prepared_events.publish_deferred();
    let rx_pool = prepared_rx.publish_deferred();
    assert_eq!(available_idx(&events), 1);
    assert_eq!(available_idx(&rx), 1);
    assert_eq!(available_idx(&tx), 0);
    let bytes: &[u8] = notify_memory.as_ref();
    assert!(bytes.iter().all(|byte| *byte == 0xa5));

    // This fixture checks publication/kicks, not PCI DRIVER_OK sequencing.
    events.queue.borrow_mut().kick_deferred();
    rx.queue.borrow_mut().kick_deferred();
    let bytes: &[u8] = notify_memory.as_ref();
    assert_eq!(&bytes[8..12], &[0, 0, 2, 0]);
    assert!(bytes[..8].iter().all(|byte| *byte == 0xa5));
    assert!(bytes[12..].iter().all(|byte| *byte == 0xa5));

    events.publish_used(available_head(&events, 0), 0);
    rx.publish_used(available_head(&rx, 0), 0);
    drop(event_pool);
    drop(rx_pool);
    drop(tx_pool);
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
