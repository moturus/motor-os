//! VirtIO Queue.
use super::virtio_device::VirtioDevice;
use super::{le16, le32, le64};
use crate::pci::PciBar;
use crate::virtio_device::mapper;

use moto_async::AsFuture;
use moto_sys::SysHandle;
use moto_tooling::iobuf::IoBuf;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{ErrorKind, Result};
use std::marker::PhantomData;
use std::rc::Rc;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

fn mfence() {
    // SAFETY: there's nothing unsafe about mfence on x64.
    unsafe {
        core::arch::x86_64::_mm_mfence();
    }

    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[repr(C, align(8))]
struct VirtqDesc {
    addr: le64,
    len: le32,
    flags: le16,
    next: le16,
}

const _: () = assert!(core::mem::size_of::<VirtqDesc>() == 16);

// Updated by the driver (here, in this file).
struct VirtqAvail {
    flags: &'static mut le16,
    next_available_idx: *mut le16, // "idx" in VirtIO spec.
    ring: &'static mut [le16],
    used_event: *mut le16,
}

unsafe impl Send for VirtqAvail {}

#[derive(Clone, Copy)]
pub struct UserData {
    pub phys_addr: u64,
    pub len: u32,
}

impl VirtqAvail {
    fn from_addr(addr: u64, queue_size: u16) -> Self {
        let queue_size = queue_size as u64;
        let flags_addr = addr + 16 * queue_size;
        let idx_addr = flags_addr + 2;
        let ring = unsafe {
            core::slice::from_raw_parts_mut((idx_addr + 2) as *mut le16, queue_size as usize)
        };
        let used_event_addr = flags_addr + 4 + 2 * queue_size;

        unsafe {
            VirtqAvail {
                flags: &mut *(flags_addr as *mut le16),
                next_available_idx: idx_addr as *mut le16,
                ring,
                used_event: used_event_addr as *mut le16,
            }
        }
    }
}

#[repr(C)]
struct VirtqUsedElem {
    id: le32,  // le32,
    len: le32, // le32,
}

// Updated by the "device" (the VMM).
struct VirtqUsed {
    flags: &'static mut le16,
    idx: *const le16,
    ring: &'static mut [VirtqUsedElem],
    avail_event: *const le16,
}

unsafe impl Send for VirtqUsed {}

impl VirtqUsed {
    fn from_addr(addr: u64, queue_size: u16) -> Self {
        let queue_size = queue_size as u64;

        // VirtqUsed must be 4-byte aligned.
        let flags_addr = super::align_up(addr + 16 * queue_size + 6 + 2 * queue_size, 4);
        let idx_addr = flags_addr + 2;
        let ring = unsafe {
            core::slice::from_raw_parts_mut(
                (idx_addr + 2) as *mut VirtqUsedElem,
                queue_size as usize,
            )
        };
        let avail_event_addr = flags_addr + 4 + 8 * queue_size;

        VirtqUsed {
            flags: unsafe { &mut *(flags_addr as *mut le16) },
            idx: idx_addr as *const le16,
            ring,
            avail_event: avail_event_addr as *const le16,
        }
    }
}

struct HeaderBuffer {
    buf: IoBuf,
    consumed: u32,
    in_use_by_device: bool,
    in_use_by_completion: bool,
}

pub(crate) struct VqAlloc {
    num_to_alloc: u16,
    virtqueue: Rc<RefCell<Virtqueue>>,
}

impl VqAlloc {
    pub(crate) fn new(virtqueue: Rc<RefCell<Virtqueue>>, num_to_alloc: u16) -> Self {
        Self {
            num_to_alloc,
            virtqueue,
        }
    }
}

impl Future for VqAlloc {
    type Output = u16;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        loop {
            let mut virtq = self.virtqueue.borrow_mut();
            if let Some(chain_head) = virtq.alloc_descriptor_chain(self.num_to_alloc) {
                return std::task::Poll::Ready(chain_head);
            }

            let mut empty = true;
            while let Some(_chain_head) = virtq.reclaim_used() {
                empty = false;
            }
            if !empty {
                continue;
            }

            virtq.alloc_waiters.push_back(cx.local_waker().clone());
            return std::task::Poll::Pending;
        }
    }
}

pub(super) struct Virtqueue {
    pub virt_addr: u64,
    pub queue_size: u16,
    pub queue_num: u16,
    pub queue_notify_off: u16, // This is the cfg value.

    device_kind: crate::VirtioDeviceKind,

    descriptors: &'static mut [VirtqDesc],
    available_ring: VirtqAvail,
    used_ring: VirtqUsed,

    free_head_idx: u16,
    next_used_idx: u16,

    wait_handle: SysHandle,

    // Most (all?) requests placed into virtqueues have descriptors pointing to
    // a header and a status. These are internal to VirtIO machinery; as our virtqueues
    // operate asynchronously, these buffers (the header and the status) cannot live
    // on stack; so we either need to allocate/deallocate them on each request, ask
    // the user to provide the memory to us with each request, or pre-allocate them
    // here. We preallocate them here.
    header_buffers: Vec<HeaderBuffer>,

    // These are actual parameters to use in `fn notify()`.
    notify_bar: *const PciBar,
    notify_offset: u64,

    queue_size_mask: u16, // queue_size - 1

    // The value of available_ring.next_available_idx at the last device
    // notification (doorbell); see notify_device_if_needed.
    last_kick_idx: u16,

    alloc_waiters: VecDeque<std::task::LocalWaker>,

    // For each slot we may have a waker.
    completion_waiters: Vec<Option<std::task::LocalWaker>>,

    virtio_f_event_idx_negotiated: bool,
}

impl Virtqueue {
    pub(super) fn allocate_virtqueue(
        dev: &VirtioDevice,
        queue_num: u16,
        queue_size: u16,
    ) -> Result<Rc<RefCell<Self>>> {
        assert!(queue_size > 0);
        // We don't do wrapping_add(), we `& queue_size_mask`.
        assert!(queue_size < u16::MAX);

        if !queue_size.is_power_of_two() {
            log::error!(
                "VirtQueue size for device {:?} is not a power of two: 0x{:x}",
                dev.pci_device.id,
                queue_size
            );
            return Err(ErrorKind::InvalidInput.into());
        }

        // VirtIO 1.1 spec says that both split and packed virtqueues have at most 2^15 items.
        if queue_size > (1 << 15) {
            log::error!(
                "VirtQueue size for device {:?} is too large: 0x{:x}",
                dev.pci_device.id,
                queue_size
            );
            return Err(ErrorKind::InvalidInput.into());
        }

        let queue_sz = queue_size as u64;

        // See VirtIO 1.1 spec, #2.6.
        let mem_sz: u64 = (18 * queue_sz) + 4;
        let mem_sz = super::align_up(mem_sz, 4);
        let mem_sz = mem_sz + 8 * queue_sz * 4;

        let virt_addr = super::mapper().alloc_contiguous_pages(mem_sz)?;

        let descriptors = unsafe {
            core::slice::from_raw_parts_mut(virt_addr as *mut VirtqDesc, queue_size as usize)
        };

        for idx in 0..(queue_size - 1) {
            descriptors[idx as usize].next = idx + 1;
        }
        descriptors[queue_size as usize - 1].next = 0;

        let available_ring = VirtqAvail::from_addr(virt_addr, queue_size);
        let used_ring = VirtqUsed::from_addr(virt_addr, queue_size);

        let mut header_buffers = Vec::with_capacity(queue_sz as usize);
        for _ in 0..queue_sz {
            let buffer = HeaderBuffer {
                buf: IoBuf::new_from_size_align(16).unwrap(),
                consumed: 0,
                in_use_by_device: false,
                in_use_by_completion: false,
            };
            header_buffers.push(buffer);
        }

        let mut completion_waiters = Vec::with_capacity(queue_size as usize);
        completion_waiters.resize(queue_size as usize, None);

        log::debug!("New virtqueue sz: {queue_size}");

        let self_ = Rc::new(RefCell::new(Virtqueue {
            virt_addr,
            device_kind: dev.kind(),
            queue_size,
            queue_num,
            queue_notify_off: 0,
            descriptors,
            available_ring,
            used_ring,
            free_head_idx: 0,
            next_used_idx: 0,
            wait_handle: SysHandle::NONE,
            last_kick_idx: 0,
            header_buffers,
            notify_bar: core::ptr::null(),
            notify_offset: 0,
            queue_size_mask: queue_size - 1,
            alloc_waiters: VecDeque::new(),
            completion_waiters,

            virtio_f_event_idx_negotiated: false,
        }));

        let self_clone = self_.clone();
        moto_async::LocalRuntime::spawn(async move {
            Self::reclaim_task(self_clone).await;
        });

        Self::spawn_monitoring_task(self_.clone());
        Ok(self_)
    }

    fn spawn_monitoring_task(this: Rc<RefCell<Self>>) {
        moto_async::LocalRuntime::spawn(async move {
            log::warn!("VirtQ monitoring thread started");
            let mut errors = 0;
            let mut prev_used = 0;
            loop {
                if errors == 0 {
                    moto_async::sleep(std::time::Duration::from_secs(1)).await;
                } else {
                    moto_async::sleep(std::time::Duration::from_millis(10)).await;
                }
                let vq = this.borrow();

                let driver_used_idx = vq.next_used_idx;
                if prev_used != driver_used_idx {
                    prev_used = driver_used_idx;
                    errors = 0;
                    continue;
                }

                let alloc_waiters = vq.alloc_waiters.len();
                let mut completion_waiters = 0;
                let mut cw_idx = 0;
                for (idx, cw) in vq.completion_waiters.iter().enumerate() {
                    if cw.is_some() {
                        completion_waiters += 1;
                        cw_idx = idx;
                    }
                }

                let has_used = vq.has_new_used();
                if has_used && (alloc_waiters + completion_waiters > 0) {
                    errors += 1;
                    let device_used_idx = unsafe { vq.used_ring.idx.read_volatile() };

                    log::error!(
                        "vq {:?}:{}: aw: {alloc_waiters} cw: {completion_waiters} driver used: 0x{driver_used_idx:x} device used: 0x{device_used_idx:x} idx: 0x{cw_idx:x}",
                        vq.device_kind,
                        vq.queue_num
                    );

                    if errors == 2 {
                        drop(vq);
                        let mut vq = this.borrow_mut();
                        let mut reclaimed = 0;
                        while let Some(_chain_head) = vq.reclaim_used() {
                            reclaimed += 1;
                        }

                        for waiter in vq.completion_waiters.iter() {
                            if let Some(waiter) = waiter {
                                log::error!(
                                    "waking a stalled completion waiter on {:?}; reclaimed: {reclaimed}",
                                    vq.device_kind
                                );
                                waiter.wake_by_ref();
                            }
                        }
                        errors = 0;
                    }
                } else {
                    errors = 0;
                }
            }
        });
    }

    async fn reclaim_task(this: Rc<RefCell<Self>>) {
        let wait_handle = this.borrow().wait_handle;

        loop {
            let mut virtq = this.borrow_mut();

            virtq.disable_irq();
            while let Some(_chain_head) = virtq.reclaim_used() {}

            virtq.enable_irq();
            if virtq.has_new_used() {
                continue;
            }

            drop(virtq);
            wait_handle.as_future().await.unwrap();
        }
    }

    pub fn queue_size(&self) -> u16 {
        self.queue_size
    }

    pub fn set_wait_handle(&mut self, handle: SysHandle) {
        self.wait_handle = handle;
    }

    pub fn set_f_event_idx_negotiated(&mut self) {
        self.virtio_f_event_idx_negotiated = true;
    }

    fn notify_device_if_needed(&mut self, new_idx: u16) {
        mfence();
        // Safety: safe by construction.
        unsafe {
            if self.virtio_f_event_idx_negotiated {
                // The spec's vring_need_event (virtio 1.1 §2.7.10): kick if
                // avail_event falls anywhere in the window of entries
                // published since the last kick, i.e. (last_kick, new_idx]
                // in wrapping u16 arithmetic. An exact-equality check
                // against the just-published index loses the doorbell when
                // the device arms avail_event concurrently with a batch of
                // publishes — survivable at high packet rates (the next
                // publish re-races it) but a permanent stall once
                // publishing itself waits for completions, as with
                // multi-descriptor TX chains exhausting the table.
                let event_idx = self.used_ring.avail_event.read_volatile();
                if new_idx
                    .wrapping_sub(event_idx)
                    .wrapping_sub(1)
                    < new_idx.wrapping_sub(self.last_kick_idx)
                {
                    (*self.notify_bar).write_u16(self.notify_offset, 0);
                    self.last_kick_idx = new_idx;
                }
            } else if (self.used_ring.flags as *const u16).read_volatile() == 0 {
                (*self.notify_bar).write_u16(self.notify_offset, 0);
                self.last_kick_idx = new_idx;
            }
        }
        mfence();
    }

    fn disable_irq(&mut self) {
        unsafe {
            if self.virtio_f_event_idx_negotiated {
                // NOOP: it's the way.
            } else {
                mfence();
                (self.available_ring.flags as *mut u16).write_volatile(1);
                mfence();
            }
        }
    }

    fn enable_irq(&mut self) {
        mfence();
        unsafe {
            if self.virtio_f_event_idx_negotiated {
                self.available_ring
                    .used_event
                    .write_volatile(self.next_used_idx);
            } else {
                (self.available_ring.flags as *mut u16).write_volatile(0);
            }
        }
        mfence();
    }

    pub fn set_notify_params(&mut self, notify_bar: *const PciBar, notify_offset: u64) {
        self.notify_bar = notify_bar;
        self.notify_offset = notify_offset;
    }

    fn update_and_increment_available_idx(&mut self, head: u16) {
        // Note: we can unconditionally add/increment available_idx
        //       because we successfully allocated (available) descriptors.
        mfence();
        let new_idx = unsafe {
            let idx = *self.available_ring.next_available_idx;
            ((&mut self.available_ring.ring[(idx & self.queue_size_mask) as usize]) as *mut u16)
                .write_volatile(head);
            mfence();

            // Note: we must wrap around at u16::MAX, not at queue_size, otherwise
            // both CHV and Qemu misbehave.
            let next_idx = idx.wrapping_add(1);
            self.available_ring
                .next_available_idx
                .write_volatile(next_idx);
            next_idx
        };
        self.notify_device_if_needed(new_idx);
    }

    pub fn alloc_descriptor_chain(&mut self, chain_len: u16) -> Option<u16> {
        debug_assert!(chain_len <= self.queue_size);
        let chain_start = self.free_head_idx;

        let mut curr = chain_start;
        let mut marked = 0_u16;
        for idx in 0..chain_len {
            debug_assert!(curr < self.queue_size);

            let header_buffer = &mut self.header_buffers[curr as usize];
            if header_buffer.in_use_by_device || header_buffer.in_use_by_completion {
                break;
            }
            header_buffer.in_use_by_device = true;
            marked += 1;

            let descriptor = self.get_descriptor_mut(curr);

            if idx == (chain_len - 1) {
                descriptor.flags = 0; // Clear VIRTQ_DESC_F_NEXT, if any.
                self.free_head_idx = descriptor.next;

                return Some(chain_start);
            }
            descriptor.flags = VIRTQ_DESC_F_NEXT;

            debug_assert_ne!(curr, descriptor.next);
            curr = descriptor.next;
        }

        // Allocation failed: clear "in_use" on exactly the `marked`
        // descriptors above. The blocking descriptor and everything past it
        // belong to in-flight chains (the free list wraps into them when it
        // runs out) and must not be touched: unmarking them would make their
        // completions report as done while the device still owns the memory.
        curr = chain_start;
        for _ in 0..marked {
            self.header_buffers[curr as usize].in_use_by_device = false;
            curr = self.get_descriptor_mut(curr).next;
        }

        None
    }

    fn free_descriptor_chain(&mut self, chain_head: u16) {
        let mut curr = chain_head;
        let free_head_idx = self.free_head_idx;

        // Note: if all descriptors have been allocated, and this one is the first
        // one, curr will be equal to free_head_idx.
        // debug_assert_ne!(curr, free_head_idx);

        loop {
            debug_assert!(!self.header_buffers[curr as usize].in_use_by_device);
            debug_assert!(!self.header_buffers[curr as usize].in_use_by_completion);

            let descriptor = self.get_descriptor_mut(curr);
            if descriptor.flags & VIRTQ_DESC_F_NEXT == 0 {
                descriptor.next = free_head_idx;
                break;
            }
            curr = descriptor.next;
        }

        self.free_head_idx = chain_head;

        // Wake a couple of waiters (this deallocation may free more descriptors
        // than the first waiter may consume).
        if let Some(waker) = self.alloc_waiters.pop_front() {
            waker.wake();
            if let Some(waker) = self.alloc_waiters.pop_front() {
                waker.wake();
            }
        }
    }

    /// Get a buffer to use with descriptor at idx; return the buffer and the next idx.
    pub fn get_buffer<T>(&mut self, idx: u16) -> (&'static mut T, u64, u16) {
        debug_assert!(idx < self.queue_size);
        debug_assert!(core::mem::size_of::<T>() <= 16);
        let next = self.get_descriptor_mut(idx).next;
        // Safety: checked above that the inded and the size are Ok.
        unsafe {
            let pbuf = &mut self.header_buffers[idx as usize].buf;
            let addr = pbuf.raw_ptr_mut() as usize;
            (
                (addr as *mut T).as_mut().unwrap(),
                pbuf.phys_addr() as u64,
                next,
            )
        }
    }

    /// The index of the descriptor following `idx` in its chain.
    pub(crate) fn next_idx(&self, idx: u16) -> u16 {
        self.get_descriptor(idx).next
    }

    fn get_descriptor_mut(&mut self, idx: u16) -> &mut VirtqDesc {
        debug_assert!(idx < self.queue_size);

        &mut self.descriptors[idx as usize]
    }

    fn get_descriptor(&self, idx: u16) -> &VirtqDesc {
        debug_assert!(idx < self.queue_size);

        &self.descriptors[idx as usize]
    }

    pub(crate) fn add_buffs<T>(
        this: Rc<RefCell<Self>>,
        data: &[UserData],
        outgoing: u16,
        incoming: u16,
        chain_head: u16,
        bytes: T,
    ) -> VqCompletion<T> {
        assert_ne!(outgoing + incoming, 0);
        assert_eq!(outgoing + incoming, data.len() as u16);

        let mut curr = chain_head;
        let mut this_mut = this.borrow_mut();

        let elements = outgoing + incoming;
        for el_idx in 0..elements {
            debug_assert!(this_mut.header_buffers[curr as usize].in_use_by_device);
            this_mut.header_buffers[curr as usize].in_use_by_completion = true;

            let descriptor = this_mut.get_descriptor_mut(curr);
            let el = data.get(el_idx as usize).unwrap();
            descriptor.addr = el.phys_addr;
            descriptor.len = el.len;

            let mut flags: u16 = 0;
            if el_idx < (elements - 1) {
                flags |= VIRTQ_DESC_F_NEXT;
            }
            if el_idx >= outgoing {
                flags |= VIRTQ_DESC_F_WRITE;
            }
            descriptor.flags = flags;
            curr = descriptor.next;
        }

        // Note: we can unconditionally add/increment available_idx
        //       because we successfully allocated (available) descriptors.
        this_mut.update_and_increment_available_idx(chain_head);
        core::mem::drop(this_mut);

        VqCompletion {
            chain_head,
            virtqueue: this,
            data: Some(bytes),
        }
    }

    fn has_new_used(&self) -> bool {
        mfence();
        self.next_used_idx != unsafe { self.used_ring.idx.read_volatile() }
    }

    fn reclaim_used(&mut self) -> Option<u16> {
        // See section 2.7.14 in Virtio PDF v 1.3.
        mfence();
        // SAFETY: safe by construction.
        if self.next_used_idx == unsafe { self.used_ring.idx.read_volatile() } {
            return None;
        }

        let head = self.next_used_idx & self.queue_size_mask;
        let elem = &self.used_ring.ring[head as usize];

        let chain_head = elem.id as u16;
        self.header_buffers[chain_head as usize].consumed = elem.len;

        let mut curr = chain_head;
        let mut chain_in_use = true;
        loop {
            self.header_buffers[curr as usize].in_use_by_device = false;
            if curr == chain_head {
                chain_in_use = self.header_buffers[curr as usize].in_use_by_completion;
            } else {
                debug_assert_eq!(
                    chain_in_use,
                    self.header_buffers[curr as usize].in_use_by_completion
                );
            }

            let descriptor = self.get_descriptor_mut(curr);
            if (descriptor.flags & VIRTQ_DESC_F_NEXT) != 0 {
                curr = descriptor.next;
            } else {
                break;
            }
        }

        if !chain_in_use {
            self.free_descriptor_chain(chain_head);
        }

        self.next_used_idx = self.next_used_idx.wrapping_add(1);
        assert!(chain_head < self.queue_size);
        if let Some(waker) = self.completion_waiters[chain_head as usize].take() {
            waker.wake();
        }
        Some(chain_head)
    }

    fn get_result(&self, chain_head: u16) -> u32 {
        let consumed = self.header_buffers[chain_head as usize].consumed;

        let mut curr = chain_head;
        loop {
            let header_buffer = &self.header_buffers[curr as usize];
            debug_assert!(!header_buffer.in_use_by_device);
            debug_assert!(header_buffer.in_use_by_completion);

            let descriptor = self.get_descriptor(curr);
            if descriptor.flags & VIRTQ_DESC_F_NEXT != 0 {
                curr = descriptor.next;
                continue;
            }

            // This is the last descriptor.
            return consumed;
        }
    }
}

impl Drop for Virtqueue {
    fn drop(&mut self) {
        log::error!("Virtqueue::drop(): not implemented");
    }
}

pub(crate) struct VqCompletion<T> {
    chain_head: u16,
    virtqueue: Rc<RefCell<Virtqueue>>,
    data: Option<T>, // Option because we need to take it out.
}

impl<T> VqCompletion<T> {
    fn do_poll(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<(T, Result<(u32)>)> {
        let mut virtq = self.virtqueue.borrow_mut();
        virtq.completion_waiters[self.chain_head as usize] = Some(cx.local_waker().clone());

        if !virtq.header_buffers[self.chain_head as usize].in_use_by_device {
            virtq.completion_waiters[self.chain_head as usize] = None;
            let consumed = virtq.get_result(self.chain_head);

            // log::debug!("completion done: OK: {consumed}");
            drop(virtq);
            return std::task::Poll::Ready((self.data.take().unwrap(), Ok(consumed)));
        }

        return std::task::Poll::Pending;
    } // fn poll()
}

impl<T> Drop for VqCompletion<T> {
    fn drop(&mut self) {
        let mut virtqueue = self.virtqueue.borrow_mut();
        let mut curr = self.chain_head;
        let mut chain_in_use = true;
        virtqueue.completion_waiters[self.chain_head as usize] = None;

        loop {
            virtqueue.header_buffers[curr as usize].in_use_by_completion = false;
            if curr == self.chain_head {
                chain_in_use = virtqueue.header_buffers[curr as usize].in_use_by_device;
            } else {
                debug_assert_eq!(
                    chain_in_use,
                    virtqueue.header_buffers[curr as usize].in_use_by_device
                );
            }

            let descriptor = virtqueue.get_descriptor(curr);
            if descriptor.flags & VIRTQ_DESC_F_NEXT != 0 {
                curr = descriptor.next;
                continue;
            } else {
                break;
            }
        }

        if !chain_in_use {
            virtqueue.free_descriptor_chain(self.chain_head);
        }
    }
}

pub struct WriteCompletion<T: Unpin> {
    pub(crate) vq_completion: VqCompletion<T>,
}

impl<T: Unpin> Future for WriteCompletion<T> {
    type Output = (T, Result<()>);

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.as_mut()
            .vq_completion
            .do_poll(cx)
            .map(|(val, res)| (val, res.map(|_| ())))
    }
}

/// Completion of a scatter-gather read: one request filling several 4K
/// buffers (see `BlockDevice::post_read_many`).
pub struct ReadManyCompletion<T: AsMut<IoBuf> + Unpin> {
    pub(crate) vq_completion: VqCompletion<Vec<T>>,
}

impl<T: AsMut<IoBuf> + Unpin> Future for ReadManyCompletion<T> {
    type Output = (Vec<T>, Result<()>);

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.as_mut()
            .vq_completion
            .do_poll(cx)
            .map(|(mut bufs, res)| {
                if res.is_ok() {
                    // As in ReadCompletion, the device-reported size is
                    // unreliable (it may include the status byte); each
                    // buffer is a full block.
                    for buf in &mut bufs {
                        buf.as_mut().set_len(4096);
                    }
                }

                (bufs, res.map(|_| ()))
            })
    }
}

pub struct ReadCompletion<T: AsMut<IoBuf> + Unpin> {
    pub(crate) vq_completion: VqCompletion<T>,
    pub(crate) size_adjustor: fn(u32) -> u32,
}

impl<T: AsMut<IoBuf> + Unpin> Future for ReadCompletion<T> {
    type Output = (T, Result<()>);

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.as_mut()
            .vq_completion
            .do_poll(cx)
            .map(|(mut val, res)| {
                if let Ok(sz) = res {
                    if sz != 4097 {
                        log::debug!("ReadCompletion done: {sz}");
                    }
                    val.as_mut().set_len((self.size_adjustor)(sz) as usize);
                }

                (val, res.map(|_| ()))
            })
    }
}
