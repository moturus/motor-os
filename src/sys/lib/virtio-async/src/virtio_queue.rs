//! VirtIO Queue.
//!
//! Note: the VirtIO spec explicitly states that requests from the available queue
//! may be processed in any order, and thus used request IDs can also appear in any
//! order. It thus _may_ seem important to keep track of out-of-order used idxes
//! coming in. But this will not help with throughput, only with latency under
//! high load scenarios; and as such tracking complicates the code and adds CPU
//! usage, it is not even clear that latency will be materially improved, so
//! out virtqueues below only track next_available and last_used.
use super::virtio_device::VirtioDevice;
use super::{le16, le32, le64};
use crate::pci::PciBar;
use crate::virtio_device::mapper;
use moto_async::AsFuture;
use moto_sys::SysHandle;
use std::cell::RefCell;
use std::io::{ErrorKind, Result};
use std::marker::PhantomData;
use std::rc::Rc;
use zerocopy::FromZeros;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

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
    _flags: &'static mut le16,     // Ignored/never used.
    next_available_idx: *mut le16, // "idx" in VirtIO spec.
    ring: &'static mut [le16],
    used_event: *mut le16,
}

unsafe impl Send for VirtqAvail {}

pub struct UserData {
    pub addr: u64,
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
                _flags: &mut *(flags_addr as *mut le16),
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
    _flags: &'static mut le16, // Ignored/never used.
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
            _flags: unsafe { &mut *(flags_addr as *mut le16) },
            idx: idx_addr as *const le16,
            ring,
            avail_event: avail_event_addr as *const le16,
        }
    }
}

#[derive(FromZeros)]
#[repr(C, align(8))]
struct HeaderBuffer {
    header: [u64; 2],
    consumed: u32, // From the descriptor.
    in_use_by_device: u8,
    in_use_by_completion: u8,
    _reserved: [u8; 2],
}

static _A: () = assert!(core::mem::size_of::<HeaderBuffer>() == 24);

pub struct Completion<'a> {
    chain_head: u16,
    virtqueue: Rc<RefCell<Virtqueue>>,
    _phantom_data: PhantomData<&'a ()>,
}

impl<'a> Future for Completion<'a> {
    // Return consumed len/bytes in u32; the status in u8.
    type Output = (u32, u8);

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        loop {
            let mut virtq = self.virtqueue.borrow_mut();
            if virtq.header_buffers[self.chain_head as usize].in_use_by_device == 0 {
                return std::task::Poll::Ready(virtq.get_result(self.chain_head));
            }

            if let Some(_chain_head) = virtq.reclaim_used() {
                continue;
            }

            let mut pinned = Box::pin(virtq.wait_handle.as_future());
            core::mem::drop(virtq);

            match pinned.as_mut().poll(cx) {
                std::task::Poll::Ready(_) => continue,
                std::task::Poll::Pending => {
                    self.virtqueue.borrow().notify();
                    return std::task::Poll::Pending;
                }
            }
        }
    }
}

impl Drop for Completion<'_> {
    fn drop(&mut self) {
        let mut virtqueue = self.virtqueue.borrow_mut();
        let mut curr = self.chain_head;
        let mut chain_in_use = true;
        loop {
            virtqueue.header_buffers[curr as usize].in_use_by_completion = 0;
            if curr == self.chain_head {
                chain_in_use = virtqueue.header_buffers[curr as usize].in_use_by_device == 1;
            } else {
                debug_assert_eq!(
                    chain_in_use,
                    virtqueue.header_buffers[curr as usize].in_use_by_device == 1
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

pub(super) struct Virtqueue {
    pub virt_addr: u64,
    pub queue_size: u16,
    pub queue_num: u16,
    pub queue_notify_off: u16, // This is the cfg value.

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
    header_buffers: &'static mut [HeaderBuffer],
    header_buffers_phys_addr: u64,

    // These are actual parameters to use in `fn notify()`.
    notify_bar: *const PciBar,
    notify_offset: u64,

    queue_size_mask: u16, // queue_size - 1
}

impl Virtqueue {
    pub(super) fn allocate(
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

        let header_buffers_vaddr = super::mapper()
            .alloc_contiguous_pages((core::mem::size_of::<HeaderBuffer>() as u64) * queue_sz)?;
        let header_buffers = unsafe {
            core::slice::from_raw_parts_mut(
                header_buffers_vaddr as *mut HeaderBuffer,
                queue_size as usize,
            )
        };

        let header_buffers_phys_addr = super::mapper().virt_to_phys(header_buffers_vaddr)?;

        log::debug!("New virtqueue sz: {queue_size}");

        Ok(Rc::new(RefCell::new(Virtqueue {
            virt_addr,
            queue_size,
            queue_num,
            queue_notify_off: 0,
            descriptors,
            available_ring,
            used_ring,
            free_head_idx: 0,
            next_used_idx: 0,
            wait_handle: SysHandle::NONE,
            header_buffers,
            header_buffers_phys_addr,
            notify_bar: core::ptr::null(),
            notify_offset: 0,
            queue_size_mask: queue_size - 1,
        })))
    }

    pub fn queue_size(&self) -> u16 {
        self.queue_size
    }

    pub fn set_wait_handle(&mut self, handle: SysHandle) {
        self.wait_handle = handle;
    }

    fn notify(&self) {
        // Safety: safe by construction.
        unsafe { (*self.notify_bar).write_u16(self.notify_offset, 0) };
    }

    pub fn set_notify_params(&mut self, notify_bar: *const PciBar, notify_offset: u64) {
        self.notify_bar = notify_bar;
        self.notify_offset = notify_offset;
    }

    pub fn wait_handle(&self) -> SysHandle {
        self.wait_handle
    }

    fn update_and_increment_available_idx(&mut self, head: u16) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        unsafe {
            let idx = *self.available_ring.next_available_idx;
            ((&mut self.available_ring.ring[(idx & self.queue_size_mask) as usize]) as *mut u16)
                .write_volatile(head);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

            // Note: we must wrap around at u16::MAX, not at queue_size, otherwise
            // both CHV and Qemu misbehave.
            let next_idx = idx.wrapping_add(1);
            self.available_ring
                .next_available_idx
                .write_volatile(next_idx);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }

    pub fn alloc_descriptor_chain(&mut self, chain_len: u16) -> Option<u16> {
        debug_assert!(chain_len <= self.queue_size);
        let chain_start = self.free_head_idx;

        let mut curr = chain_start;
        for idx in 0..chain_len {
            debug_assert!(curr < self.queue_size);

            let header_buffer = &mut self.header_buffers[curr as usize];
            debug_assert_eq!(0, header_buffer.in_use_by_device);
            debug_assert_eq!(0, header_buffer.in_use_by_completion);
            header_buffer.in_use_by_device = 1;

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

        // Allocation failed: clear "in_use".
        curr = chain_start;
        loop {
            if self.header_buffers[curr as usize].in_use_by_device == 0 {
                break;
            }
            self.header_buffers[curr as usize].in_use_by_device = 0;
            curr = self.get_descriptor_mut(curr).next;
        }

        return None;
    }

    fn free_descriptor_chain(&mut self, chain_head: u16) {
        let mut curr = chain_head;
        let free_head_idx = self.free_head_idx;
        debug_assert_ne!(curr, free_head_idx);

        loop {
            debug_assert_eq!(0, self.header_buffers[curr as usize].in_use_by_device);
            debug_assert_eq!(0, self.header_buffers[curr as usize].in_use_by_completion);

            let descriptor = self.get_descriptor_mut(curr);
            if descriptor.flags & VIRTQ_DESC_F_NEXT == 0 {
                descriptor.next = free_head_idx;
                break;
            }
            curr = descriptor.next;
        }

        self.free_head_idx = chain_head;
    }

    /// Get a buffer to use with descriptor at idx; return the buffer and the next idx.
    pub fn get_buffer<T>(&mut self, idx: u16) -> (&'static mut T, u16) {
        debug_assert!(idx < self.queue_size);
        debug_assert!(core::mem::size_of::<T>() <= 16);
        let next = self.get_descriptor_mut(idx).next;
        // Safety: checked above that the inded and the size are Ok.
        unsafe {
            let addr = (&mut self.header_buffers[idx as usize].header) as *mut _ as usize;
            ((addr as *mut T).as_mut().unwrap(), next)
        }
    }

    fn get_descriptor_mut(&mut self, idx: u16) -> &mut VirtqDesc {
        debug_assert!(idx < self.queue_size);

        &mut self.descriptors[idx as usize]
    }

    fn get_descriptor(&self, idx: u16) -> &VirtqDesc {
        debug_assert!(idx < self.queue_size);

        &self.descriptors[idx as usize]
    }

    pub fn add_buffs<'a>(
        this: Rc<RefCell<Self>>,
        data: &[UserData],
        outgoing: u16,
        incoming: u16,
        chain_head: u16,
    ) -> Completion<'a> {
        assert_ne!(outgoing + incoming, 0);
        assert_eq!(outgoing + incoming, data.len() as u16);

        let mut curr = chain_head;
        let mut this_mut = this.borrow_mut();

        let elements = outgoing + incoming;
        for el_idx in 0..elements {
            debug_assert_eq!(1, this_mut.header_buffers[curr as usize].in_use_by_device);
            this_mut.header_buffers[curr as usize].in_use_by_completion = 1;

            let descriptor = this_mut.get_descriptor_mut(curr);
            let el = data.get(el_idx as usize).unwrap();
            descriptor.addr = super::mapper().virt_to_phys(el.addr).unwrap();
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

        this_mut.update_and_increment_available_idx(chain_head);
        // this_mut.notify();
        core::mem::drop(this_mut);

        Completion {
            chain_head,
            virtqueue: this,
            _phantom_data: PhantomData,
        }
    }

    pub fn reclaim_used(&mut self) -> Option<u16> {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        if self.next_used_idx == unsafe { self.used_ring.idx.read_volatile() } {
            return None;
        }

        let head = self.next_used_idx;
        let elem = &self.used_ring.ring[head as usize];

        let chain_head = elem.id as u16;
        self.header_buffers[chain_head as usize].consumed = elem.len;

        let mut curr = chain_head;
        let mut chain_in_use = true;
        loop {
            self.header_buffers[curr as usize].in_use_by_device = 0;
            if curr == chain_head {
                chain_in_use = self.header_buffers[curr as usize].in_use_by_completion == 1;
            } else {
                debug_assert_eq!(
                    chain_in_use,
                    self.header_buffers[curr as usize].in_use_by_completion == 1
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

        self.next_used_idx = (self.next_used_idx + 1) & self.queue_size_mask;
        Some(chain_head)
    }

    fn get_result(&self, chain_head: u16) -> (u32, u8) {
        let consumed = self.header_buffers[chain_head as usize].consumed;

        let mut curr = chain_head;
        loop {
            let header_buffer = &self.header_buffers[curr as usize];
            debug_assert_eq!(0, header_buffer.in_use_by_device);
            debug_assert_eq!(1, header_buffer.in_use_by_completion);

            let descriptor = self.get_descriptor(curr);
            if descriptor.flags & VIRTQ_DESC_F_NEXT != 0 {
                curr = descriptor.next;
                continue;
            }

            // This is the last descriptor, with status.
            return (consumed, header_buffer.header[0] as u8);
        }
    }
}

impl Drop for Virtqueue {
    fn drop(&mut self) {
        log::error!("Virtqueue::drop(): not implemented");
    }
}
