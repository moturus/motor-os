// VirtIO Queue.

use crate::virtio_device::mapper;

use super::is_power_of_two;
use super::virtio_device::VirtioDevice;

use super::{le16, le32, le64};

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

#[repr(C, packed)]
struct VirtqDesc {
    addr: le64,
    len: le32,
    flags: le16,
    next: le16,
}

struct VirtqAvail {
    _flags: &'static mut le16, // Ignored/never used.
    idx: &'static mut le16,
    ring: &'static mut [le16],
    used_event: &'static mut le16,
}

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
                idx: &mut *(idx_addr as *mut le16),
                ring,
                used_event: &mut *(used_event_addr as *mut le16),
            }
        }
    }
}

#[repr(C)]
struct VirtqUsedElem {
    id: le32,  // le32,
    len: le32, // le32,
}

struct VirtqUsed {
    _flags: &'static mut le16, // Ignored/never used.
    idx: &'static mut le16,
    ring: &'static mut [VirtqUsedElem],
    avail_event: &'static mut le16,
}

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
            idx: unsafe { &mut *(idx_addr as *mut le16) },
            ring,
            avail_event: unsafe { &mut *(avail_event_addr as *mut le16) },
        }
    }
}

pub(super) struct Virtqueue {
    pub virt_addr: u64,
    pub queue_size: u16,
    pub queue_num: u16,
    pub queue_notify_off: u16,

    descriptors: &'static mut [VirtqDesc],
    available_ring: VirtqAvail,
    used_ring: VirtqUsed,

    free_head_idx: u16,
    last_used_idx: u16,

    wait_handles: alloc::vec::Vec<crate::WaitHandle>,
}

impl Virtqueue {
    pub(super) fn allocate(
        dev: &VirtioDevice,
        queue_num: u16,
        queue_size: u16,
    ) -> Result<Self, ()> {
        assert!(queue_size > 0);
        if !is_power_of_two!(queue_size) {
            log::error!(
                "VirtQueue size for device {:?} is not a power of two: 0x{:x}",
                dev.pci_device.id,
                queue_size
            );
            return Err(());
        }

        // VirtIO 1.1 spec says that both split and packed virtqueues have at most 2^15 items.
        if queue_size > (1 << 15) {
            log::error!(
                "VirtQueue size for device {:?} is too large: 0x{:x}",
                dev.pci_device.id,
                queue_size
            );
            return Err(());
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

        Ok(Virtqueue {
            virt_addr,
            queue_size,
            queue_num,
            queue_notify_off: 0,
            descriptors,
            available_ring,
            used_ring,
            free_head_idx: 0,
            last_used_idx: 0,
            wait_handles: alloc::vec![],
        })
    }

    pub fn add_wait_handle(&mut self, handle: crate::WaitHandle) {
        self.wait_handles.push(handle);
    }

    pub fn wait_deprecated(&self) -> Result<(), ()> {
        if self.more_used_deprecated() {
            return Ok(());
        }
        if self.wait_handles.is_empty() {
            return Err(()); // Nothing to wait on.
        }
        if self.wait_handles.len() > 2 {
            moto_sys::syscalls::SysMem::log(
                alloc::format!("too many wait handles: {}", self.wait_handles.len()).as_str(),
            )
            .ok();
        }
        assert!(self.wait_handles.len() <= 2);
        let mut handles = [0_u64; 2];

        for idx in 0..self.wait_handles.len() {
            handles[idx] = self.wait_handles[idx];
        }
        mapper().wait(&mut handles)
    }

    pub fn wait_handles(&self) -> &[crate::WaitHandle] {
        &self.wait_handles
    }

    fn update_available(&mut self, head: u16) -> u16 {
        let idx = *self.available_ring.idx % self.queue_size;
        self.available_ring.ring[idx as usize] = head;
        idx
    }

    fn increment_available_idx(&mut self, cnt: u16) {
        let val = (*self.available_ring.idx).wrapping_add(cnt);
        *self.available_ring.idx = val;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }

    fn get_descriptor(&mut self, idx: u16) -> &mut VirtqDesc {
        assert!(idx < self.queue_size);

        &mut self.descriptors[idx as usize]
    }

    pub fn add_buf(&mut self, data: &[UserData], outgoing: u16, incoming: u16) -> u16 {
        assert_ne!(outgoing + incoming, 0);
        assert_eq!(outgoing + incoming, data.len() as u16);

        core::sync::atomic::fence(core::sync::atomic::Ordering::AcqRel);
        let mut idx = self.free_head_idx;
        let req_id = idx;

        let elements = outgoing + incoming;

        for el_idx in 0..elements {
            let descriptor = self.get_descriptor(idx);
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

            idx = descriptor.next;
        }

        self.update_available(self.free_head_idx);
        self.free_head_idx = idx;

        self.increment_available_idx(1);
        req_id
    }

    // Returns true if the host should be notified of the event.
    pub fn add_rx_buf(&mut self, phys_addr: u64, len: u32, descriptor_idx: u16) -> bool {
        let descriptor = self.get_descriptor(descriptor_idx);
        descriptor.addr = phys_addr;
        descriptor.len = len;
        descriptor.flags = VIRTQ_DESC_F_WRITE;
        let updated_idx = self.update_available(descriptor_idx);

        self.increment_available_idx(1);
        let avail_event = *self.used_ring.avail_event % self.queue_size;
        updated_idx <= avail_event || avail_event == 0
    }

    // Returns true if the host should be notified of the event.
    pub fn add_tx_buf(&mut self, phys_addr: u64, descriptor_idx: u16, len: u32) -> bool {
        let descriptor_idx = descriptor_idx << 1;

        // Net header.
        let descriptor = self.get_descriptor(descriptor_idx);
        descriptor.addr = phys_addr;
        descriptor.len = super::virtio_net::NET_HEADER_LEN as u32;
        descriptor.flags = VIRTQ_DESC_F_NEXT;

        // Net bytes.
        let descriptor = self.get_descriptor(descriptor_idx + 1);
        descriptor.addr = phys_addr + (super::virtio_net::NET_HEADER_LEN as u64);
        descriptor.len = len;
        descriptor.flags = 0;

        let updated_idx = self.update_available(descriptor_idx);

        self.increment_available_idx(1);
        let avail_event = *self.used_ring.avail_event % self.queue_size;
        updated_idx <= avail_event || avail_event == 0
    }

    pub fn get_completed_rx_buf(&mut self) -> Option<(u16, u32)> {
        // Having Acquire here and Release below is not enough (rnetbench hangs).
        core::sync::atomic::fence(core::sync::atomic::Ordering::AcqRel);
        if self.last_used_idx == *self.used_ring.idx {
            return None;
        }

        let head = self.last_used_idx % self.queue_size;
        let elem = &self.used_ring.ring[head as usize];

        let idx = elem.id as u16;
        let consumed = elem.len;

        let val = self.last_used_idx.wrapping_add(1);
        self.last_used_idx = val;
        *self.available_ring.used_event = val;
        core::sync::atomic::fence(core::sync::atomic::Ordering::AcqRel);

        Some((idx, consumed))
    }

    pub fn get_completed_tx_buf(&mut self) -> Option<u16> {
        // Having Acquire here and Release below is not enough (rnetbench hangs).
        core::sync::atomic::fence(core::sync::atomic::Ordering::AcqRel);
        if self.last_used_idx == *self.used_ring.idx {
            return None;
        }

        let head = self.last_used_idx % self.queue_size;
        let elem = &self.used_ring.ring[head as usize];

        let idx = elem.id as u16;
        assert_eq!(0, idx & 1);

        let val = self.last_used_idx.wrapping_add(1);
        self.last_used_idx = val;
        *self.available_ring.used_event = val;
        core::sync::atomic::fence(core::sync::atomic::Ordering::AcqRel);

        Some(idx >> 1)
    }

    pub fn more_used_deprecated(&self) -> bool {
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        self.last_used_idx != *self.used_ring.idx
    }

    pub fn reclaim_used_deprecated(&mut self) -> Option<u16> {
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        if self.last_used_idx == *self.used_ring.idx {
            return None;
        }

        let head = self.last_used_idx % self.queue_size;
        let elem = &self.used_ring.ring[head as usize];

        let mut idx = elem.id as u16;
        let req_id = idx;
        loop {
            let descriptor = self.get_descriptor(idx);
            if (descriptor.flags & VIRTQ_DESC_F_NEXT) != 0 {
                idx = descriptor.next;
            } else {
                assert!(descriptor.next == self.free_head_idx);
                self.free_head_idx = idx;
                break;
            }
        }

        let val = self.last_used_idx.wrapping_add(1);
        self.last_used_idx = val;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        Some(req_id)
    }

    pub fn consume_used_deprecated(&mut self) -> u32 {
        if !self.more_used_deprecated() {
            return 0;
        }

        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let head = self.last_used_idx % self.queue_size;
        let elem = &self.used_ring.ring[head as usize];

        let mut idx = elem.id as u16;
        let consumed = elem.len;

        loop {
            let descriptor = self.get_descriptor(idx);
            if (descriptor.flags & VIRTQ_DESC_F_NEXT) != 0 {
                // TODO: fix below.
                #[allow(unused_assignments)]
                {
                    idx = descriptor.next;
                }
            } else {
                assert!(descriptor.next == self.free_head_idx);
                self.free_head_idx = idx;
                break;
            }
        }

        let val = self.last_used_idx.wrapping_add(1);
        self.last_used_idx = val;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

        consumed
    }
}

impl Drop for Virtqueue {
    fn drop(&mut self) {
        log::error!("Virtqueue::drop(): not implemented");
    }
}
