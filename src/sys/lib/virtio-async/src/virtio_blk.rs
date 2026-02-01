use async_trait::async_trait;
use core::sync::atomic::*;
use moto_rt::spinlock::SpinLock;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::io::Result;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use zerocopy::FromZeros;

use super::pci::PciBar;
use super::virtio_device::VirtioDevice;
use crate::Completion;
use crate::virtio_queue::Virtqueue;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Little Endian is often assumed here.");

// Although virtio uses blocks of 512 bytes, we expose blocks of 4k.
pub const BLOCK_SIZE: usize = 4096;

/*
 *  VIRTIO_BLK_F_SIZE_MAX (1) Maximum size of any single segment is in size_max.
 *  VIRTIO_BLK_F_SEG_MAX (2) Maximum number of segments in a request is in seg_max.
 *  VIRTIO_BLK_F_GEOMETRY (4) Disk-style geometry specified in geometry.
 *  VIRTIO_BLK_F_RO (5) Device is read-only.
 *  VIRTIO_BLK_F_BLK_SIZE (6) Block size of disk is in blk_size.
 *  VIRTIO_BLK_F_FLUSH (9) Cache flush command support.
 *  VIRTIO_BLK_F_TOPOLOGY (10) Device exports information on optimal I/O alignment.
 *  VIRTIO_BLK_F_CONFIG_WCE (11) Device can toggle its cache between writeback and writethrough modes.
 *  VIRTIO_BLK_F_DISCARD (13) Device can support discard command, maximum discard sectors size in
 *      max_discard_sectors and maximum discard segment number in max_discard_seg.
 *  VIRTIO_BLK_F_WRITE_ZEROES (14) Device can support write zeroes command, maximum write zeroes
 *      sectors size in max_write_zeroes_sectors and maximum write zeroes segment number in max_write_-
 *      zeroes_seg.
 */
// Virtio-Blk features used here.
//const VIRTIO_BLK_F_SIZE_MAX : u64 = 1u64 << 1;
//const VIRTIO_BLK_F_SEG_MAX  : u64 = 1u64 << 2;
const VIRTIO_BLK_F_RO: u64 = 1u64 << 5;
// const VIRTIO_BLK_F_CONFIG_WCE: u64 = 1u64 << 11;
const VIRTIO_BLK_F_FLUSH: u64 = 1u64 << 9;

// See struct virtio_blk_req in VirtIO spec.
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct BlkHeader {
    type_: u32,
    _reserved: u32,
    sector: u64,
}

// NOTE: VIRTIO_BLK_F_BLK_SIZE is read-only, i.e. the driver cannot set the block size to e.g. 4K.
//       It is 512 if not negotiated, 512 by default, and hard to configure the VMM to make
//       it something else. So we don't bother with anything other than 512.
//const VIRTIO_BLK_F_BLK_SIZE : u64 = 1u64 << 6;

pub struct BlockDevice {
    dev: Box<VirtioDevice>,
    capacity: u64, // The number of sectors of BLOCK_SIZE.
    read_only: bool,
}

impl BlockDevice {
    /// The number of sectors (512 bytes) the device has.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    pub fn wait_handle(&self) -> moto_sys::SysHandle {
        assert_eq!(1, self.dev.virtqueues.len());
        self.dev.virtqueues[0].borrow().wait_handle()
    }

    fn self_init(&mut self) -> Result<()> {
        self.dev.acknowledge_driver(); // Step 3
        self.negotiate_features()?; // Steps 4, 5, 6
        self.dev.init_virtqueues(1, 1)?; // Step 7
        self.dev.driver_ok(); // Step 8

        let notify_cap = self.dev.notify_cfg.unwrap();
        let notify_bar = self.dev.pci_device.bars[notify_cap.bar as usize]
            .as_ref()
            .unwrap() as *const PciBar;
        let notify_offset = notify_cap.offset as u64
            + (notify_cap.notify_off_multiplier as u64
                * self.dev.virtqueues[0].borrow().queue_notify_off as u64);

        self.dev.virtqueues[0]
            .borrow_mut()
            .set_notify_params(notify_bar, notify_offset);

        Ok(())
    }

    pub(super) fn init(dev: Box<VirtioDevice>) -> Result<BlockDevice> {
        if dev.device_cfg.is_none() {
            log::warn!("Skiping VirtioBlk device without device configuration.");
            return Err(ErrorKind::Other.into());
        }

        let mut blk = BlockDevice {
            dev,
            capacity: 0,
            read_only: true,
        };

        match blk.self_init() {
            Ok(()) => {
                log::debug!(
                    "Initialized Virtio BLOCK device {:?}: capacity: 0x{:x} read only: {}.",
                    blk.dev.pci_device.id,
                    blk.capacity,
                    blk.read_only
                );
                Ok(blk)
            }
            Err(err) => {
                log::error!("Failed to initialize VirtioBlk device.");
                blk.dev.mark_failed();
                Err(err)
            }
        }
    }

    // Step 4
    fn negotiate_features(&mut self) -> Result<()> {
        let features_available = self.dev.get_available_features();
        log::debug!("BLK devices features: 0x{features_available:x}");

        if (features_available & super::virtio_device::VIRTIO_F_VERSION_1) == 0 {
            log::warn!(
                "Virtio BLK device {:?}: VIRTIO_F_VERSION_1 feature not available; features: 0x{:x}.",
                self.dev.pci_device.id,
                features_available
            );
            return Err(ErrorKind::Other.into());
        }

        if (features_available & VIRTIO_BLK_F_FLUSH) == 0 {
            return Err(ErrorKind::Other.into());
        }

        let features_acked = super::virtio_device::VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_FLUSH;
        // | VIRTIO_BLK_F_RO;
        // (VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_SIZE_MAX | VIRTIO_BLK_F_SEG_MAX | VIRTIO_BLK_F_RO | VIRTIO_BLK_F_BLK_SIZE);
        //  | VIRTIO_BLK_F_RO);
        self.dev.write_enabled_features(features_acked);
        self.dev.confirm_features()?;

        self.read_only = (features_acked & VIRTIO_BLK_F_RO) != 0;

        let device_cfg = self.dev.device_cfg.as_ref().unwrap();
        let cfg_bar: &PciBar = self.dev.pci_device.bars[device_cfg.bar as usize]
            .as_ref()
            .unwrap();
        let capacity = cfg_bar.read_u64(device_cfg.offset as u64);
        self.capacity = capacity;

        Ok(())
    }

    #[inline(never)]
    pub fn post_read<'a>(
        this: Rc<RefCell<Self>>,
        sector: u64,
        buf: &'a mut [u8],
    ) -> Option<Completion<'a>> {
        assert!(buf.len() <= BLOCK_SIZE);
        assert_eq!(0, (buf.as_ptr() as usize) & (BLOCK_SIZE - 1));

        let vq = this.borrow().dev.virtqueues[0].clone();
        let mut virtqueue = vq.borrow_mut();
        let chain_head = virtqueue.alloc_descriptor_chain(3)?;

        let (header, next_idx) = virtqueue.get_buffer::<BlkHeader>(chain_head);

        *header = BlkHeader {
            type_: 0, /* VIRTIO_BLK_T_IN */
            _reserved: 0,
            sector,
        };

        const VIRTIO_BLK_S_OK: u8 = 0;
        const VIRTIO_BLK_S_IOERR: u8 = 1;
        const VIRTIO_BLK_S_UNSUPP: u8 = 2;

        // If we use a single byte for status, CHV corrupts the stack (writes more than one byte).
        let (status, _) = virtqueue.get_buffer::<u64>(next_idx);
        *status = VIRTIO_BLK_S_UNSUPP as u64; // Note: we assume LE.

        use super::virtio_queue::UserData;
        let buffs: [UserData; 3] = [
            UserData {
                addr: header as *mut _ as usize as u64,
                len: core::mem::size_of::<BlkHeader>() as u32,
            },
            UserData {
                addr: buf.as_mut_ptr() as usize as u64,
                len: buf.len() as u32,
            },
            UserData {
                addr: status as *mut _ as usize as u64,
                len: 1,
            },
        ];

        core::mem::drop(virtqueue);
        let completion = Virtqueue::add_buffs(vq, &buffs, 1, 2, chain_head);

        Some(completion)
    }

    #[inline(never)]
    pub fn post_write<'a>(
        this: Rc<RefCell<Self>>,
        sector: u64,
        buf: &'a [u8],
    ) -> Option<Completion<'a>> {
        assert!(buf.len() <= BLOCK_SIZE);
        assert_eq!(0, (buf.as_ptr() as usize) & (BLOCK_SIZE - 1));

        let vq = this.borrow().dev.virtqueues[0].clone();
        let mut virtqueue = vq.borrow_mut();
        let chain_head = virtqueue.alloc_descriptor_chain(3)?;

        let (header, next_idx) = virtqueue.get_buffer::<BlkHeader>(chain_head);

        *header = BlkHeader {
            type_: 1, /* VIRTIO_BLK_T_OUT */
            _reserved: 0,
            sector,
        };

        const VIRTIO_BLK_S_OK: u8 = 0;
        const VIRTIO_BLK_S_IOERR: u8 = 1;
        const VIRTIO_BLK_S_UNSUPP: u8 = 2;

        // If we use a single byte for status, CHV corrupts the stack (writes more than one byte).
        let (status, _) = virtqueue.get_buffer::<u64>(next_idx);
        *status = VIRTIO_BLK_S_UNSUPP as u64; // Note: we assume LE.

        use super::virtio_queue::UserData;
        let buffs: [UserData; 3] = [
            UserData {
                addr: header as *mut _ as usize as u64,
                len: core::mem::size_of::<BlkHeader>() as u32,
            },
            UserData {
                addr: buf.as_ptr() as usize as u64,
                len: buf.len() as u32,
            },
            UserData {
                addr: status as *mut _ as usize as u64,
                len: 1,
            },
        ];

        core::mem::drop(virtqueue);
        let completion = Virtqueue::add_buffs(vq, &buffs, 2, 1, chain_head);

        Some(completion)
    }

    /// Returns the ID of the submitted request.
    #[inline(never)]
    pub fn post_flush<'a>(this: Rc<RefCell<Self>>) -> Option<Completion<'a>> {
        let vq = this.borrow().dev.virtqueues[0].clone();
        let mut virtqueue = vq.borrow_mut();
        let chain_head = virtqueue.alloc_descriptor_chain(2)?;

        let (header, next_idx) = virtqueue.get_buffer::<BlkHeader>(chain_head);

        *header = BlkHeader {
            type_: 4, /* VIRTIO_BLK_T_FLUSH */
            _reserved: 0,
            sector: 0,
        };

        const VIRTIO_BLK_S_OK: u8 = 0;
        const VIRTIO_BLK_S_IOERR: u8 = 1;
        const VIRTIO_BLK_S_UNSUPP: u8 = 2;

        // If we use a single byte for status, CHV corrupts the stack (writes more than one byte).
        let (status, _) = virtqueue.get_buffer::<u64>(next_idx);
        *status = VIRTIO_BLK_S_UNSUPP as u64; // Note: we assume LE.

        use super::virtio_queue::UserData;
        let buffs: [UserData; 2] = [
            UserData {
                addr: header as *mut _ as usize as u64,
                len: core::mem::size_of::<BlkHeader>() as u32,
            },
            UserData {
                addr: status as *mut _ as usize as u64,
                len: 1,
            },
        ];

        core::mem::drop(virtqueue);
        let completion = Virtqueue::add_buffs(vq, &buffs, 1, 1, chain_head);

        Some(completion)
    }

    pub fn notify(this: Rc<RefCell<Self>>) {
        this.borrow().dev.virtqueues[0].borrow().notify();
    }
}
