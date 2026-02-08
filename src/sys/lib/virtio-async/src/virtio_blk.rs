use async_trait::async_trait;
use core::sync::atomic::*;
use moto_rt::spinlock::SpinLock;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::io::Result;
use std::marker::PhantomData;
use std::rc::Rc;
use zerocopy::FromZeros;

use super::pci::PciBar;
use super::virtio_device::VirtioDevice;
use crate::WriteCompletion;
use crate::virtio_queue::ReadCompletion;
use crate::virtio_queue::Virtqueue;
use crate::virtio_queue::VqAlloc;

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
    dev: Rc<RefCell<VirtioDevice>>,
    virtqueue: Rc<RefCell<Virtqueue>>,
    capacity: u64, // The number of sectors of BLOCK_SIZE.
    read_only: bool,
}

impl BlockDevice {
    /// The number of sectors (512 bytes) the device has.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    pub fn wait_handle(&self) -> moto_sys::SysHandle {
        self.virtqueue.borrow().wait_handle()
    }

    pub(super) fn init(dev: Rc<RefCell<VirtioDevice>>) -> Result<Rc<BlockDevice>> {
        let mut dev_mut = dev.borrow_mut();

        if dev_mut.device_cfg.is_none() {
            log::warn!("Skiping VirtioBlk device without device configuration.");
            return Err(ErrorKind::Other.into());
        }

        dev_mut.acknowledge_driver(); // Step 3
        let (capacity, read_only) = Self::negotiate_features(&mut dev_mut)?; // Steps 4, 5, 6
        dev_mut.init_virtqueues(1, 1)?; // Step 7
        dev_mut.driver_ok(); // Step 8

        let virtqueue = dev_mut.virtqueues[0].clone();

        let notify_cap = dev_mut.notify_cfg.unwrap();
        let notify_bar = dev_mut.pci_device.bars[notify_cap.bar as usize]
            .as_ref()
            .unwrap() as *const PciBar;
        let notify_offset = notify_cap.offset as u64
            + (notify_cap.notify_off_multiplier as u64
                * virtqueue.borrow().queue_notify_off as u64);

        virtqueue
            .borrow_mut()
            .set_notify_params(notify_bar, notify_offset);

        log::debug!(
            "Initialized Virtio BLOCK device {:?}: capacity: 0x{:x} read only: {}.",
            dev_mut.pci_device.id,
            capacity,
            read_only
        );

        drop(dev_mut);

        Ok(Rc::new(BlockDevice {
            dev,
            capacity,
            read_only,
            virtqueue,
        }))
    }

    // Step 4; returns (capacity, read_only)
    fn negotiate_features(dev: &mut VirtioDevice) -> Result<(u64, bool)> {
        let features_available = dev.get_available_features();
        log::debug!("BLK devices features: 0x{features_available:x}");

        if (features_available & super::virtio_device::VIRTIO_F_VERSION_1) == 0 {
            log::warn!(
                "Virtio BLK device {:?}: VIRTIO_F_VERSION_1 feature not available; features: 0x{:x}.",
                dev.pci_device.id,
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
        dev.write_enabled_features(features_acked);
        dev.confirm_features()?;

        let read_only = (features_acked & VIRTIO_BLK_F_RO) != 0;

        let device_cfg = dev.device_cfg.as_ref().unwrap();
        let cfg_bar: &PciBar = dev.pci_device.bars[device_cfg.bar as usize]
            .as_ref()
            .unwrap();
        let capacity = cfg_bar.read_u64(device_cfg.offset as u64);

        Ok((capacity, read_only))
    }

    #[inline(never)]
    pub async fn post_read<T: AsMut<[u8]>>(
        self: Rc<Self>,
        sector: u64,
        mut bytes: T,
    ) -> ReadCompletion<T> {
        let chain_head = VqAlloc::new(self.virtqueue.clone(), 3).await;
        let mut virtqueue = self.virtqueue.borrow_mut();

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

        let buf = bytes.as_mut();
        assert!(buf.len() <= BLOCK_SIZE);
        assert_eq!(0, (buf.as_ptr() as usize) & (BLOCK_SIZE - 1));

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

        drop(virtqueue);
        let vq_completion = Virtqueue::add_buffs(self.virtqueue.clone(), &buffs, 1, 2, chain_head);

        ReadCompletion {
            vq_completion,
            bytes,
        }
    }

    #[inline(never)]
    pub async fn post_write<T: AsRef<[u8]>>(
        self: Rc<Self>,
        sector: u64,
        bytes: T,
    ) -> WriteCompletion<T> {
        let chain_head = VqAlloc::new(self.virtqueue.clone(), 3).await;
        let mut virtqueue = self.virtqueue.borrow_mut();

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

        let buf: &[u8] = bytes.as_ref();
        assert!(buf.len() <= BLOCK_SIZE);
        assert_eq!(0, (buf.as_ptr() as usize) & (BLOCK_SIZE - 1));

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

        drop(virtqueue);
        let vq_completion = Virtqueue::add_buffs(self.virtqueue.clone(), &buffs, 2, 1, chain_head);

        WriteCompletion {
            vq_completion,
            bytes,
        }
    }

    /// Returns the ID of the submitted request.
    #[inline(never)]
    pub async fn post_flush(self: Rc<Self>) {
        let chain_head = VqAlloc::new(self.virtqueue.clone(), 2).await;

        let mut virtqueue = self.virtqueue.borrow_mut();
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
        Virtqueue::add_buffs(self.virtqueue.clone(), &buffs, 1, 1, chain_head).await;
    }

    pub fn notify(self: Rc<Self>) {
        self.virtqueue.borrow().notify();
    }
}
