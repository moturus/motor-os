use async_trait::async_trait;
use core::sync::atomic::*;
use moto_rt::spinlock::SpinLock;
use moto_tooling::iobuf::IoBuf;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::io::Result;
use std::marker::PhantomData;
use std::rc::Rc;

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
const VIRTIO_BLK_F_SEG_MAX: u64 = 1u64 << 2;
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
    flush_enabled: bool,
    seg_max: usize,
}

impl BlockDevice {
    /// The number of sectors (512 bytes) the device has.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// The maximum number of data descriptors (segments) per request.
    ///
    /// From VIRTIO_BLK_F_SEG_MAX; when the device does not offer the feature
    /// this is 1 (the convention Linux follows): e.g. Firecracker does not
    /// offer it and rejects/mangles requests with more than one data
    /// descriptor.
    pub fn seg_max(&self) -> usize {
        self.seg_max
    }

    pub fn from(dev: VirtioDevice) -> Result<Rc<Self>> {
        let dev = Rc::new(RefCell::new(dev));
        let dev_clone = dev.clone();

        Self::init(dev).inspect_err(|err| {
            dev_clone.borrow_mut().mark_failed();
            log::error!("Failed initializing VirtIO Block device");
        })
    }

    fn init(dev: Rc<RefCell<VirtioDevice>>) -> Result<Rc<BlockDevice>> {
        let mut dev_mut = dev.borrow_mut();
        dev_mut.init();
        dev_mut.reset();
        dev_mut.acknowledge_device();

        if dev_mut.device_cfg.is_none() {
            log::warn!("Skiping VirtioBlk device without device configuration.");
            return Err(ErrorKind::Other.into());
        }

        dev_mut.acknowledge_driver(); // Step 3
        let (capacity, read_only, seg_max) = Self::negotiate_features(&mut dev_mut)?; // Steps 4, 5, 6
        dev_mut.init_virtqueues(1, 1)?; // Step 7
        dev_mut.driver_ok(); // Step 8

        let virtqueue = dev_mut.virtqueues[0].clone();

        // Requests also need a header and a status descriptor, and
        // post_read_many/post_write_many keep chains within half the queue.
        let queue_size = virtqueue.borrow().queue_size() as usize;
        let seg_max = seg_max.clamp(1, queue_size / 2 - 2);

        log::debug!(
            "Initialized Virtio BLOCK device {:?}: capacity: 0x{:x} read only: {} seg_max: {}.",
            dev_mut.pci_device.id,
            capacity,
            read_only,
            seg_max
        );

        let flush_enabled = dev_mut.virtio_features_negotiated & VIRTIO_BLK_F_FLUSH != 0;

        drop(dev_mut);

        Ok(Rc::new(BlockDevice {
            dev,
            capacity,
            read_only,
            virtqueue,
            flush_enabled,
            seg_max,
        }))
    }

    // Step 4; returns (capacity, read_only, seg_max)
    fn negotiate_features(dev: &mut VirtioDevice) -> Result<(u64, bool, usize)> {
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

        let mut features_acked = super::virtio_device::VIRTIO_F_VERSION_1;
        if (features_available & VIRTIO_BLK_F_FLUSH) == 0 {
            log::debug!("VirtioBLK: VIRTIO_BLK_F_FLUSH feature is not available");
        } else {
            features_acked |= VIRTIO_BLK_F_FLUSH;
        }

        let seg_max_offered = (features_available & VIRTIO_BLK_F_SEG_MAX) != 0;
        if seg_max_offered {
            features_acked |= VIRTIO_BLK_F_SEG_MAX;
        } else {
            // Without the feature the device may support only a single data
            // descriptor per request (Firecracker does exactly that).
            log::info!(
                "virtio-blk: VIRTIO_BLK_F_SEG_MAX not offered; limiting requests to one data descriptor."
            );
        }

        /*
        if (features_available & super::virtio_device::VIRTIO_F_RING_EVENT_IDX) != 0 {
            log::debug!(
                "Virtio BLK device {:?}:\n\tVIRTIO_F_RING_EVENT_IDX feature IS available.",
                dev.pci_device.id,
            );
            features_acked |= super::virtio_device::VIRTIO_F_RING_EVENT_IDX;
        } else {
            log::debug!(
                "Virtio BLK device {:?}:\n\tVIRTIO_F_RING_EVENT_IDX feature is NOT available.",
                dev.pci_device.id,
            );
        }
        */

        // | VIRTIO_BLK_F_RO;
        // (VIRTIO_F_VERSION_1 | VIRTIO_BLK_F_SIZE_MAX | VIRTIO_BLK_F_SEG_MAX | VIRTIO_BLK_F_RO | VIRTIO_BLK_F_BLK_SIZE);
        //  | VIRTIO_BLK_F_RO);
        dev.write_enabled_features(features_acked);
        dev.confirm_features()?;
        dev.virtio_features_negotiated = features_acked;

        let read_only = (features_acked & VIRTIO_BLK_F_RO) != 0;

        let device_cfg = dev.device_cfg.as_ref().unwrap();
        let cfg_bar: &PciBar = dev.pci_device.bars[device_cfg.bar as usize]
            .as_ref()
            .unwrap();
        let capacity = cfg_bar.read_u64(device_cfg.offset as u64);

        // struct virtio_blk_config: capacity: u64, size_max: u32, seg_max: u32.
        // The seg_max field is valid only if the feature was offered.
        let seg_max = if seg_max_offered {
            cfg_bar.read_u32(device_cfg.offset as u64 + 12) as usize
        } else {
            1
        };

        Ok((capacity, read_only, seg_max))
    }

    #[inline(never)]
    pub async fn post_read<T: AsMut<IoBuf> + Unpin>(
        self: Rc<Self>,
        sector: u64,
        mut bytes: T,
    ) -> ReadCompletion<T> {
        use super::virtio_queue::UserData;

        assert_eq!(bytes.as_mut().len(), 4096);

        let chain_head = VqAlloc::new(self.virtqueue.clone(), 3).await;
        let mut virtqueue = self.virtqueue.borrow_mut();

        let (header, phys_addr, next_idx) = virtqueue.get_buffer::<BlkHeader>(chain_head);
        *header = BlkHeader {
            type_: 0, /* VIRTIO_BLK_T_IN */
            _reserved: 0,
            sector,
        };

        let header_data = UserData {
            phys_addr,
            len: core::mem::size_of::<BlkHeader>() as u32,
        };

        const VIRTIO_BLK_S_OK: u8 = 0;
        const VIRTIO_BLK_S_IOERR: u8 = 1;
        const VIRTIO_BLK_S_UNSUPP: u8 = 2;

        let (_, _, next_idx) = virtqueue.get_buffer::<u64>(next_idx); // Skip the second buffer (unused).
        // If we use a single byte for status, CHV corrupts the stack (writes more than one byte).
        let (status, phys_addr, _) = virtqueue.get_buffer::<u64>(next_idx);
        *status = VIRTIO_BLK_S_UNSUPP as u64; // Note: we assume LE.

        let buffs: [UserData; 3] = [
            header_data,
            UserData {
                phys_addr: bytes.as_mut().phys_addr() as u64,
                len: 4096,
            },
            UserData { phys_addr, len: 1 },
        ];

        drop(virtqueue);
        let vq_completion =
            Virtqueue::add_buffs(self.virtqueue.clone(), &buffs, 1, 2, chain_head, bytes);

        // Status is often included. We hard-code block size for simplicity.
        const READ_SIZE_ADJUSTOR: fn(u32) -> u32 = |_| 4096;

        ReadCompletion {
            vq_completion,
            size_adjustor: READ_SIZE_ADJUSTOR,
        }
    }

    /// Read `buffers.len()` consecutive 4K blocks starting at `sector` with
    /// ONE device request: a single descriptor chain scatter-gathers the
    /// contiguous disk range into the (arbitrarily located) buffers, so the
    /// whole read costs one queue notification (a VM exit) and one
    /// completion interrupt instead of one per block.
    #[inline(never)]
    pub async fn post_read_many<T: AsMut<IoBuf> + Unpin>(
        self: Rc<Self>,
        sector: u64,
        mut buffers: Vec<T>,
    ) -> crate::virtio_queue::ReadManyCompletion<T> {
        use super::virtio_queue::UserData;

        let num_buffers = buffers.len();
        assert!(num_buffers > 0);
        assert!(num_buffers <= self.seg_max);
        // Header + data descriptors + status must fit the queue (and leave
        // room for concurrent requests; callers keep chains short).
        let chain_len = (num_buffers + 2) as u16;
        assert!(chain_len <= self.virtqueue.borrow().queue_size() / 2);

        let chain_head = VqAlloc::new(self.virtqueue.clone(), chain_len).await;
        let mut virtqueue = self.virtqueue.borrow_mut();

        let (header, phys_addr, mut next_idx) = virtqueue.get_buffer::<BlkHeader>(chain_head);
        *header = BlkHeader {
            type_: 0, /* VIRTIO_BLK_T_IN */
            _reserved: 0,
            sector,
        };

        let mut buffs: Vec<UserData> = Vec::with_capacity(num_buffers + 2);
        buffs.push(UserData {
            phys_addr,
            len: core::mem::size_of::<BlkHeader>() as u32,
        });

        for buf in &mut buffers {
            assert_eq!(buf.as_mut().len(), 4096);
            buffs.push(UserData {
                phys_addr: buf.as_mut().phys_addr() as u64,
                len: 4096,
            });
            // The data descriptors' header buffers are unused; walk past them
            // to the last descriptor, whose header buffer holds the status.
            next_idx = virtqueue.next_idx(next_idx);
        }

        const VIRTIO_BLK_S_UNSUPP: u8 = 2;

        // If we use a single byte for status, CHV corrupts the stack (writes
        // more than one byte).
        let (status, phys_addr, _) = virtqueue.get_buffer::<u64>(next_idx);
        *status = VIRTIO_BLK_S_UNSUPP as u64; // Note: we assume LE.
        buffs.push(UserData { phys_addr, len: 1 });

        drop(virtqueue);
        let vq_completion = Virtqueue::add_buffs(
            self.virtqueue.clone(),
            &buffs,
            1,
            (num_buffers + 1) as u16,
            chain_head,
            buffers,
        );

        crate::virtio_queue::ReadManyCompletion { vq_completion }
    }

    #[inline(never)]
    pub async fn post_write<T: AsRef<IoBuf> + Unpin>(
        self: Rc<Self>,
        sector: u64,
        bytes: T,
    ) -> WriteCompletion<T> {
        use super::virtio_queue::UserData;

        assert_eq!(bytes.as_ref().len(), 4096);

        let chain_head = VqAlloc::new(self.virtqueue.clone(), 3).await;
        let mut virtqueue = self.virtqueue.borrow_mut();

        let (header, phys_addr, next_idx) = virtqueue.get_buffer::<BlkHeader>(chain_head);
        *header = BlkHeader {
            type_: 1, /* VIRTIO_BLK_T_OUT */
            _reserved: 0,
            sector,
        };

        let header_data = UserData {
            phys_addr,
            len: core::mem::size_of::<BlkHeader>() as u32,
        };

        const VIRTIO_BLK_S_OK: u8 = 0;
        const VIRTIO_BLK_S_IOERR: u8 = 1;
        const VIRTIO_BLK_S_UNSUPP: u8 = 2;

        let (_, _, next_idx) = virtqueue.get_buffer::<u64>(next_idx); // Skip the second buffer (unused).
        // If we use a single byte for status, CHV corrupts the stack (writes more than one byte).
        let (status, phys_addr, _) = virtqueue.get_buffer::<u64>(next_idx);
        *status = VIRTIO_BLK_S_UNSUPP as u64; // Note: we assume LE.

        let buffs: [UserData; 3] = [
            header_data,
            UserData {
                phys_addr: bytes.as_ref().phys_addr() as u64,
                len: 4096,
            },
            UserData { phys_addr, len: 1 },
        ];

        drop(virtqueue);
        let vq_completion =
            Virtqueue::add_buffs(self.virtqueue.clone(), &buffs, 2, 1, chain_head, bytes);

        WriteCompletion { vq_completion }
    }

    /// Write `buffers.len()` consecutive 4K blocks starting at `sector` with
    /// ONE device request; the write-side mirror of [`Self::post_read_many`].
    #[inline(never)]
    pub async fn post_write_many<T: AsRef<IoBuf> + Unpin>(
        self: Rc<Self>,
        sector: u64,
        buffers: Vec<T>,
    ) -> WriteCompletion<Vec<T>> {
        use super::virtio_queue::UserData;

        let num_buffers = buffers.len();
        assert!(num_buffers > 0);
        assert!(num_buffers <= self.seg_max);
        // Header + data descriptors + status must fit the queue (and leave
        // room for concurrent requests; callers keep chains short).
        let chain_len = (num_buffers + 2) as u16;
        assert!(chain_len <= self.virtqueue.borrow().queue_size() / 2);

        let chain_head = VqAlloc::new(self.virtqueue.clone(), chain_len).await;
        let mut virtqueue = self.virtqueue.borrow_mut();

        let (header, phys_addr, mut next_idx) = virtqueue.get_buffer::<BlkHeader>(chain_head);
        *header = BlkHeader {
            type_: 1, /* VIRTIO_BLK_T_OUT */
            _reserved: 0,
            sector,
        };

        let mut buffs: Vec<UserData> = Vec::with_capacity(num_buffers + 2);
        buffs.push(UserData {
            phys_addr,
            len: core::mem::size_of::<BlkHeader>() as u32,
        });

        for buf in &buffers {
            assert_eq!(buf.as_ref().len(), 4096);
            buffs.push(UserData {
                phys_addr: buf.as_ref().phys_addr() as u64,
                len: 4096,
            });
            // The data descriptors' header buffers are unused; walk past them
            // to the last descriptor, whose header buffer holds the status.
            next_idx = virtqueue.next_idx(next_idx);
        }

        const VIRTIO_BLK_S_UNSUPP: u8 = 2;

        // If we use a single byte for status, CHV corrupts the stack (writes
        // more than one byte).
        let (status, phys_addr, _) = virtqueue.get_buffer::<u64>(next_idx);
        *status = VIRTIO_BLK_S_UNSUPP as u64; // Note: we assume LE.
        buffs.push(UserData { phys_addr, len: 1 });

        drop(virtqueue);
        let vq_completion = Virtqueue::add_buffs(
            self.virtqueue.clone(),
            &buffs,
            (num_buffers + 1) as u16,
            1,
            chain_head,
            buffers,
        );

        WriteCompletion { vq_completion }
    }

    /// Returns the ID of the submitted request.
    #[inline(never)]
    pub async fn post_flush(self: Rc<Self>) -> Result<()> {
        use super::virtio_queue::UserData;

        if !self.flush_enabled {
            return Err(ErrorKind::Unsupported.into());
        }

        let chain_head = VqAlloc::new(self.virtqueue.clone(), 2).await;
        let mut virtqueue = self.virtqueue.borrow_mut();

        let (header, phys_addr, next_idx) = virtqueue.get_buffer::<BlkHeader>(chain_head);
        *header = BlkHeader {
            type_: 4, /* VIRTIO_BLK_T_FLUSH */
            _reserved: 0,
            sector: 0,
        };

        let header_data = UserData {
            phys_addr,
            len: core::mem::size_of::<BlkHeader>() as u32,
        };

        const VIRTIO_BLK_S_OK: u8 = 0;
        const VIRTIO_BLK_S_IOERR: u8 = 1;
        const VIRTIO_BLK_S_UNSUPP: u8 = 2;

        let (status, phys_addr, _) = virtqueue.get_buffer::<u64>(next_idx);
        *status = VIRTIO_BLK_S_UNSUPP as u64; // Note: we assume LE.

        let buffs: [UserData; 2] = [header_data, UserData { phys_addr, len: 1 }];

        core::mem::drop(virtqueue);

        let vq_completion =
            Virtqueue::add_buffs(self.virtqueue.clone(), &buffs, 1, 1, chain_head, ());

        WriteCompletion { vq_completion }.await.1.map(|_| ())
    }
}
