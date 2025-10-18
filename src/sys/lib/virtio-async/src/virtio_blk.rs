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

use super::BLOCK_SIZE;
use super::BLOCK_SIZE_LOG2;
use super::pci::PciBar;
use super::virtio_device::VirtioDevice;
use crate::Completion;
use crate::virtio_queue::Virtqueue;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Little Endian is often assumed here.");

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

#[derive(FromZeros)]
#[repr(C, align(512))]
pub struct VirtioBlock {
    pub bytes: [u8; BLOCK_SIZE],
}

pub struct VirtioBlockRef<'a> {
    pub bytes: *mut u8,
    _marker: PhantomData<&'a mut ()>,
}

impl VirtioBlock {
    pub fn as_mut<'a>(&'a mut self) -> VirtioBlockRef<'a> {
        VirtioBlockRef {
            bytes: self.bytes.as_mut_ptr(),
            _marker: PhantomData,
        }
    }
}

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

    /// Returns the ID of the submitted request.
    #[inline(never)]
    pub fn post_read<'a>(
        this: Rc<RefCell<Self>>,
        sector: u64,
        block_ref: VirtioBlockRef<'a>,
    ) -> Option<Completion<'a>> {
        let vq = this.borrow().dev.virtqueues[0].clone();
        let mut virtqueue = vq.borrow_mut();
        let Some(chain_head) = virtqueue.alloc_descriptor_chain(3) else {
            return None;
        };

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
                addr: block_ref.bytes as usize as u64,
                len: BLOCK_SIZE as u32,
            },
            UserData {
                addr: status as *mut _ as usize as u64,
                len: 1,
            },
        ];

        core::mem::drop(virtqueue);
        let completion = Virtqueue::add_buffs(vq, &buffs, 1, 2, chain_head);

        Some(completion)

        /*
        let mut wait_failed = false;
        while !virtqueue.more_used_deprecated() {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            if wait_failed {
                super::nop(); // Don't spam the kernel if something is wrong here.
            } else {
                wait_failed = virtqueue.wait_deprecated().is_err();
                if wait_failed {
                    log::error!("virtqueue.wait() failed: switching to spinning.");
                }
            }
        }
        let consumed = virtqueue.consume_used_deprecated();
        // Qemu indicates that 513 bytes were consumed, but CHV says 512.
        assert!((consumed == 512) || (consumed == 513));

        // todo!("add vring_get_isr");
        core::sync::atomic::fence(core::sync::atomic::Ordering::AcqRel);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::AcqRel);
        let status = unsafe { (status_addr as *const u8).read_volatile() };
        if status == VIRTIO_BLK_S_OK {
            Ok(())
        } else if status == VIRTIO_BLK_S_IOERR {
            log::error!("VirtioBlk read error");
            Err(ErrorKind::Other.into())
        } else {
            panic!("status: {}", status)
        }
        */
    }

    /*
    #[inline(never)]
    async fn write(&mut self, sector: u64, buf: &[u8]) -> Result<()> {
        assert_eq!(BLOCK_SIZE, buf.len());
        // assert!(!self.read_only);

        #[repr(C, packed)]
        struct Header {
            type_: u32,
            _reserved: u32,
            sector: u64,
        }
        let header = Header {
            type_: 1, /* VIRTIO_BLK_T_OUT */
            _reserved: 0,
            sector,
        };

        const VIRTIO_BLK_S_OK: u8 = 0;
        const VIRTIO_BLK_S_IOERR: u8 = 1;
        const VIRTIO_BLK_S_UNSUPP: u8 = 2;

        // If we use a single byte for status, CHV corrupts the stack (writes more than one byte).
        let mut status_64 = 0_u64;
        let status_addr = &mut status_64 as *mut _ as usize;
        unsafe {
            let status = status_addr as *mut u8;
            status.write_volatile(VIRTIO_BLK_S_UNSUPP);
        }

        use super::virtio_queue::UserData;
        let sg: [UserData; 3] = [
            UserData {
                addr: &header as *const Header as usize as u64,
                len: core::mem::size_of::<Header>() as u32,
            },
            UserData {
                addr: buf.as_ptr() as usize as u64,
                len: BLOCK_SIZE as u32,
            },
            UserData {
                addr: status_addr as u64,
                len: 1,
            },
        ];

        assert_eq!(self.dev.virtqueues.len(), 1);
        let virtqueue = &mut self.dev.virtqueues[0];
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        virtqueue.add_buf(&sg, 2, 1);

        // Notify
        let notify_cap = self.dev.notify_cfg.unwrap();
        let cfg_bar: &PciBar = self.dev.pci_device.bars[notify_cap.bar as usize]
            .as_ref()
            .unwrap();
        let notify_offset = notify_cap.offset as u64
            + (notify_cap.notify_off_multiplier as u64 * virtqueue.queue_notify_off as u64);

        cfg_bar.write_u16(notify_offset, virtqueue.queue_num);

        let mut wait_failed = false;
        while !virtqueue.more_used_deprecated() {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            if wait_failed {
                super::nop(); // Don't spam the kernel if something is wrong here.
            } else {
                wait_failed = virtqueue.wait_deprecated().is_err();
                if wait_failed {
                    log::error!("virtqueue.wait() failed: switching to spinning.");
                }
            }
        }
        virtqueue.reclaim_used_deprecated();

        // todo!("add vring_get_isr");
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);
        let status = unsafe { (status_addr as *const u8).read_volatile() };
        if status == VIRTIO_BLK_S_OK {
            Ok(())
        } else if status == VIRTIO_BLK_S_IOERR {
            log::error!("VirtioBlk write error");
            Err(ErrorKind::Other.into())
        } else {
            panic!("status: {}", status)
        }
    }

    #[inline(never)]
    async fn flush(&mut self) -> Result<()> {
        // assert!(!self.read_only);

        #[repr(C, packed)]
        struct Header {
            type_: u32,
            _reserved: u32,
            sector: u64,
        }
        let header = Header {
            type_: 4, /* VIRTIO_BLK_T_FLUSH */
            _reserved: 0,
            sector: 0,
        };

        const VIRTIO_BLK_S_OK: u8 = 0;
        const VIRTIO_BLK_S_IOERR: u8 = 1;
        const VIRTIO_BLK_S_UNSUPP: u8 = 2;

        let mut status = AtomicU8::new(VIRTIO_BLK_S_UNSUPP);

        use super::virtio_queue::UserData;
        let sg: [UserData; 2] = [
            UserData {
                addr: &header as *const Header as usize as u64,
                len: core::mem::size_of::<Header>() as u32,
            },
            UserData {
                addr: &mut status as *mut _ as usize as u64,
                len: 1,
            },
        ];

        assert_eq!(self.dev.virtqueues.len(), 1);
        let virtqueue = &mut self.dev.virtqueues[0];
        virtqueue.add_buf(&sg, 1, 1);

        // Notify
        let notify_cap = self.dev.notify_cfg.unwrap();
        let cfg_bar: &PciBar = self.dev.pci_device.bars[notify_cap.bar as usize]
            .as_ref()
            .unwrap();
        let notify_offset = notify_cap.offset as u64
            + (notify_cap.notify_off_multiplier as u64 * virtqueue.queue_notify_off as u64);

        cfg_bar.write_u16(notify_offset, virtqueue.queue_num);

        let mut wait_failed = false;
        while !virtqueue.more_used_deprecated() {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            if wait_failed {
                super::nop(); // Don't spam the kernel if something is wrong here.
            } else {
                wait_failed = virtqueue.wait_deprecated().is_err();
                if wait_failed {
                    log::error!("virtqueue.wait() failed: switching to spinning.");
                }
            }
        }
        virtqueue.reclaim_used_deprecated();

        // todo!("add vring_get_isr");
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        if status.load(Ordering::Acquire) == VIRTIO_BLK_S_OK {
            Ok(())
        } else if status.load(Ordering::Acquire) == VIRTIO_BLK_S_IOERR {
            log::error!("VirtioBlk write error");
            Err(ErrorKind::Other.into())
        } else {
            panic!("status: {}", status.load(Ordering::Relaxed))
        }
    }
    */
}

/*
static BLK: SpinLock<Vec<BlockDevice>> = SpinLock::new(vec![]);

pub fn lsblk() -> Vec<Arc<dyn super::BlockDevice>> {
    let mut result: Vec<Arc<dyn super::BlockDevice>> = vec![];
    let cnt = BLK.lock().len();

    for idx in 0..cnt {
        result.push(Arc::new(VirtioDrive {
            blk_idx: idx as u64,
        }));
    }

    result
}

#[derive(Clone, Copy)]
pub(super) struct VirtioDrive {
    blk_idx: u64, // index into BLK
}

impl super::BlockDevice for VirtioDrive {
    fn read(&self, buf: &mut [u8], address: u64, number_of_blocks: usize) -> Result<(), ()> {
        assert_eq!(0, address & (BLOCK_SIZE as u64 - 1));
        assert_eq!(buf.len(), number_of_blocks << BLOCK_SIZE_LOG2);

        // Block reads must not cross physical page lines.
        assert_eq!(0, (buf.as_ptr() as usize) & (BLOCK_SIZE - 1));

        let mut guard = BLK.lock();
        let blk = guard.get_mut(self.blk_idx as usize).unwrap();

        let start_block = address >> BLOCK_SIZE_LOG2;
        if start_block + (number_of_blocks as u64) > blk.capacity {
            log::error!(
                "Read past volume end: start: 0x{:x} blocks: 0x{:x} capacity: 0x{:x}",
                address,
                number_of_blocks,
                blk.capacity
            );
            return Err(());
        }

        let mut offset = 0;
        for idx in 0..(number_of_blocks as u64) {
            let curr_buf = &mut buf[offset..(offset + BLOCK_SIZE)];
            blk.read(start_block + idx, curr_buf)?;
            offset += BLOCK_SIZE;
        }

        core::sync::atomic::fence(Ordering::Acquire);
        core::sync::atomic::compiler_fence(Ordering::Acquire);

        Ok(())
    }

    #[allow(unused)]
    fn write(&self, buf: &[u8], address: u64, number_of_blocks: usize) -> Result<(), ()> {
        assert_eq!(0, address & (BLOCK_SIZE as u64 - 1));
        assert_eq!(buf.len(), number_of_blocks << BLOCK_SIZE_LOG2);

        // Block writes must not cross physical page lines.
        assert_eq!(0, (buf.as_ptr() as usize) & (BLOCK_SIZE - 1));

        let mut guard = BLK.lock();
        let blk = guard.get_mut(self.blk_idx as usize).unwrap();

        let start_block = address >> BLOCK_SIZE_LOG2;
        if start_block + (number_of_blocks as u64) > blk.capacity {
            log::error!(
                "Write past volume end: start: 0x{:x} blocks: 0x{:x} capacity: 0x{:x}",
                address,
                number_of_blocks,
                blk.capacity
            );
            return Err(());
        }

        let mut offset = 0;
        for idx in 0..(number_of_blocks as u64) {
            let curr_buf = &buf[offset..(offset + BLOCK_SIZE)];
            blk.write(start_block + idx, curr_buf)?;
            offset += BLOCK_SIZE;
        }

        blk.flush()?;
        Ok(())
    }

    fn capacity(&self) -> u64 {
        BLK.lock().get(self.blk_idx as usize).unwrap().capacity
    }
}
*/

/*
#[async_trait(?Send)]
impl async_fs::AsyncBlockDevice for BlockDevice {
    /// The number of blocks in this device.
    fn num_blocks(&self) -> u64 {
        // Virtio blocks are 512 bytes, while async-fs blocks are 4096 bytes.
        self.capacity >> 3
    }
    /// Read a single block.
    async fn read_block(
        &mut self,
        block_no: u64,
        block: &mut async_fs::Block,
    ) -> async_fs::Result<()> {
        #[repr(C, packed)]
        struct Header {
            type_: u32,
            _reserved: u32,
            sector: u64,
        }
        let header = Header {
            type_: 0, /* VIRTIO_BLK_T_IN */
            _reserved: 0,
            sector,
        };

        const VIRTIO_BLK_S_OK: u8 = 0;
        const VIRTIO_BLK_S_IOERR: u8 = 1;
        const VIRTIO_BLK_S_UNSUPP: u8 = 2;

        // If we use a single byte for status, CHV corrupts the stack (writes more than one byte).
        let mut status_64 = VIRTIO_BLK_S_UNSUPP as u64; // Note: we assume LE.
        let status_addr = &mut status_64 as *mut _ as usize;

        use super::virtio_queue::UserData;
        let buffs: [UserData; 3] = [
            UserData {
                addr: &header as *const Header as usize as u64,
                len: core::mem::size_of::<Header>() as u32,
            },
            UserData {
                addr: block.as_bytes_mut().as_mut_ptr() as usize as u64,
                len: async_fs::BLOCK_SIZE as u32,
            },
            UserData {
                addr: status_addr as u64,
                len: 1,
            },
        ];

        assert_eq!(self.dev.virtqueues.len(), 1);
        let virtqueue = &mut self.dev.virtqueues[0];
        virtqueue.add_buf(&buffs, 1, 2);

        // Notify
        let notify_cap = self.dev.notify_cfg.unwrap();
        let cfg_bar: &PciBar = self.dev.pci_device.bars[notify_cap.bar as usize]
            .as_ref()
            .unwrap();
        let notify_offset = notify_cap.offset as u64
            + (notify_cap.notify_off_multiplier as u64 * virtqueue.queue_notify_off as u64);

        cfg_bar.write_u16(notify_offset, virtqueue.queue_num);

        let mut wait_failed = false;
        while !virtqueue.more_used_deprecated() {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            if wait_failed {
                super::nop(); // Don't spam the kernel if something is wrong here.
            } else {
                wait_failed = virtqueue.wait_deprecated().is_err();
                if wait_failed {
                    log::error!("virtqueue.wait() failed: switching to spinning.");
                }
            }
        }
        let consumed = virtqueue.consume_used_deprecated();
        // Qemu indicates that 513 bytes were consumed, but CHV says 512.
        assert!((consumed == 512) || (consumed == 513));

        // todo!("add vring_get_isr");
        core::sync::atomic::fence(core::sync::atomic::Ordering::AcqRel);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::AcqRel);
        let status = unsafe { (status_addr as *const u8).read_volatile() };
        if status == VIRTIO_BLK_S_OK {
            Ok(())
        } else if status == VIRTIO_BLK_S_IOERR {
            log::error!("VirtioBlk read error");
            Err(())
        } else {
            panic!("status: {}", status)
        }
    }
    /// Write a single block.
    async fn write_block(
        &mut self,
        block_no: u64,
        block: &async_fs::Block,
    ) -> async_fs::Result<()> {
        todo!()
    }

    /// Flush dirty blocks to the underlying storage.
    async fn flush(&mut self) -> async_fs::Result<()> {
        todo!()
    }
}
*/
