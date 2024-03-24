//! A generalized asyncrhonous I/O channel.
//!
//! Inspired by io_uring, but necessarily different because it is used
//! for communication between two userspace processes instead of
//! between the kernel and a userspace process.
//!
//! Also simpler than io_uring. More specifically, SQE and CQE have the same layout.
use core::{fmt::Debug, sync::atomic::*};

use moto_sys::{syscalls::*, ErrorCode};

// Although client+server can use any value in QueueEntry::command, it is recommended
// that they respect the ranges below.

// Command values in [1..CMD_RESERVED_MAX_CORE] are reserved for core commands,
// such as CMD_NOOP and CMD_CANCEL.
pub const CMD_RESERVED_MAX_CORE: u16 = 0x100;

// Command values in [CMD_RESERVED_MIN_LOCAL..CMD_RESERVED_MAX_LOCAL] are reserved for
// local commands, i.e. those that are not supposed to trigger an IPC.
pub const CMD_RESERVED_MIN_LOCAL: u16 = CMD_RESERVED_MAX_CORE; // 0x100
pub const CMD_RESERVED_MAX_LOCAL: u16 = CMD_RESERVED_MIN_LOCAL + 0x1000; // 0x1100

// Free to use above that.
pub const CMD_RESERVED_MAX: u16 = CMD_RESERVED_MAX_LOCAL; // 0x1100

// A noop command that triggers an immediate completion. Used for testing throughput/latency.
pub const CMD_NOOP_OK: u16 = 1;

// If this flag is set, the "server" will put its current timestamp (tsc) into
// payload::args_64()[2].
pub const FLAG_CMD_NOOP_OK_TIMESTAMP: u32 = 1;

pub const PAGE_SIZE: usize = 4096;

#[repr(C, align(4096))]
pub struct Page {
    bytes: [u8; PAGE_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union Payload {
    shared_pages: [u16; 12],
    args_8: [u8; 24],
    args_16: [u16; 12],
    args_32: [u32; 6],
    args_64: [u64; 3],
}

const _PAYLOAD_SIZE: () = assert!(core::mem::size_of::<Payload>() == 24);

impl Payload {
    pub fn shared_pages_mut(&mut self) -> &mut [u16; 12] {
        unsafe { &mut self.shared_pages }
    }

    pub fn shared_pages(&self) -> &[u16; 12] {
        unsafe { &self.shared_pages }
    }

    pub fn args_8_mut(&mut self) -> &mut [u8; 24] {
        unsafe { &mut self.args_8 }
    }

    pub fn args_16_mut(&mut self) -> &mut [u16; 12] {
        unsafe { &mut self.args_16 }
    }

    pub fn args_32_mut(&mut self) -> &mut [u32; 6] {
        unsafe { &mut self.args_32 }
    }

    pub fn args_64_mut(&mut self) -> &mut [u64; 3] {
        unsafe { &mut self.args_64 }
    }

    pub fn args_8(&self) -> &[u8; 24] {
        unsafe { &self.args_8 }
    }

    pub fn args_16(&self) -> &[u16; 12] {
        unsafe { &self.args_16 }
    }

    pub fn args_32(&self) -> &[u32; 6] {
        unsafe { &self.args_32 }
    }

    pub fn args_64(&self) -> &[u64; 3] {
        unsafe { &self.args_64 }
    }
}

// QueueEntry is used for both the submission queue and the completion queue.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct QueueEntry {
    pub id: u64,          // IN. See user_data in io_uring.pdf. Used by client-side executor.
    pub handle: u64,      // IN/OUT. Like Windows handle, or Unix fd.
    pub command: u16,     // IN.
    pub status: u16,      // OUT.
    pub flags: u32,       // IN/OUT.
    pub wake_handle: u64, // IN (used by client-side executor to notify upon completion).
    pub payload: Payload, // IN/OUT.
}

const _QE_SIZE: () = assert!(core::mem::size_of::<QueueEntry>() == 56);

// Cache-line aligned, cache-line sized.
#[repr(C, align(64))]
pub struct QueueSlot {
    pub stamp: AtomicU64, // IN/OUT: same as stamp in crossbeam ArrayQueue, or sequence_ in Dmitry Vyukov's mpmc.
    pub qe: QueueEntry,
}

const _QS_SIZE: () = assert!(core::mem::size_of::<QueueSlot>() == 64);

impl Debug for QueueEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QueueEntry").field("id", &self.id).finish()
    }
}

impl QueueEntry {
    pub fn new() -> Self {
        let mut result: Self = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
        result.status = ErrorCode::NotReady.into();
        result
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }

    pub fn status(&self) -> ErrorCode {
        ErrorCode::from_u16(self.status)
    }
}

const QUEUE_SIZE: u64 = 64;
const QUEUE_MASK: u64 = QUEUE_SIZE - 1;
const CHANNEL_PAGE_COUNT: usize = 128;

#[repr(C, align(4096))]
struct RawChannel {
    // First 4 cache lines.
    submission_queue_head: AtomicU64,
    _pad1: [u64; 7],
    submission_queue_tail: AtomicU64,
    _pad2: [u64; 7],
    completion_queue_head: AtomicU64,
    _pad3: [u64; 7],
    completion_queue_tail: AtomicU64,
    _pad4: [u64; 7],

    shared_pages_in_use_0: AtomicU64,
    _pad5: [u64; 7],
    shared_pages_in_use_1: AtomicU64,
    _pad6: [u64; 7],

    // Pad to BLOCK_SIZE (512 bytes).
    _pad7: [u8; 128],

    // Pad to PAGE_SIZE
    _pad8: [u8; 3584],

    // offset: 4096 = 1 page
    submission_queue: [QueueSlot; QUEUE_SIZE as usize], // 4096 bytes = 8 blocks

    // offset: 8192 = 2 pages
    completion_queue: [QueueSlot; QUEUE_SIZE as usize], // 4096 bytes = 8 blocks

    shared_pages: [Page; CHANNEL_PAGE_COUNT],
}

pub const _RAW_CHANNEL_SIZE: () = assert!(core::mem::size_of::<RawChannel>() == ((128 + 3) * 4096));

impl RawChannel {
    fn is_empty(&self) -> bool {
        self.submission_queue_head.load(Ordering::Acquire)
            == self.completion_queue_tail.load(Ordering::Acquire)
    }

    fn shared_page_bytes(&self, page_idx: u16) -> Result<&mut [u8], ErrorCode> {
        if page_idx >= (CHANNEL_PAGE_COUNT as u16) {
            return Err(ErrorCode::InvalidArgument);
        }

        unsafe {
            let addr = &self.shared_pages[page_idx as usize] as *const _ as usize;
            Ok(core::slice::from_raw_parts_mut(addr as *mut u8, PAGE_SIZE))
        }
    }

    fn alloc_page_in(&self, arena_idx: usize) -> Result<u16, ErrorCode> {
        let bitmap_ref = if arena_idx == 0 {
            &self.shared_pages_in_use_0
        } else if arena_idx == 1 {
            &self.shared_pages_in_use_1
        } else {
            panic!()
        };
        let bitmap = bitmap_ref.load(Ordering::Relaxed);
        let ones = bitmap.trailing_ones();
        if ones == 64 {
            // Nothing left.
            return Err(ErrorCode::NotReady);
        }

        let bit = 1u64 << ones;
        assert_eq!(0, bitmap & bit);
        // We cannot use fetch_xor here, because if a concurent xor succeeds, we may clear it,
        // and another concurrent xor will succeed again, leading to double alloc.
        if bitmap_ref
            .compare_exchange_weak(bitmap, bitmap | bit, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            // Contention.
            return Err(ErrorCode::NotReady);
        }

        Ok(ones as u16)
    }

    fn free_page_in(&self, arena_idx: usize, page_idx: u16) -> Result<(), ErrorCode> {
        let bitmap = if arena_idx == 0 {
            &self.shared_pages_in_use_0
        } else if arena_idx == 1 {
            &self.shared_pages_in_use_1
        } else {
            panic!()
        };
        let bit = 1u64 << page_idx;
        if (bitmap.fetch_xor(bit, Ordering::Relaxed) & bit) == 0 {
            // The page was not actually used.
            panic!(
                "io_channel: freeing unused page {} in arena {}; bitmap: 0x{:x}",
                page_idx,
                arena_idx,
                bitmap.load(Ordering::Relaxed)
            )
        } else {
            Ok(())
        }
    }

    fn free_page(&self, page_idx: u16) -> Result<(), ErrorCode> {
        if (page_idx as usize) >= CHANNEL_PAGE_COUNT {
            return Err(ErrorCode::InvalidArgument);
        }

        if page_idx < 64 {
            self.free_page_in(0, page_idx)
        } else {
            self.free_page_in(1, page_idx - 64)
        }
    }

    fn may_submit(&self) -> bool {
        self.submission_queue_head.load(Ordering::Relaxed)
            < (self.submission_queue_tail.load(Ordering::Relaxed) + QUEUE_SIZE)
    }

    fn may_have_completions(&self) -> bool {
        self.completion_queue_head.load(Ordering::Relaxed)
            > self.completion_queue_tail.load(Ordering::Relaxed)
    }

    fn dump_state(&self) {
        crate::moto_log!(
            "RawChannel: sqh: {} sqt: {} cqh: {} cqt: {}",
            self.submission_queue_head.load(Ordering::Relaxed),
            self.submission_queue_tail.load(Ordering::Relaxed),
            self.completion_queue_head.load(Ordering::Relaxed),
            self.completion_queue_tail.load(Ordering::Relaxed),
        );
    }
}

pub struct IoPage {
    page_idx: u16,
    raw_channel: &'static RawChannel,
}

impl Drop for IoPage {
    fn drop(&mut self) {
        if self.page_idx != u16::MAX {
            self.raw_channel.free_page(self.page_idx).unwrap();
        }
    }
}

impl IoPage {
    pub fn bytes(&self) -> &[u8] {
        self.raw_channel.shared_page_bytes(self.page_idx).unwrap()
    }

    pub fn bytes_mut(&self) -> &mut [u8] {
        self.raw_channel.shared_page_bytes(self.page_idx).unwrap()
    }

    pub fn page_idx(&self) -> u16 {
        self.page_idx
    }

    pub fn forget(mut self) {
        self.page_idx = u16::MAX;
    }
}

pub struct Client {
    raw_channel: AtomicPtr<RawChannel>,
    server_handle: SysHandle,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.clear();
    }
}

impl Client {
    pub fn connect(url: &str) -> Result<Self, ErrorCode> {
        let addr = SysMem::map(
            SysHandle::SELF,
            SysMem::F_READABLE | SysMem::F_WRITABLE,
            u64::MAX,
            u64::MAX,
            4096,
            (core::mem::size_of::<RawChannel>() >> 12) as u64,
        )?;
        let full_url = alloc::format!(
            "shared:url={};address={};page_type=small;page_num={}",
            moto_sys::url_encode(url),
            addr,
            64
        );

        let server_handle =
            SysCtl::get(SysHandle::SELF, SysCtl::F_WAKE_PEER, &full_url).map_err(|err| {
                SysMem::free(addr).unwrap();
                err
            })?;

        let self_ = Self {
            raw_channel: AtomicPtr::new(addr as usize as *mut RawChannel),
            server_handle,
        };

        fence(Ordering::Acquire);
        self_
            .raw_channel()
            .completion_queue_head
            .store(0, Ordering::Relaxed);
        self_
            .raw_channel()
            .completion_queue_tail
            .store(0, Ordering::Relaxed);
        self_
            .raw_channel()
            .submission_queue_head
            .store(0, Ordering::Relaxed);
        self_
            .raw_channel()
            .submission_queue_tail
            .store(0, Ordering::Relaxed);

        for idx in 0..(QUEUE_SIZE) {
            self_.raw_channel().submission_queue[idx as usize]
                .stamp
                .store(idx, Ordering::Relaxed);
            self_.raw_channel().completion_queue[idx as usize]
                .stamp
                .store(idx, Ordering::Relaxed);
        }
        fence(Ordering::Release);

        Ok(self_)
    }

    pub fn server_handle(&self) -> SysHandle {
        self.server_handle
    }

    fn clear(&mut self) {
        let addr = self.raw_channel.load(Ordering::Acquire) as usize;
        SysMem::free(addr as u64).unwrap();
        self.raw_channel
            .store(core::ptr::null_mut(), Ordering::Release);
        SysCtl::put(self.server_handle).unwrap();
        self.server_handle = SysHandle::NONE;
    }

    // See enqueue() in mpmc.cc.
    pub fn submit_sqe(&self, sqe: QueueEntry) -> Result<(), ErrorCode> {
        let raw_channel = self.raw_channel();

        let mut slot: &mut QueueSlot;
        let mut pos = raw_channel.submission_queue_head.load(Ordering::Relaxed);
        loop {
            slot = &mut raw_channel.submission_queue[(pos & QUEUE_MASK) as usize];
            let stamp = slot.stamp.load(Ordering::Acquire);

            if stamp == pos {
                match raw_channel.submission_queue_head.compare_exchange_weak(
                    pos,
                    pos + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(head) => pos = head, // continue
                }
            } else if stamp < pos {
                return Err(ErrorCode::NotReady); // The queue is full.
            } else {
                // We lost the race - continue.
                pos = raw_channel.submission_queue_head.load(Ordering::Relaxed);
            }
        }

        slot.qe = sqe;
        slot.stamp.store(pos + 1, Ordering::Release);
        Ok(())
    }

    // See dequeue() in mpmc.cc.
    pub fn get_cqe(&self) -> Result<QueueEntry, ErrorCode> {
        let raw_channel = self.raw_channel();

        let mut slot: &mut QueueSlot;
        let mut pos = raw_channel.completion_queue_tail.load(Ordering::Relaxed);

        loop {
            slot = &mut raw_channel.completion_queue[(pos & QUEUE_MASK) as usize];
            let stamp = slot.stamp.load(Ordering::Acquire);

            if stamp == (pos + 1) {
                match raw_channel.completion_queue_tail.compare_exchange_weak(
                    pos,
                    pos + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(tail) => pos = tail, // continue
                }
            } else if stamp < (pos + 1) {
                return Err(ErrorCode::NotReady); // The queue is empty.
            } else {
                // We lost the race - continue.
                pos = raw_channel.completion_queue_tail.load(Ordering::Relaxed);
            }
        }

        let cqe = slot.qe;
        slot.stamp.store(pos + QUEUE_SIZE, Ordering::Release);
        Ok(cqe)
    }

    pub fn alloc_page(&self) -> Result<IoPage, ErrorCode> {
        // The client allocates first in 0, then 1. The server allocates first in 1, then 0.
        if let Ok(idx) = self.raw_channel().alloc_page_in(0) {
            Ok(IoPage {
                page_idx: idx,
                raw_channel: self.raw_channel(),
            })
        } else {
            if let Ok(idx) = self.raw_channel().alloc_page_in(1) {
                Ok(IoPage {
                    page_idx: idx + 64,
                    raw_channel: self.raw_channel(),
                })
            } else {
                Err(ErrorCode::NotReady)
            }
        }
    }

    pub fn shared_page(&self, page_idx: u16) -> IoPage {
        assert!(page_idx < CHANNEL_PAGE_COUNT as u16);
        IoPage {
            page_idx,
            raw_channel: self.raw_channel(),
        }
    }

    fn raw_channel(&self) -> &'static mut RawChannel {
        unsafe {
            let ptr = self.raw_channel.load(Ordering::Relaxed);
            ptr.as_mut().unwrap()
        }
    }

    pub fn is_empty(&self) -> bool {
        self.raw_channel().is_empty()
    }

    pub fn may_submit(&self) -> bool {
        self.raw_channel().may_submit()
    }

    pub fn may_have_completions(&self) -> bool {
        self.raw_channel().may_have_completions()
    }

    pub fn dump_state(&self) {
        self.raw_channel().dump_state()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServerStatus {
    Created,
    Connected,
    Error(ErrorCode),
}

pub struct Server {
    raw_channel: *mut RawChannel,
    wait_handle: SysHandle,
    status: ServerStatus,
}

impl Drop for Server {
    fn drop(&mut self) {
        if !self.raw_channel.is_null() {
            self.clear();
        }
    }
}

impl Server {
    pub fn create(url: &str) -> Result<Self, ErrorCode> {
        let addr = SysMem::map(
            SysHandle::SELF,
            0, // not mapped
            u64::MAX,
            u64::MAX,
            4096,
            (core::mem::size_of::<RawChannel>() >> 12) as u64,
        )?;
        let full_url = alloc::format!(
            "shared:url={};address={};page_type=small;page_num={}",
            moto_sys::url_encode(url),
            addr,
            64
        );

        let wait_handle = SysCtl::create(SysHandle::SELF, 0, &full_url).map_err(|err| {
            SysMem::free(addr).unwrap();
            err
        })?;

        Ok(Self {
            raw_channel: addr as usize as *mut RawChannel,
            wait_handle,
            status: ServerStatus::Created,
        })
    }

    pub fn status(&self) -> ServerStatus {
        self.status
    }

    // See dequeue() in mpmc.cc.
    pub fn get_sqe(&mut self) -> Result<QueueEntry, ErrorCode> {
        if self.status != ServerStatus::Connected {
            return Err(ErrorCode::InvalidArgument);
        }

        let raw_channel = self.raw_channel();

        let mut slot: &mut QueueSlot;
        let mut pos = raw_channel.submission_queue_tail.load(Ordering::Relaxed);
        loop {
            slot = &mut raw_channel.submission_queue[(pos & QUEUE_MASK) as usize];
            let stamp = slot.stamp.load(Ordering::Acquire);

            if stamp == (pos + 1) {
                match raw_channel.submission_queue_tail.compare_exchange_weak(
                    pos,
                    pos + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(tail) => pos = tail, // continue
                }
            } else if stamp < (pos + 1) {
                return Err(ErrorCode::NotReady); // The queue is empty.
            } else {
                // We lost the race - continue.
                pos = raw_channel.submission_queue_tail.load(Ordering::Relaxed);
            }
        }

        let sqe = slot.qe;
        slot.stamp.store(pos + QUEUE_SIZE, Ordering::Release);
        Ok(sqe)
    }

    // See enqueue() in mpmc.cc.
    pub fn complete_sqe(&mut self, sqe: QueueEntry) -> Result<(), ErrorCode> {
        if self.status != ServerStatus::Connected {
            return Err(ErrorCode::InvalidArgument);
        }

        let raw_channel = self.raw_channel();

        let mut slot: &mut QueueSlot;
        let mut pos = raw_channel.completion_queue_head.load(Ordering::Relaxed);

        loop {
            slot = &mut raw_channel.completion_queue[(pos & QUEUE_MASK) as usize];
            let stamp = slot.stamp.load(Ordering::Acquire);

            if stamp == pos {
                match raw_channel.completion_queue_head.compare_exchange_weak(
                    pos,
                    pos + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(head) => pos = head, // continue
                }
            } else if stamp < pos {
                return Err(ErrorCode::NotReady); // The queue is full.
            } else {
                // We lost the race - continue.
                pos = raw_channel.completion_queue_head.load(Ordering::Relaxed);
            }
        }

        slot.qe = sqe;
        slot.stamp.store(pos + 1, Ordering::Release);
        Ok(())
    }

    pub fn wait_handle(&self) -> SysHandle {
        self.wait_handle
    }

    // Unsafe because it assumes wait on wait_handle succeeded. Otherwise
    // raw_buf pointer could still be unmapped.
    pub unsafe fn accept(&mut self) -> Result<(), ErrorCode> {
        assert_eq!(self.status, ServerStatus::Created);

        compiler_fence(Ordering::Acquire);
        fence(Ordering::Acquire);

        if (*self.raw_channel)
            .completion_queue_head
            .load(Ordering::Relaxed)
            != 0
            || (*self.raw_channel)
                .completion_queue_tail
                .load(Ordering::Relaxed)
                != 0
        {
            self.status = ServerStatus::Error(ErrorCode::BadHandle);
            self.clear();
            return Err(ErrorCode::BadHandle);
        }

        self.status = ServerStatus::Connected;
        Ok(())
    }

    fn clear(&mut self) {
        assert!(!self.raw_channel.is_null());
        SysMem::free(self.raw_channel as usize as u64).unwrap();
        self.raw_channel = core::ptr::null_mut();
        SysCtl::put(self.wait_handle).unwrap();
        self.wait_handle = SysHandle::NONE;
    }

    pub fn alloc_page(&self) -> Result<IoPage, ErrorCode> {
        // The client allocates first in 0, then 1. The server allocates first in 1, then 0.
        if let Ok(idx) = self.raw_channel().alloc_page_in(1) {
            Ok(IoPage {
                page_idx: idx + 64,
                raw_channel: self.raw_channel(),
            })
        } else {
            if let Ok(idx) = self.raw_channel().alloc_page_in(0) {
                Ok(IoPage {
                    page_idx: idx,
                    raw_channel: self.raw_channel(),
                })
            } else {
                Err(ErrorCode::NotReady)
            }
        }
    }

    pub fn shared_page(&self, page_idx: u16) -> Result<IoPage, ErrorCode> {
        if page_idx >= (CHANNEL_PAGE_COUNT as u16) {
            Err(ErrorCode::InvalidArgument)
        } else {
            Ok(IoPage {
                page_idx,
                raw_channel: self.raw_channel(),
            })
        }
    }

    fn raw_channel(&self) -> &'static mut RawChannel {
        #[cfg(debug_assertions)]
        unsafe {
            self.raw_channel.as_mut().unwrap()
        }

        #[cfg(not(debug_assertions))]
        unsafe {
            self.raw_channel.as_mut().unwrap_unchecked()
        }
    }

    pub fn dump_state(&self) {
        self.raw_channel().dump_state()
    }
}
