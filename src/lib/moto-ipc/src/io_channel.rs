//! A generalized asyncrhonous I/O channel.
//!
//! Inspired by io_uring, but necessarily different because it is used
//! for communication between two userspace processes instead of
//! between the kernel and a userspace process.
//!
//! Also simpler than io_uring. More specifically, SQE and CQE have the same layout.
use core::{fmt::Debug, sync::atomic::*};

use moto_sys::{syscalls::*, ErrorCode, SysHandle};

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
// payload::args_64()[3].
pub const FLAG_CMD_NOOP_OK_TIMESTAMP: u32 = 1;

pub const BLOCK_SIZE: usize = 512;

#[repr(C, align(512))]
pub struct Block {
    bytes: [u8; BLOCK_SIZE],
}

#[repr(C, align(4))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IoBuffer {
    pub idx: u16, // The index of the block in the ring. u16::MAX => none.
    pub len: u16, // The number of contiguous blocks.
}

impl IoBuffer {
    pub const MAX_NUM_BLOCKS: u16 = 64;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union Payload {
    buffers: [IoBuffer; 8],
    args_8: [u8; 32],
    args_16: [u16; 16],
    args_32: [u32; 8],
    args_64: [u64; 4],
}

impl Payload {
    pub fn buffers_mut(&mut self) -> &mut [IoBuffer; 8] {
        unsafe { &mut self.buffers }
    }

    pub fn buffers(&self) -> &[IoBuffer; 8] {
        unsafe { &self.buffers }
    }

    pub fn args_8_mut(&mut self) -> &mut [u8; 32] {
        unsafe { &mut self.args_8 }
    }

    pub fn args_16_mut(&mut self) -> &mut [u16; 16] {
        unsafe { &mut self.args_16 }
    }

    pub fn args_32_mut(&mut self) -> &mut [u32; 8] {
        unsafe { &mut self.args_32 }
    }

    pub fn args_64_mut(&mut self) -> &mut [u64; 4] {
        unsafe { &mut self.args_64 }
    }

    pub fn args_8(&self) -> &[u8; 32] {
        unsafe { &self.args_8 }
    }

    pub fn args_16(&self) -> &[u16; 16] {
        unsafe { &self.args_16 }
    }

    pub fn args_32(&self) -> &[u32; 8] {
        unsafe { &self.args_32 }
    }

    pub fn args_64(&self) -> &[u64; 4] {
        unsafe { &self.args_64 }
    }
}

// QueueEntry is used for both the submission queue and the completion queue.
// Cache-line aligned, cache-line sized.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct QueueEntry {
    pub id: u64,          // IN. See user_data in io_uring.pdf.
    pub handle: u64,      // IN/OUT. Like Windows handle, or Unix fd.
    pub command: u16,     // IN.
    pub status: u16,      // OUT.
    pub flags: u32,       // IN/OUT.
    pub wake_handle: u64, // IN (used by client-side executor to notify upon completion).
    pub payload: Payload, // IN/OUT.
}

const _QE_SIZE: () = assert!(core::mem::size_of::<QueueEntry>() == 64);

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

    pub fn poll(&self) -> core::task::Poll<()> {
        compiler_fence(Ordering::Acquire);
        fence(Ordering::Acquire);
        if self.status == ErrorCode::NotReady.into() {
            core::task::Poll::Pending
        } else {
            core::task::Poll::Ready(())
        }
    }

    pub fn wake_waiter(&self) -> Result<(), ErrorCode> {
        SysCpu::wake(SysHandle::from_u64(self.wake_handle))
    }

    pub fn status(&self) -> ErrorCode {
        ErrorCode::from_u16(self.status)
    }
}

const QUEUE_SIZE: u64 = 64;
const QUEUE_MASK: u64 = QUEUE_SIZE - 1;
const BLOCK_COUNT: usize = 111;

#[repr(C, align(4096))]
struct RawChannel {
    // First 4 cache lines.
    submission_queue_head: u64,
    _pad1: [u64; 7],
    submission_queue_tail: u64,
    _pad2: [u64; 7],
    completion_queue_head: u64,
    _pad3: [u64; 7],
    completion_queue_tail: u64,
    _pad4: [u64; 7],

    // Pad to BLOCK_SIZE (512 bytes).
    _pad5: [u8; 256],

    // offset: 512 = 1 block
    submission_queue: [QueueEntry; QUEUE_SIZE as usize], // 4096 bytes = 8 blocks

    // offset: 4608 = 9 blocks
    completion_queue: [QueueEntry; QUEUE_SIZE as usize], // 4096 bytes = 8 blocks

    // offset: 8704 = 17 blocks
    buffers: [Block; BLOCK_COUNT],
}

// 16 pages of 4096.
const _RAW_CHANNEL_SIZE: () = assert!(core::mem::size_of::<RawChannel>() == 65536);

impl RawChannel {
    fn is_empty(&self) -> bool {
        compiler_fence(Ordering::Acquire);
        fence(Ordering::Acquire);

        self.submission_queue_head == self.completion_queue_tail
    }

    pub fn buffer_bytes(&self, buffer: IoBuffer) -> Result<&mut [u8], ErrorCode> {
        if buffer.len == 0 || buffer.idx + buffer.len > (BLOCK_COUNT as u16) {
            return Err(ErrorCode::InvalidArgument);
        }

        let addr = &self.buffers[buffer.idx as usize] as *const _ as usize;
        unsafe {
            Ok(core::slice::from_raw_parts_mut(
                addr as *mut u8,
                (buffer.len as usize) * BLOCK_SIZE,
            ))
        }
    }
}

pub struct Client {
    raw_channel: *mut RawChannel,
    server_handle: SysHandle,
    blocks_in_use: [u64; 2],
}

impl Drop for Client {
    fn drop(&mut self) {
        if !self.raw_channel.is_null() {
            self.clear();
        }
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
            64,
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

        let mut blocks_in_use: [u64; 2] = [0; 2];
        blocks_in_use[1] = !((1_u64 << (BLOCK_COUNT - 64)) - 1);
        debug_assert_eq!(128 - BLOCK_COUNT, blocks_in_use[1].leading_ones() as usize);
        Ok(Self {
            raw_channel: addr as usize as *mut RawChannel,
            server_handle,
            blocks_in_use,
        })
    }

    pub fn server_handle(&self) -> SysHandle {
        self.server_handle
    }

    fn clear(&mut self) {
        assert!(!self.raw_channel.is_null());
        SysMem::free(self.raw_channel as usize as u64).unwrap();
        self.raw_channel = core::ptr::null_mut();
        SysCtl::put(self.server_handle).unwrap();
        self.server_handle = SysHandle::NONE;
    }

    pub fn _cancel_sqe(&mut self, _sqe: QueueEntry) -> Result<(), ErrorCode> {
        todo!()
    }

    pub fn submit_sqe(&mut self, sqe: QueueEntry) -> Result<(), ErrorCode> {
        if self.raw_channel.is_null() {
            return Err(ErrorCode::InvalidArgument);
        }

        let raw_channel = self.raw_channel();
        compiler_fence(Ordering::Acquire);
        fence(Ordering::Acquire);

        let sqe_head = raw_channel.submission_queue_head;
        let sqe_tail = raw_channel.submission_queue_tail;
        debug_assert!(sqe_tail <= sqe_head);
        if sqe_head == (sqe_tail + QUEUE_SIZE) {
            return Err(ErrorCode::NotReady); // Overflow: try again.
        }

        raw_channel.submission_queue[(sqe_head & QUEUE_MASK) as usize] = sqe;

        compiler_fence(Ordering::Release);
        fence(Ordering::Release);
        raw_channel.submission_queue_head += 1;
        compiler_fence(Ordering::Release);
        fence(Ordering::Release);

        Ok(())
    }

    pub fn get_cqe(&mut self) -> Result<QueueEntry, ErrorCode> {
        if self.raw_channel.is_null() {
            return Err(ErrorCode::InvalidArgument);
        }

        compiler_fence(Ordering::Acquire);
        fence(Ordering::Acquire);

        let raw_channel = self.raw_channel();
        let cqe_head = raw_channel.completion_queue_head; // The server.
        let cqe_tail = raw_channel.completion_queue_tail; // The client.
        if cqe_tail == cqe_head {
            return Err(ErrorCode::NotReady); // Overflow: try again.
        }

        debug_assert!(cqe_tail < cqe_head);

        let cqe = raw_channel.completion_queue[(cqe_tail & QUEUE_MASK) as usize];

        compiler_fence(Ordering::Release);
        fence(Ordering::Release);
        raw_channel.completion_queue_tail += 1;
        compiler_fence(Ordering::Release);
        fence(Ordering::Release);

        Ok(cqe)
    }

    fn alloc_buffer_in(
        arena: &mut u64,
        num_blocks: u16,
        idx_offset: u16,
    ) -> Result<IoBuffer, ErrorCode> {
        let idx = arena.trailing_ones() as u16;
        if (idx + num_blocks) < 64 {
            let mut bits = 0_u64;
            for _ in 0..num_blocks {
                bits |= (bits << 1) + (1_u64 << idx);
            }

            if *arena & bits == 0 {
                *arena |= bits;
                return Ok(IoBuffer {
                    idx: idx + idx_offset,
                    len: num_blocks,
                });
            }
        }
        Err(ErrorCode::NotReady)
    }

    pub fn alloc_buffer(&mut self, num_blocks: u16) -> Result<IoBuffer, ErrorCode> {
        // We do not deal with fragmentation: assume that num_blocks is always the same.
        if num_blocks >= IoBuffer::MAX_NUM_BLOCKS {
            return Err(ErrorCode::InvalidArgument);
        }

        if let Ok(buffer) = Self::alloc_buffer_in(&mut self.blocks_in_use[0], num_blocks, 0) {
            Ok(buffer)
        } else {
            Self::alloc_buffer_in(&mut self.blocks_in_use[1], num_blocks, 64)
        }
    }

    pub fn free_buffer(&mut self, buffer: IoBuffer) -> Result<(), ErrorCode> {
        if buffer.idx + buffer.len > (BLOCK_COUNT as u16) {
            return Err(ErrorCode::InvalidArgument);
        }

        if buffer.len > 64 {
            return Err(ErrorCode::InvalidArgument);
        }

        let mut bits = 0_u64;

        let (idx, offset) = if buffer.idx < 64 {
            (buffer.idx, 0)
        } else {
            (buffer.idx - 64, 1)
        };

        for _ in 0..buffer.len {
            bits |= (bits << 1) + (1_u64 << idx);
        }

        if self.blocks_in_use[offset] & bits != bits {
            return Err(ErrorCode::InvalidArgument);
        }

        self.blocks_in_use[offset] ^= bits;

        Ok(())
    }

    pub fn buffer_bytes(&mut self, buffer: IoBuffer) -> Result<&mut [u8], ErrorCode> {
        self.raw_channel().buffer_bytes(buffer)
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

    pub fn is_empty(&self) -> bool {
        self.raw_channel.is_null() || self.raw_channel().is_empty()
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
            64,
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

    pub fn get_sqe(&mut self) -> Result<QueueEntry, ErrorCode> {
        if self.status != ServerStatus::Connected {
            return Err(ErrorCode::InvalidArgument);
        }

        compiler_fence(Ordering::Acquire);
        fence(Ordering::Acquire);

        let raw_channel = self.raw_channel();
        let sqe_head = raw_channel.submission_queue_head; // The client.
        let sqe_tail = raw_channel.submission_queue_tail; // The server.
        if sqe_tail == sqe_head {
            return Err(ErrorCode::NotReady); // Overflow: try again.
        }

        debug_assert!(sqe_tail < sqe_head);

        let sqe = raw_channel.submission_queue[(sqe_tail & QUEUE_MASK) as usize];

        compiler_fence(Ordering::Release);
        fence(Ordering::Release);
        raw_channel.submission_queue_tail += 1;
        compiler_fence(Ordering::Release);
        fence(Ordering::Release);

        Ok(sqe)
    }

    pub fn complete_sqe(&mut self, sqe: QueueEntry) -> Result<(), ErrorCode> {
        if self.status != ServerStatus::Connected {
            return Err(ErrorCode::InvalidArgument);
        }

        compiler_fence(Ordering::Acquire);
        fence(Ordering::Acquire);

        let raw_channel = self.raw_channel();
        let cqe_head = raw_channel.completion_queue_head; // The server.
        let cqe_tail = raw_channel.completion_queue_tail; // The client.
        if cqe_head == (cqe_tail + QUEUE_SIZE) {
            return Err(ErrorCode::NotReady); // Overflow: try again.
        }

        debug_assert!(cqe_head < (cqe_tail + QUEUE_SIZE));

        let cqe = &mut raw_channel.completion_queue[(cqe_head & QUEUE_MASK) as usize];
        *cqe = sqe;

        assert_ne!(sqe.status(), ErrorCode::NotReady);

        compiler_fence(Ordering::Release);
        fence(Ordering::Release);
        raw_channel.completion_queue_head += 1;
        compiler_fence(Ordering::Release);
        fence(Ordering::Release);

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

        if (*self.raw_channel).completion_queue_head != 0
            || (*self.raw_channel).completion_queue_tail != 0
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

    pub fn buffer_bytes(&mut self, buffer: IoBuffer) -> Result<&mut [u8], ErrorCode> {
        self.raw_channel().buffer_bytes(buffer)
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
}
