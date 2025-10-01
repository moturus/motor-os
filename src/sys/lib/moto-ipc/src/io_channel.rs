//! A generalized asyncrhonous I/O channel.
//!
//! Inspired by io_uring, but necessarily different because it is used
//! for communication between two userspace processes instead of
//! between the kernel and a userspace process.
//!
//! Also simpler than io_uring. More specifically, SQE and CQE have the same layout.
use core::{fmt::Debug, sync::atomic::*};

use moto_sys::*;

// Although client+server can use any value in QueueEntry::command, it is recommended
// that they respect the ranges below.

// Command values in [1..CMD_RESERVED_MAX_CORE] are reserved for core commands,
// such as CMD_NOOP and CMD_CANCEL.
pub const CMD_RESERVED_MAX_CORE: u16 = 0x100;

// Command values in [CMD_RESERVED_MIN_LOCAL..CMD_RESERVED_MAX_LOCAL] are reserved for
// local commands, i.e. those that are not supposed to trigger an IPC.
pub const CMD_RESERVED_MIN_LOCAL: u16 = CMD_RESERVED_MAX_CORE; // 0x100
pub const CMD_RESERVED_MAX_LOCAL: u16 = CMD_RESERVED_MIN_LOCAL + 0x1000; // 0x1100 = 4352

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
    pub fn new_zeroed() -> Self {
        Self { args_64: [0; 3] }
    }

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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Msg {
    pub id: u64,           // IN. See user_data in io_uring.pdf. Used by client-side executor.
    pub handle: u64,       // IN/OUT. Like Windows handle, or Unix fd.
    pub command: u16,      // IN.
    pub status: ErrorCode, // OUT.
    pub flags: u32,        // IN/OUT.
    pub wake_handle: u64,  // IN (used by client-side executor to notify upon completion).
    pub payload: Payload,  // IN/OUT.
}

const _MSG_SIZE: () = assert!(core::mem::size_of::<Msg>() == 56);

// Cache-line aligned, cache-line sized.
#[repr(C, align(64))]
struct MsgSlot {
    pub stamp: AtomicU64, // IN/OUT: same as stamp in crossbeam ArrayQueue, or sequence_ in Dmitry Vyukov's mpmc.
    pub msg: Msg,
}

const _SLOT_SIZE: () = assert!(core::mem::size_of::<MsgSlot>() == 64);

impl Debug for Msg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Msg").field("id", &self.id).finish()
    }
}

impl Default for Msg {
    fn default() -> Self {
        Msg::new()
    }
}

impl Msg {
    pub fn new() -> Self {
        let mut result: Self = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
        result.status = moto_rt::E_NOT_READY;
        result
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }

    pub fn status(&self) -> ErrorCode {
        self.status
    }
}

pub const QUEUE_SIZE: u64 = 64;
const QUEUE_MASK: u64 = QUEUE_SIZE - 1;
pub const CHANNEL_PAGE_COUNT: usize = 64;

#[derive(Clone, Copy, Debug)]
pub enum SubChannelType {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug)]
enum SubChannel {
    Client(u64),
    Server(u64),
}

impl From<SubChannel> for SubChannelType {
    fn from(val: SubChannel) -> SubChannelType {
        match val {
            SubChannel::Client(_) => SubChannelType::Client,
            SubChannel::Server(_) => SubChannelType::Server,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RawIoPage {
    page_idx: u16,
    s_type: SubChannelType,
}

#[repr(C, align(4096))]
struct RawChannel {
    // First 4 cache lines.
    client_queue_head: AtomicU64,
    _pad1: [u64; 7],
    client_queue_tail: AtomicU64,
    _pad2: [u64; 7],
    server_queue_head: AtomicU64,
    _pad3: [u64; 7],
    server_queue_tail: AtomicU64,
    _pad4: [u64; 7],

    client_pages_in_use: AtomicU64,
    _pad5: [u64; 7],
    server_pages_in_use: AtomicU64,
    _pad6: [u64; 7],

    // Pad to BLOCK_SIZE (512 bytes).
    _pad7: [u8; 128],

    // Pad to PAGE_SIZE
    _pad8: [u8; 3584],

    // offset: 4096 = 1 page; client=>server queue.
    client_queue: [MsgSlot; QUEUE_SIZE as usize], // 4096 bytes = 8 blocks

    // offset: 8192 = 2 pages; server=>client queue.
    server_queue: [MsgSlot; QUEUE_SIZE as usize], // 4096 bytes = 8 blocks

    client_pages: [Page; CHANNEL_PAGE_COUNT],
    server_pages: [Page; CHANNEL_PAGE_COUNT],
}

pub const _RAW_CHANNEL_SIZE: () = assert!(core::mem::size_of::<RawChannel>() == ((128 + 3) * 4096));

impl RawChannel {
    fn is_empty(&self) -> bool {
        self.client_queue_head.load(Ordering::Acquire)
            == self.client_queue_tail.load(Ordering::Acquire)
            && self.server_queue_head.load(Ordering::Acquire)
                == self.server_queue_tail.load(Ordering::Acquire)
            && self.client_pages_in_use.load(Ordering::Relaxed) == 0
            && self.server_pages_in_use.load(Ordering::Relaxed) == 0
    }

    fn assert_empty(&self) {
        if !self.is_empty() {
            self.dump_state();
        }
        assert_eq!(
            self.client_queue_head.load(Ordering::Acquire),
            self.client_queue_tail.load(Ordering::Acquire)
        );
        assert_eq!(
            self.server_queue_head.load(Ordering::Acquire),
            self.server_queue_tail.load(Ordering::Acquire)
        );
        assert_eq!(0, self.client_pages_in_use.load(Ordering::Relaxed));
        assert_eq!(0, self.server_pages_in_use.load(Ordering::Relaxed));
    }

    #[allow(clippy::mut_from_ref)]
    fn page_bytes(&self, raw_page: RawIoPage) -> Result<&mut [u8], ErrorCode> {
        if raw_page.page_idx >= (CHANNEL_PAGE_COUNT as u16) {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        unsafe {
            let addr = match raw_page.s_type {
                SubChannelType::Server => {
                    &self.server_pages[raw_page.page_idx as usize] as *const _ as usize
                }
                SubChannelType::Client => {
                    &self.client_pages[raw_page.page_idx as usize] as *const _ as usize
                }
            };
            Ok(core::slice::from_raw_parts_mut(addr as *mut u8, PAGE_SIZE))
        }
    }

    fn may_alloc_page(&self, subchannel: SubChannel) -> bool {
        let (bitmap_ref, subchannel_mask) = match subchannel {
            SubChannel::Client(mask) => (&self.client_pages_in_use, mask),
            SubChannel::Server(mask) => (&self.server_pages_in_use, mask),
        };

        let bitmap = bitmap_ref.load(Ordering::Relaxed);
        let ones = (bitmap | !subchannel_mask).trailing_ones();
        ones != 64
    }

    fn alloc_page(&self, subchannel: SubChannel) -> Result<RawIoPage, ErrorCode> {
        let (bitmap_ref, subchannel_mask) = match subchannel {
            SubChannel::Client(mask) => (&self.client_pages_in_use, mask),
            SubChannel::Server(mask) => (&self.server_pages_in_use, mask),
        };

        loop {
            let bitmap = bitmap_ref.load(Ordering::Relaxed);
            let ones = (bitmap | !subchannel_mask).trailing_ones();
            if ones == 64 {
                // Nothing left.
                return Err(moto_rt::E_NOT_READY);
            }

            let bit = 1u64 << ones;
            debug_assert_eq!(0, bitmap & bit);
            debug_assert_ne!(0, subchannel_mask & bit);
            // We cannot use fetch_xor here, because if a concurent xor succeeds, we may clear it,
            // and another concurrent xor will succeed again, leading to double alloc.
            if bitmap_ref
                .compare_exchange_weak(bitmap, bitmap | bit, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
            {
                // Contention. Mitigated via subchannels.
                continue;
            }

            return Ok(RawIoPage {
                page_idx: ones as u16,
                s_type: subchannel.into(),
            });
        }
    }

    fn free_page(&self, raw_page: RawIoPage) -> Result<(), ErrorCode> {
        if (raw_page.page_idx as usize) >= CHANNEL_PAGE_COUNT {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let bitmap = match raw_page.s_type {
            SubChannelType::Client => &self.client_pages_in_use,
            SubChannelType::Server => &self.server_pages_in_use,
        };

        let bit = 1u64 << raw_page.page_idx;
        if (bitmap.fetch_xor(bit, Ordering::AcqRel) & bit) == 0 {
            // The page was not actually used.
            panic!(
                "io_channel: freeing unused page 0x{:x?}; used pages: 0x{:x}",
                raw_page,
                bitmap.load(Ordering::Relaxed)
            )
        } else {
            Ok(())
        }
    }

    fn dump_state(&self) {
        crate::moto_log!(
            "RawChannel: sqh: {} sqt: {} cqh: {} cqt: {} client pages: 0x{:x} server pages: 0x{:x}",
            self.client_queue_head.load(Ordering::Relaxed),
            self.client_queue_tail.load(Ordering::Relaxed),
            self.server_queue_head.load(Ordering::Relaxed),
            self.server_queue_tail.load(Ordering::Relaxed),
            self.client_pages_in_use.load(Ordering::Relaxed),
            self.server_pages_in_use.load(Ordering::Relaxed),
        );
    }
}

pub struct IoPage {
    raw_page: RawIoPage,
    raw_channel: &'static RawChannel,
}

impl Drop for IoPage {
    fn drop(&mut self) {
        if self.raw_page.page_idx != u16::MAX {
            self.raw_channel.free_page(self.raw_page).unwrap();
        }
    }
}

impl IoPage {
    const SERVER_FLAG: u16 = 1 << 15;
    const _FOO: () = assert!((CHANNEL_PAGE_COUNT as u16) < Self::SERVER_FLAG);

    pub fn bytes(&self) -> &[u8] {
        self.raw_channel.page_bytes(self.raw_page).unwrap()
    }

    pub fn bytes_mut(&self) -> &mut [u8] {
        self.raw_channel.page_bytes(self.raw_page).unwrap()
    }

    /// Consumes the `IoPage`, returning an opaque number.
    ///
    /// To avoid a memory leak the number must be converted back to an `IoPage` using
    /// [`IoPage::from_u16`].
    ///
    pub fn into_u16(mut val: Self) -> u16 {
        let res = match val.raw_page.s_type {
            SubChannelType::Client => val.raw_page.page_idx,
            SubChannelType::Server => val.raw_page.page_idx | Self::SERVER_FLAG,
        };
        val.raw_page.page_idx = u16::MAX;
        res
    }

    /// Constructs an `IoPage` from an opaque number.
    ///
    /// The number must have been previously returned by a call to
    /// [`IoPage::into_u16`][into_u16].
    ///
    fn from_u16(val: u16, raw_channel: &'static RawChannel) -> Self {
        debug_assert!(((val & !Self::SERVER_FLAG) as usize) < CHANNEL_PAGE_COUNT);
        match val & Self::SERVER_FLAG {
            0 => Self {
                raw_page: RawIoPage {
                    page_idx: val,
                    s_type: SubChannelType::Client,
                },
                raw_channel,
            },
            Self::SERVER_FLAG => Self {
                raw_page: RawIoPage {
                    page_idx: val & !Self::SERVER_FLAG,
                    s_type: SubChannelType::Server,
                },
                raw_channel,
            },
            _ => unreachable!(),
        }
    }
}

pub struct ClientConnection {
    raw_channel: AtomicPtr<RawChannel>,
    server_handle: SysHandle,
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        self.clear();
    }
}

impl ClientConnection {
    pub fn connect(url: &str) -> Result<Self, ErrorCode> {
        let addr = SysMem::map(
            SysHandle::SELF,
            SysMem::F_READABLE | SysMem::F_WRITABLE,
            u64::MAX,
            u64::MAX,
            4096,
            (core::mem::size_of::<RawChannel>() >> 12) as u64,
        )?;

        // Safety: safe because we just allocated the memory.
        let raw_channel: &'static mut RawChannel =
            unsafe { (addr as *mut RawChannel).as_mut().unwrap() };

        for idx in 0..(QUEUE_SIZE) {
            raw_channel.client_queue[idx as usize]
                .stamp
                .store(idx, Ordering::Relaxed);
            raw_channel.server_queue[idx as usize]
                .stamp
                .store(idx, Ordering::Relaxed);
        }

        let full_url = alloc::format!(
            "shared:url={};address={};page_type=small;page_num={}",
            moto_sys::url_encode(url),
            addr,
            64
        );

        let server_handle = SysObj::get(SysHandle::SELF, SysObj::F_WAKE_PEER, &full_url)
            .inspect_err(|_| SysMem::free(addr).unwrap())?;

        let self_ = Self {
            raw_channel: AtomicPtr::new(addr as usize as *mut RawChannel),
            server_handle,
        };

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
        SysObj::put(self.server_handle).unwrap();
        self.server_handle = SysHandle::NONE;
    }

    // See enqueue() in mpmc.cc.
    pub fn send(&self, msg: Msg) -> Result<(), ErrorCode> {
        let raw_channel = self.raw_channel();

        let mut slot: &mut MsgSlot;
        let mut pos = raw_channel.client_queue_head.load(Ordering::Relaxed);
        loop {
            slot = &mut raw_channel.client_queue[(pos & QUEUE_MASK) as usize];
            let stamp = slot.stamp.load(Ordering::Acquire);

            match stamp.cmp(&pos) {
                core::cmp::Ordering::Equal => {
                    match raw_channel.client_queue_head.compare_exchange_weak(
                        pos,
                        pos + 1,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(head) => pos = head, // continue
                    }
                }
                // The queue is full.
                core::cmp::Ordering::Less => return Err(moto_rt::E_NOT_READY),
                // We lost the race - continue.
                core::cmp::Ordering::Greater => {
                    pos = raw_channel.client_queue_head.load(Ordering::Relaxed)
                }
            }
        }

        slot.msg = msg;
        slot.stamp.store(pos + 1, Ordering::Release);
        Ok(())
    }

    // See dequeue() in mpmc.cc.
    pub fn recv(&self) -> Result<Msg, ErrorCode> {
        let raw_channel = self.raw_channel();

        let mut slot: &mut MsgSlot;
        let mut pos = raw_channel.server_queue_tail.load(Ordering::Relaxed);

        loop {
            slot = &mut raw_channel.server_queue[(pos & QUEUE_MASK) as usize];
            let stamp = slot.stamp.load(Ordering::Acquire);

            match stamp.cmp(&(pos + 1)) {
                core::cmp::Ordering::Equal => {
                    match raw_channel.server_queue_tail.compare_exchange_weak(
                        pos,
                        pos + 1,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(tail) => pos = tail, // continue
                    }
                }
                core::cmp::Ordering::Less => return Err(moto_rt::E_NOT_READY), // The queue is empty.
                core::cmp::Ordering::Greater => {
                    // We lost the race - continue.
                    pos = raw_channel.server_queue_tail.load(Ordering::Relaxed)
                }
            }
        }

        let cqe = slot.msg;
        slot.stamp.store(pos + QUEUE_SIZE, Ordering::Release);
        Ok(cqe)
    }

    pub fn alloc_page(&self, subchannel_mask: u64) -> Result<IoPage, ErrorCode> {
        if let Ok(raw_page) = self
            .raw_channel()
            .alloc_page(SubChannel::Client(subchannel_mask))
        {
            Ok(IoPage {
                raw_page,
                raw_channel: self.raw_channel(),
            })
        } else {
            Err(moto_rt::E_NOT_READY)
        }
    }

    pub fn may_alloc_page(&self, subchannel_mask: u64) -> bool {
        self.raw_channel()
            .may_alloc_page(SubChannel::Client(subchannel_mask))
    }

    pub fn get_page(&self, page_idx: u16) -> Result<IoPage, ErrorCode> {
        if page_idx & !IoPage::SERVER_FLAG > (CHANNEL_PAGE_COUNT as u16) {
            Err(moto_rt::E_INVALID_ARGUMENT)
        } else {
            Ok(IoPage::from_u16(page_idx, self.raw_channel()))
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

    pub fn assert_empty(&self) {
        self.raw_channel().assert_empty()
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

pub struct ServerConnection {
    raw_channel: *mut RawChannel,
    wait_handle: SysHandle,
    status: ServerStatus,
}

impl Drop for ServerConnection {
    fn drop(&mut self) {
        if !self.raw_channel.is_null() {
            self.clear();
        }
    }
}

impl ServerConnection {
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

        let wait_handle = SysObj::create(SysHandle::SELF, 0, &full_url)
            .inspect_err(|_| SysMem::free(addr).unwrap())?;

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
    pub fn recv(&self) -> Result<Msg, ErrorCode> {
        if self.status != ServerStatus::Connected {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let raw_channel = self.raw_channel();

        let mut slot: &mut MsgSlot;
        let mut pos = raw_channel.client_queue_tail.load(Ordering::Relaxed);
        loop {
            slot = &mut raw_channel.client_queue[(pos & QUEUE_MASK) as usize];
            let stamp = slot.stamp.load(Ordering::Acquire);

            pos = match stamp.cmp(&(pos + 1)) {
                core::cmp::Ordering::Equal => {
                    match raw_channel.client_queue_tail.compare_exchange_weak(
                        pos,
                        pos + 1,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(tail) => tail, // continue
                    }
                }
                core::cmp::Ordering::Less => return Err(moto_rt::E_NOT_READY), // The queue is empty.
                core::cmp::Ordering::Greater => {
                    // We lost the race - continue.
                    raw_channel.client_queue_tail.load(Ordering::Relaxed)
                }
            }
        }

        let sqe = slot.msg;
        slot.stamp.store(pos + QUEUE_SIZE, Ordering::Release);
        Ok(sqe)
    }

    pub async fn recv_async(&self) -> Result<Msg, ErrorCode> {
        core::future::poll_fn(|_cx| match self.recv() {
            Ok(msg) => core::task::Poll::Ready(Ok(msg)),
            Err(moto_rt::E_NOT_READY) => core::task::Poll::Pending,
            Err(err) => core::task::Poll::Ready(Err(err)),
        })
        .await
    }

    // See enqueue() in mpmc.cc.
    pub fn send(&self, sqe: Msg) -> Result<(), ErrorCode> {
        if self.status != ServerStatus::Connected {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let raw_channel = self.raw_channel();

        let mut slot: &mut MsgSlot;
        let mut pos = raw_channel.server_queue_head.load(Ordering::Relaxed);

        loop {
            slot = &mut raw_channel.server_queue[(pos & QUEUE_MASK) as usize];
            let stamp = slot.stamp.load(Ordering::Acquire);

            pos = match stamp.cmp(&pos) {
                core::cmp::Ordering::Equal => {
                    match raw_channel.server_queue_head.compare_exchange_weak(
                        pos,
                        pos + 1,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(head) => head, // continue
                    }
                }
                core::cmp::Ordering::Less => return Err(moto_rt::E_NOT_READY), // The queue is full.
                // We lost the race - continue.
                core::cmp::Ordering::Greater => {
                    raw_channel.server_queue_head.load(Ordering::Relaxed)
                }
            };
        }

        slot.msg = sqe;
        slot.stamp.store(pos + 1, Ordering::Release);
        Ok(())
    }

    pub async fn send_async(&self, msg: Msg) -> Result<(), ErrorCode> {
        core::future::poll_fn(|_cx| match self.send(msg) {
            Ok(()) => core::task::Poll::Ready(Ok(())),
            Err(moto_rt::E_NOT_READY) => core::task::Poll::Pending,
            Err(err) => core::task::Poll::Ready(Err(err)),
        })
        .await
    }

    pub fn wait_handle(&self) -> SysHandle {
        self.wait_handle
    }

    /// # Safety
    ///
    /// Unsafe because it assumes wait on wait_handle succeeded. Otherwise
    /// raw_buf pointer could still be unmapped.
    pub unsafe fn accept(&mut self) -> Result<(), ErrorCode> {
        assert_eq!(self.status, ServerStatus::Created);

        compiler_fence(Ordering::Acquire);
        fence(Ordering::Acquire);

        if (*self.raw_channel)
            .server_queue_head
            .load(Ordering::Relaxed)
            != 0
            || (*self.raw_channel)
                .server_queue_tail
                .load(Ordering::Relaxed)
                != 0
        {
            self.status = ServerStatus::Error(moto_rt::E_BAD_HANDLE);
            self.clear();
            return Err(moto_rt::E_BAD_HANDLE);
        }

        self.status = ServerStatus::Connected;
        Ok(())
    }

    fn clear(&mut self) {
        assert!(!self.raw_channel.is_null());
        SysMem::free(self.raw_channel as usize as u64).unwrap();
        self.raw_channel = core::ptr::null_mut();
        SysObj::put(self.wait_handle).unwrap();
        self.wait_handle = SysHandle::NONE;
    }

    pub fn alloc_page(&self, subchannel_mask: u64) -> Result<IoPage, ErrorCode> {
        if let Ok(raw_page) = self
            .raw_channel()
            .alloc_page(SubChannel::Server(subchannel_mask))
        {
            Ok(IoPage {
                raw_page,
                raw_channel: self.raw_channel(),
            })
        } else {
            Err(moto_rt::E_NOT_READY)
        }
    }

    pub fn may_alloc_page(&self, subchannel_mask: u64) -> bool {
        self.raw_channel()
            .may_alloc_page(SubChannel::Server(subchannel_mask))
    }

    pub fn get_page(&self, page_idx: u16) -> Result<IoPage, ErrorCode> {
        if page_idx & !IoPage::SERVER_FLAG > (CHANNEL_PAGE_COUNT as u16) {
            Err(moto_rt::E_INVALID_ARGUMENT)
        } else {
            Ok(IoPage::from_u16(page_idx, self.raw_channel()))
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
