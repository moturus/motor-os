//! A generalized asyncrhonous I/O channel.
//!
//! Inspired by io_uring, but necessarily different because it is used
//! for communication between two userspace processes instead of
//! between the kernel and a userspace process.
//!
//! Also simpler than io_uring. More specifically, SQE and CQE have the same layout.
//!
//! Async: ServerConnection uses local wakers, ClientConnection uses cross-thread wakers.
use core::{fmt::Debug, sync::atomic::*};

use alloc::sync::Arc;
use moto_async::AsFuture;
use moto_rt::Result;
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

    pub fn set_arg_128(&mut self, val: u128) {
        self.args_64_mut()[0] = (val >> 64) as u64;
        self.args_64_mut()[1] = (val & (u64::MAX as u128)) as u64;
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

    pub fn arg_128(&self) -> u128 {
        (self.args_64()[0] as u128) << 64 | (self.args_64()[1] as u128)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Msg {
    pub id: u64,           // IN. See user_data in io_uring.pdf. Used by client-side executor.
    pub handle: u64,       // IN/OUT. Like Windows handle, or Unix fd.
    pub wake_handle: u64,  // IN (used by client-side executor to notify upon completion).
    pub command: u16,      // IN.
    pub status: ErrorCode, // OUT.
    pub flags: u32,        // IN/OUT.
    pub payload: Payload,  // IN/OUT.
}

const _MSG_SIZE: () = assert!(core::mem::size_of::<Msg>() == 56);

// Cache-line aligned, cache-line sized.
#[repr(C, align(64))]
struct MsgSlot {
    pub stamp: AtomicU64, // IN/OUT: same as stamp in crossbeam ArrayQueue, or sequence_ in Dmitry Vyukov's mpmc.
    pub msg: core::cell::UnsafeCell<Msg>,
}

// Safety: we carefully control acess to slots via stamps. See send/recv below.
unsafe impl Sync for MsgSlot {}

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
        result.status = moto_rt::Error::NotReady.into();
        result
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }

    pub fn status(&self) -> Result<()> {
        if self.status == moto_rt::Error::Ok.into() {
            Ok(())
        } else {
            Err(self.status.into())
        }
    }
}

pub const QUEUE_SIZE: u64 = 64;
const QUEUE_MASK: u64 = QUEUE_SIZE - 1;
pub const CHANNEL_PAGE_COUNT: usize = 64;

#[derive(Clone, Copy, Debug)]
enum EndpointType {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug)]
enum SubChannel {
    Client(u64),
    Server(u64),
}

impl From<SubChannel> for EndpointType {
    fn from(val: SubChannel) -> EndpointType {
        match val {
            SubChannel::Client(_) => EndpointType::Client,
            SubChannel::Server(_) => EndpointType::Server,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RawIoPage {
    page_idx: u16,
    s_type: EndpointType,
}

#[repr(u64)]
enum WaitType {
    NoWait = 0,
    WaitingToSend = 1,
    WaitingToRecv = 2,
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

    // Next 8 cache lines.
    client_pages_in_use: AtomicU64,
    _pad5: [u64; 7],
    server_pages_in_use: AtomicU64,
    _pad6: [u64; 7],

    client_waits: AtomicU64,
    _pad7: [u64; 7],
    server_waits: AtomicU64,
    _pad8: [u64; 7],
    client_page_waits: AtomicU64,
    _pad9: [u64; 7],
    server_page_waits: AtomicU64,

    // Pad to PAGE_SIZE
    _pad10: [u8; 3512],

    // offset: 4096 = 1 page; client=>server queue.
    client_queue: [MsgSlot; QUEUE_SIZE as usize], // 4096 bytes = 8 blocks

    // offset: 8192 = 2 pages; server=>client queue.
    server_queue: [MsgSlot; QUEUE_SIZE as usize], // 4096 bytes = 8 blocks

    client_pages: [Page; CHANNEL_PAGE_COUNT],
    server_pages: [Page; CHANNEL_PAGE_COUNT],
}

const _RAW_CHANNEL_SIZE: () = assert!(core::mem::size_of::<RawChannel>() == ((128 + 3) * 4096));

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
    fn page_bytes(&self, raw_page: RawIoPage) -> Result<&mut [u8]> {
        if raw_page.page_idx >= (CHANNEL_PAGE_COUNT as u16) {
            return Err(moto_rt::Error::InvalidArgument);
        }

        unsafe {
            let addr = match raw_page.s_type {
                EndpointType::Server => {
                    &self.server_pages[raw_page.page_idx as usize] as *const _ as usize
                }
                EndpointType::Client => {
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

    fn alloc_page(&self, subchannel: SubChannel) -> Result<RawIoPage> {
        let (bitmap_ref, subchannel_mask) = match subchannel {
            SubChannel::Client(mask) => (&self.client_pages_in_use, mask),
            SubChannel::Server(mask) => (&self.server_pages_in_use, mask),
        };

        loop {
            let bitmap = bitmap_ref.load(Ordering::Relaxed);
            let ones = (bitmap | !subchannel_mask).trailing_ones();
            if ones == 64 {
                // Nothing left.
                return Err(moto_rt::Error::NotReady);
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

    fn free_page(&self, raw_page: RawIoPage) -> Result<()> {
        if (raw_page.page_idx as usize) >= CHANNEL_PAGE_COUNT {
            return Err(moto_rt::Error::InvalidArgument);
        }

        let bitmap = match raw_page.s_type {
            EndpointType::Client => &self.client_pages_in_use,
            EndpointType::Server => &self.server_pages_in_use,
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

    fn client_queue_full(&self) -> bool {
        let pos = self.client_queue_head.load(Ordering::Relaxed);
        let slot = &self.client_queue[(pos & QUEUE_MASK) as usize];
        let stamp = slot.stamp.load(Ordering::Acquire);

        stamp < pos
    }

    fn server_queue_full(&self) -> bool {
        let pos = self.server_queue_head.load(Ordering::Relaxed);
        let slot = &self.server_queue[(pos & QUEUE_MASK) as usize];
        let stamp = slot.stamp.load(Ordering::Acquire);

        stamp < pos
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

    fn set_server_waiting(&self, wait_type: WaitType) {
        self.server_waits
            .fetch_or(wait_type as u64, Ordering::AcqRel);
    }

    fn is_server_waiting(&self, wait_type: WaitType) -> bool {
        (self.server_waits.load(Ordering::Acquire) & (wait_type as u64)) != 0
    }

    fn set_server_page_wait(&self, subchannel_mask: u64) {
        self.server_page_waits
            .fetch_or(subchannel_mask, Ordering::AcqRel);
    }

    // We clear all waits upon wakeup. Can we do better?
    fn clear_server_waiting(&self) {
        self.server_waits
            .store(WaitType::NoWait as u64, Ordering::Release);
        self.server_page_waits.store(0, Ordering::Release);
    }

    fn set_client_waiting(&self, wait_type: WaitType) {
        self.client_waits
            .fetch_or(wait_type as u64, Ordering::AcqRel);
    }

    fn is_client_waiting(&self, wait_type: WaitType) -> bool {
        (self.client_waits.load(Ordering::Acquire) & (wait_type as u64)) != 0
    }
    fn set_client_page_wait(&self, subchannel_mask: u64) {
        self.client_page_waits
            .fetch_or(subchannel_mask, Ordering::AcqRel);
    }

    // We clear all waits upon wakeup. Can we do better?
    fn clear_client_waiting(&self) {
        self.client_waits
            .store(WaitType::NoWait as u64, Ordering::Release);
        self.client_page_waits.store(0, Ordering::Release);
    }
}

pub struct IoPage {
    raw_page: RawIoPage,
    raw_channel: &'static RawChannel,
    remote_handle: SysHandle,
}

impl Drop for IoPage {
    fn drop(&mut self) {
        if self.raw_page.page_idx != u16::MAX {
            self.raw_channel.free_page(self.raw_page).unwrap();
            if self.remote_handle != SysHandle::NONE {
                assert!(self.raw_page.page_idx < 64);
                let page_mask = 1_u64 << (self.raw_page.page_idx as u64);

                match self.raw_page.s_type {
                    EndpointType::Client => {
                        if self.raw_channel.client_page_waits.load(Ordering::Acquire) & page_mask
                            != 0
                        {
                            let _ = moto_sys::SysCpu::wake(self.remote_handle);
                        }
                    }
                    EndpointType::Server => {
                        if self.raw_channel.server_page_waits.load(Ordering::Acquire) & page_mask
                            != 0
                        {
                            let _ = moto_sys::SysCpu::wake(self.remote_handle);
                        }
                    }
                }
            }
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
            EndpointType::Client => val.raw_page.page_idx,
            EndpointType::Server => val.raw_page.page_idx | Self::SERVER_FLAG,
        };
        val.raw_page.page_idx = u16::MAX;
        res
    }

    /// Constructs an `IoPage` from an opaque number.
    ///
    /// The number must have been previously returned by a call to
    /// [`IoPage::into_u16`][into_u16].
    ///
    fn from_u16(val: u16, raw_channel: &'static RawChannel, remote_handle: SysHandle) -> Self {
        debug_assert!(((val & !Self::SERVER_FLAG) as usize) < CHANNEL_PAGE_COUNT);
        match val & Self::SERVER_FLAG {
            0 => Self {
                raw_page: RawIoPage {
                    page_idx: val,
                    s_type: EndpointType::Client,
                },
                raw_channel,
                remote_handle,
            },
            Self::SERVER_FLAG => Self {
                raw_page: RawIoPage {
                    page_idx: val & !Self::SERVER_FLAG,
                    s_type: EndpointType::Server,
                },
                raw_channel,
                remote_handle,
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
    pub fn connect(url: &str) -> Result<Self> {
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

    pub fn wake_server(&self) -> Result<()> {
        moto_sys::SysCpu::wake(self.server_handle).map_err(|err| err.into())
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
    pub fn send(&self, msg: Msg) -> Result<()> {
        let raw_channel = self.raw_channel();

        let mut slot: &MsgSlot;
        let mut pos = raw_channel.client_queue_head.load(Ordering::Relaxed);
        loop {
            slot = &raw_channel.client_queue[(pos & QUEUE_MASK) as usize];
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
                core::cmp::Ordering::Less => return Err(moto_rt::Error::NotReady),
                // We lost the race - continue.
                core::cmp::Ordering::Greater => {
                    pos = raw_channel.client_queue_head.load(Ordering::Relaxed)
                }
            }
        }

        // Safety: the loop above guarantees that this thread accesses
        // the slot exclusively.
        unsafe { *slot.msg.get() = msg };
        slot.stamp.store(pos + 1, Ordering::Release);
        Ok(())
    }

    // See dequeue() in mpmc.cc.
    pub fn recv(&self) -> Result<Msg> {
        let raw_channel = self.raw_channel();

        let mut slot: &MsgSlot;
        let mut pos = raw_channel.server_queue_tail.load(Ordering::Relaxed);

        loop {
            slot = &raw_channel.server_queue[(pos & QUEUE_MASK) as usize];
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
                core::cmp::Ordering::Less => return Err(moto_rt::Error::NotReady), // The queue is empty.
                core::cmp::Ordering::Greater => {
                    // We lost the race - continue.
                    pos = raw_channel.server_queue_tail.load(Ordering::Relaxed)
                }
            }
        }

        // Safety: the loop above ensures that only this thread access the slot.
        let msg = unsafe { *slot.msg.get() };
        slot.stamp.store(pos + QUEUE_SIZE, Ordering::Release);
        Ok(msg)
    }

    pub fn alloc_page(&self, subchannel_mask: u64) -> Result<IoPage> {
        if let Ok(raw_page) = self
            .raw_channel()
            .alloc_page(SubChannel::Client(subchannel_mask))
        {
            Ok(IoPage {
                raw_page,
                raw_channel: self.raw_channel(),
                remote_handle: SysHandle::NONE,
            })
        } else {
            Err(moto_rt::Error::NotReady)
        }
    }

    pub fn may_alloc_page(&self, subchannel_mask: u64) -> bool {
        self.raw_channel()
            .may_alloc_page(SubChannel::Client(subchannel_mask))
    }

    pub fn get_page(&self, page_idx: u16) -> Result<IoPage> {
        if page_idx & !IoPage::SERVER_FLAG > (CHANNEL_PAGE_COUNT as u16) {
            Err(moto_rt::Error::InvalidArgument)
        } else {
            Ok(IoPage::from_u16(
                page_idx,
                self.raw_channel(),
                SysHandle::NONE,
            ))
        }
    }

    fn raw_channel(&self) -> &'static RawChannel {
        #[cfg(debug_assertions)]
        unsafe {
            let ptr = self.raw_channel.load(Ordering::Relaxed);
            ptr.as_ref().unwrap()
        }

        #[cfg(not(debug_assertions))]
        unsafe {
            let ptr = self.raw_channel.load(Ordering::Relaxed);
            ptr.as_ref().unwrap_unchecked()
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

    pub fn client_queue_full(&self) -> bool {
        self.raw_channel().client_queue_full()
    }

    pub fn server_queue_full(&self) -> bool {
        self.raw_channel().server_queue_full()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServerStatus {
    Created,
    Connected,
    Error(moto_rt::Error),
}

pub struct ServerConnection {
    raw_channel: *mut RawChannel,
    wait_handle: SysHandle,
    status: ServerStatus,
}

unsafe impl Send for ServerConnection {}

impl Drop for ServerConnection {
    fn drop(&mut self) {
        if !self.raw_channel.is_null() {
            self.clear();
        }
    }
}

impl ServerConnection {
    pub fn create(url: &str) -> Result<Self> {
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
    pub fn recv(&self) -> Result<Msg> {
        if self.status != ServerStatus::Connected {
            return Err(moto_rt::Error::InvalidArgument);
        }

        let raw_channel = self.raw_channel();

        let mut slot: &MsgSlot;
        let mut pos = raw_channel.client_queue_tail.load(Ordering::Relaxed);
        loop {
            slot = &raw_channel.client_queue[(pos & QUEUE_MASK) as usize];
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
                core::cmp::Ordering::Less => return Err(moto_rt::Error::NotReady), // The queue is empty.
                core::cmp::Ordering::Greater => {
                    // We lost the race - continue.
                    raw_channel.client_queue_tail.load(Ordering::Relaxed)
                }
            }
        }

        // Safety: the loop above ensures that only this thread access the slot.
        let msg = unsafe { *slot.msg.get() };
        slot.stamp.store(pos + QUEUE_SIZE, Ordering::Release);
        Ok(msg)
    }

    // See enqueue() in mpmc.cc.
    pub fn send(&self, msg: Msg) -> Result<()> {
        if self.status != ServerStatus::Connected {
            return Err(moto_rt::Error::InvalidArgument);
        }

        let raw_channel = self.raw_channel();

        let mut slot: &MsgSlot;
        let mut pos = raw_channel.server_queue_head.load(Ordering::Relaxed);

        loop {
            slot = &raw_channel.server_queue[(pos & QUEUE_MASK) as usize];
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
                core::cmp::Ordering::Less => return Err(moto_rt::Error::NotReady), // The queue is full.
                // We lost the race - continue.
                core::cmp::Ordering::Greater => {
                    raw_channel.server_queue_head.load(Ordering::Relaxed)
                }
            };
        }

        // Safety: the loop above guarantees that this thread accesses
        // the slot exclusively.
        unsafe { *slot.msg.get() = msg };
        slot.stamp.store(pos + 1, Ordering::Release);
        Ok(())
    }

    pub fn wait_handle(&self) -> SysHandle {
        self.wait_handle
    }

    pub fn wake_client(&self) -> Result<()> {
        moto_sys::SysCpu::wake(self.wait_handle).map_err(|err| err.into())
    }

    pub fn accept(&mut self) -> Result<()> {
        assert_eq!(self.status, ServerStatus::Created);

        if !moto_sys::SysObj::is_connected(self.wait_handle)? {
            return Err(moto_rt::Error::NotConnected);
        };

        compiler_fence(Ordering::Acquire);
        fence(Ordering::Acquire);

        // Safety: safe because we checked is_connected above.
        unsafe {
            if (*self.raw_channel)
                .server_queue_head
                .load(Ordering::Relaxed)
                != 0
                || (*self.raw_channel)
                    .server_queue_tail
                    .load(Ordering::Relaxed)
                    != 0
            {
                self.status = ServerStatus::Error(moto_rt::Error::BadHandle);
                self.clear();
                return Err(moto_rt::Error::BadHandle);
            }
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

    pub fn alloc_page(&self, subchannel_mask: u64) -> Result<IoPage> {
        if let Ok(raw_page) = self
            .raw_channel()
            .alloc_page(SubChannel::Server(subchannel_mask))
        {
            Ok(IoPage {
                raw_page,
                raw_channel: self.raw_channel(),
                remote_handle: SysHandle::NONE,
            })
        } else {
            Err(moto_rt::Error::NotReady)
        }
    }

    pub fn may_alloc_page(&self, subchannel_mask: u64) -> bool {
        self.raw_channel()
            .may_alloc_page(SubChannel::Server(subchannel_mask))
    }

    pub fn get_page(&self, page_idx: u16) -> Result<IoPage> {
        if page_idx & !IoPage::SERVER_FLAG > (CHANNEL_PAGE_COUNT as u16) {
            Err(moto_rt::Error::InvalidArgument)
        } else {
            Ok(IoPage::from_u16(
                page_idx,
                self.raw_channel(),
                SysHandle::NONE,
            ))
        }
    }

    fn raw_channel(&self) -> &'static RawChannel {
        #[cfg(debug_assertions)]
        unsafe {
            self.raw_channel.as_ref().unwrap()
        }

        #[cfg(not(debug_assertions))]
        unsafe {
            self.raw_channel.as_ref().unwrap_unchecked()
        }
    }

    pub fn dump_state(&self) {
        self.raw_channel().dump_state()
    }

    pub fn client_queue_full(&self) -> bool {
        self.raw_channel().client_queue_full()
    }

    pub fn server_queue_full(&self) -> bool {
        self.raw_channel().server_queue_full()
    }
}

struct IoChannelImpl {
    raw_channel: AtomicPtr<RawChannel>,
    remote_handle: SysHandle,
    endpoint_type: EndpointType,
}

impl Drop for IoChannelImpl {
    fn drop(&mut self) {
        let addr = self.raw_channel.load(Ordering::Acquire) as usize;
        SysMem::free(addr as u64).unwrap();
        SysObj::put(self.remote_handle).unwrap();
    }
}

impl IoChannelImpl {
    #[inline]
    fn raw_channel(&self) -> &'static RawChannel {
        unsafe {
            let ptr = self.raw_channel.load(Ordering::Relaxed);
            ptr.as_ref().unwrap()
        }
    }
}

#[derive(Clone)]
pub struct Sender {
    inner: Arc<IoChannelImpl>,
}

// Note: having multiple senders in different threads is fishy: not
// tested and maybe suboptimal (they will have to wait on the same remote handle).
impl !Sync for Sender {}

impl Sender {
    #[inline]
    fn raw_channel(&self) -> &'static RawChannel {
        self.inner.raw_channel()
    }

    // See enqueue() in mpmc.cc.
    fn try_send(&self, msg: Msg) -> Result<()> {
        let raw_channel = self.raw_channel();

        let (queue_head, queue) = match self.inner.endpoint_type {
            EndpointType::Client => (&raw_channel.client_queue_head, &raw_channel.client_queue),
            EndpointType::Server => (&raw_channel.server_queue_head, &raw_channel.server_queue),
        };

        let mut slot: &MsgSlot;
        let mut pos = queue_head.load(Ordering::Relaxed);
        loop {
            slot = &queue[(pos & QUEUE_MASK) as usize];
            let stamp = slot.stamp.load(Ordering::Acquire);

            match stamp.cmp(&pos) {
                core::cmp::Ordering::Equal => {
                    match queue_head.compare_exchange_weak(
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
                core::cmp::Ordering::Less => return Err(moto_rt::Error::NotReady),
                // We lost the race - continue.
                core::cmp::Ordering::Greater => pos = queue_head.load(Ordering::Relaxed),
            }
        }

        // Safety: the loop above ensures that this thread has exclusive access to the slot.
        unsafe { *slot.msg.get() = msg };
        slot.stamp.store(pos + 1, Ordering::Release);
        Ok(())
    }

    pub async fn send(&self, msg: Msg) -> Result<()> {
        use moto_async::AsFuture;

        let mut wait_flag_set = false;
        loop {
            match self.try_send(msg) {
                Err(moto_rt::Error::NotReady) => {
                    if !wait_flag_set {
                        match self.inner.endpoint_type {
                            EndpointType::Client => self
                                .raw_channel()
                                .set_client_waiting(WaitType::WaitingToSend),
                            EndpointType::Server => self
                                .raw_channel()
                                .set_server_waiting(WaitType::WaitingToSend),
                        }

                        wait_flag_set = true;
                        continue; // Need to try send() once more.
                    }

                    self.inner.remote_handle.as_future().await?;
                    // We clear all wait flags on wakeup. Can we do better?
                    match self.inner.endpoint_type {
                        EndpointType::Client => self.raw_channel().clear_client_waiting(),
                        EndpointType::Server => self.raw_channel().clear_server_waiting(),
                    }
                    wait_flag_set = false;
                }
                Err(err) => return Err(err),
                Ok(()) => {
                    if match self.inner.endpoint_type {
                        EndpointType::Client => self
                            .raw_channel()
                            .is_server_waiting(WaitType::WaitingToRecv),
                        EndpointType::Server => self
                            .raw_channel()
                            .is_client_waiting(WaitType::WaitingToRecv),
                    } {
                        moto_sys::SysCpu::wake(self.inner.remote_handle)?;
                    }
                    return Ok(());
                }
            }
        }
    }

    fn try_alloc_page(&self, subchannel_mask: u64) -> Result<IoPage> {
        if let Ok(raw_page) = self
            .raw_channel()
            .alloc_page(match self.inner.endpoint_type {
                EndpointType::Client => SubChannel::Client(subchannel_mask),
                EndpointType::Server => SubChannel::Server(subchannel_mask),
            })
        {
            Ok(IoPage {
                raw_page,
                raw_channel: self.raw_channel(),
                remote_handle: self.inner.remote_handle,
            })
        } else {
            Err(moto_rt::Error::NotReady)
        }
    }

    pub async fn alloc_page(&self, subchannel_mask: u64) -> Result<IoPage> {
        use moto_async::AsFuture;

        let mut wait_flag_set = false;
        loop {
            match self.try_alloc_page(subchannel_mask) {
                Err(moto_rt::Error::NotReady) => {
                    if !wait_flag_set {
                        match self.inner.endpoint_type {
                            EndpointType::Client => {
                                self.raw_channel().set_client_page_wait(subchannel_mask)
                            }
                            EndpointType::Server => {
                                self.raw_channel().set_server_page_wait(subchannel_mask)
                            }
                        }

                        wait_flag_set = true;
                        continue; // Try one more alloc() before waiting.
                    } else {
                        self.inner.remote_handle.as_future().await?;
                        // We clear all wait flags on wakeup. Can we do better?
                        match self.inner.endpoint_type {
                            EndpointType::Client => self.raw_channel().clear_client_waiting(),
                            EndpointType::Server => self.raw_channel().clear_server_waiting(),
                        }
                        wait_flag_set = false;
                    }
                }
                Err(err) => return Err(err),
                Ok(page) => return Ok(page),
            }
        }
    }

    pub fn get_page(&self, page_idx: u16) -> Result<IoPage> {
        if (page_idx & !IoPage::SERVER_FLAG) > (CHANNEL_PAGE_COUNT as u16) {
            Err(moto_rt::Error::InvalidArgument)
        } else {
            Ok(IoPage::from_u16(
                page_idx,
                self.raw_channel(),
                self.inner.remote_handle,
            ))
        }
    }
}

pub struct Receiver {
    inner: Arc<IoChannelImpl>,
    recv_future: moto_async::SysHandleFuture,
}

impl !Sync for Receiver {}

impl Receiver {
    #[inline]
    fn raw_channel(&self) -> &'static RawChannel {
        self.inner.raw_channel()
    }

    // See dequeue() in mpmc.cc.
    fn try_recv(&self) -> Result<Msg> {
        let raw_channel = self.raw_channel();

        let mut slot: &MsgSlot;
        let (queue_tail, queue) = match self.inner.endpoint_type {
            EndpointType::Client => (&raw_channel.server_queue_tail, &raw_channel.server_queue),
            EndpointType::Server => (&raw_channel.client_queue_tail, &raw_channel.client_queue),
        };

        let mut pos = queue_tail.load(Ordering::Relaxed);

        loop {
            slot = &queue[(pos & QUEUE_MASK) as usize];
            let stamp = slot.stamp.load(Ordering::Acquire);

            match stamp.cmp(&(pos + 1)) {
                core::cmp::Ordering::Equal => {
                    match queue_tail.compare_exchange_weak(
                        pos,
                        pos + 1,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(tail) => pos = tail, // continue
                    }
                }
                core::cmp::Ordering::Less => return Err(moto_rt::Error::NotReady), // The queue is empty.
                core::cmp::Ordering::Greater => {
                    // We lost the race - continue.
                    pos = queue_tail.load(Ordering::Relaxed)
                }
            }
        }

        // Safety: the loop above ensures that only this thread access the slot.
        let msg = unsafe { *slot.msg.get() };
        slot.stamp.store(pos + QUEUE_SIZE, Ordering::Release);
        Ok(msg)
    }

    pub fn poll_recv(&mut self, cx: &mut core::task::Context<'_>) -> core::task::Poll<Result<Msg>> {
        let mut wait_flag_set = false;
        let mut wait_error = moto_rt::Error::Ok;
        loop {
            match self.try_recv() {
                Err(moto_rt::Error::NotReady) => {
                    if wait_error != moto_rt::Error::Ok {
                        return core::task::Poll::Ready(Err(wait_error));
                    }
                    if !wait_flag_set {
                        match self.inner.endpoint_type {
                            EndpointType::Client => self
                                .raw_channel()
                                .set_client_waiting(WaitType::WaitingToRecv),
                            EndpointType::Server => self
                                .raw_channel()
                                .set_server_waiting(WaitType::WaitingToRecv),
                        }
                        wait_flag_set = true;
                        continue; // Do one more recv() before waiting.
                    } else {
                        match self.recv_future.do_poll(cx) {
                            core::task::Poll::Ready(Err(err)) => {
                                wait_error = err;
                                continue; // Do one more recv() before returning.
                            }
                            core::task::Poll::Ready(Ok(())) => {}
                            core::task::Poll::Pending => return core::task::Poll::Pending,
                        }

                        // Wakeup; we clear all wait flags on wakeup. Can we do better?
                        match self.inner.endpoint_type {
                            EndpointType::Client => self.raw_channel().clear_client_waiting(),
                            EndpointType::Server => self.raw_channel().clear_server_waiting(),
                        }
                        wait_flag_set = false;
                    }
                }
                Err(err) => return core::task::Poll::Ready(Err(err)),
                Ok(msg) => {
                    if match self.inner.endpoint_type {
                        EndpointType::Client => self
                            .raw_channel()
                            .is_server_waiting(WaitType::WaitingToSend),

                        EndpointType::Server => self
                            .raw_channel()
                            .is_client_waiting(WaitType::WaitingToSend),
                    } {
                        // Ignore errors on recv.
                        let _ = moto_sys::SysCpu::wake(self.inner.remote_handle);
                    }
                    return core::task::Poll::Ready(Ok(msg));
                }
            }
        }
    }

    pub async fn recv(&mut self) -> Result<Msg> {
        core::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    pub fn get_page(&self, page_idx: u16) -> Result<IoPage> {
        if (page_idx & !IoPage::SERVER_FLAG) > (CHANNEL_PAGE_COUNT as u16) {
            Err(moto_rt::Error::InvalidArgument)
        } else {
            Ok(IoPage::from_u16(
                page_idx,
                self.raw_channel(),
                self.inner.remote_handle,
            ))
        }
    }
}

pub fn connect(url: &str) -> Result<(Sender, Receiver)> {
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

    let remote_handle = SysObj::get(SysHandle::SELF, SysObj::F_WAKE_PEER, &full_url)
        .inspect_err(|_| SysMem::free(addr).unwrap())?;

    let raw_channel = AtomicPtr::new(addr as usize as *mut RawChannel);
    let sender = Sender {
        inner: Arc::new(IoChannelImpl {
            raw_channel,
            remote_handle,
            endpoint_type: EndpointType::Client,
        }),
    };
    let receiver = Receiver {
        inner: sender.inner.clone(),
        recv_future: sender.inner.remote_handle.as_future(),
    };

    Ok((sender, receiver))
}

pub async fn listen(url: &str) -> Result<(Sender, Receiver)> {
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

    let remote_handle = SysObj::create(SysHandle::SELF, 0, &full_url)
        .inspect_err(|_| SysMem::free(addr).unwrap())?;

    remote_handle.as_future().await?;

    if !moto_sys::SysObj::is_connected(remote_handle)? {
        return Err(moto_rt::Error::NotConnected);
    };

    compiler_fence(Ordering::Acquire);
    fence(Ordering::Acquire);

    // Safety: safe because we checked is_connected above.
    unsafe {
        let raw_channel = addr as usize as *mut RawChannel;
        if (*raw_channel).server_queue_head.load(Ordering::Relaxed) != 0
            || (*raw_channel).server_queue_tail.load(Ordering::Relaxed) != 0
        {
            return Err(moto_rt::Error::BadHandle);
        }
    }

    let raw_channel = AtomicPtr::new(addr as usize as *mut RawChannel);
    let sender = Sender {
        inner: Arc::new(IoChannelImpl {
            raw_channel,
            remote_handle,
            endpoint_type: EndpointType::Server,
        }),
    };
    let receiver = Receiver {
        inner: sender.inner.clone(),
        recv_future: sender.inner.remote_handle.as_future(),
    };

    Ok((sender, receiver))
}
