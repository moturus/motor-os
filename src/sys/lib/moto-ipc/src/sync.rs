use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::any::Any;
use core::slice;
use core::sync::atomic::*;

use moto_sys::ErrorCode;
use moto_sys::*;

// ChannelSize: Small: 4K; Mid: 2M.
#[derive(Clone, Copy)]
pub enum ChannelSize {
    Small,
    Mid,
}

impl ChannelSize {
    pub fn size(&self) -> usize {
        match self {
            ChannelSize::Small => sys_mem::PAGE_SIZE_SMALL as usize,
            ChannelSize::Mid => sys_mem::PAGE_SIZE_MID as usize,
        }
    }
}

// Every request must have this at the beginning.
#[repr(C, align(8))]
pub struct RequestHeader {
    seq: AtomicU64, // For internal use by channel. Odd => request; Even => response.
    pub cmd: u16,
    pub ver: u16,
    pub flags: u32,
}

// Every response must have this at the beginning.
#[repr(C, align(8))]
pub struct ResponseHeader {
    seq: AtomicU64,  // For internal use by channel. Odd => request; Even => response.
    pub result: u16, // ErrorCode.
    pub ver: u16,
    _reserved: u32,
}

// Rust's borrow checker inferferes with direct memory access to the shared mem
// while holding references to connections; exposing RawChannel goes around
// this problem.
pub struct RawChannel {
    addr: usize,
    size: usize,
}

impl RawChannel {
    pub fn size(&self) -> usize {
        self.size
    }

    pub unsafe fn get_mut<T: Sized>(&self) -> &mut T {
        assert!(core::mem::size_of::<T>() <= self.size);
        (self.addr as *mut T).as_mut().unwrap_unchecked()
    }

    pub unsafe fn get<T: Sized>(&self) -> &T {
        assert!(core::mem::size_of::<T>() <= self.size);
        (self.addr as *const T).as_ref().unwrap_unchecked()
    }

    pub unsafe fn get_at_mut<T: Sized>(
        &self,
        buf: &mut [T; 0],
        size: usize,
    ) -> Result<&mut [T], ErrorCode> {
        let start = buf.as_mut_ptr();
        let start_addr = start as usize;
        if (start_addr < self.addr)
            || ((start_addr + core::mem::size_of::<T>() * size) > (self.addr + self.size))
        {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        Ok(core::slice::from_raw_parts_mut(start, size))
    }

    pub unsafe fn get_at<T: Sized>(&self, buf: &[T; 0], size: usize) -> Result<&[T], ErrorCode> {
        let start = buf.as_ptr();
        let start_addr = start as usize;
        if (start_addr < self.addr)
            || ((start_addr + core::mem::size_of::<T>() * size) > (self.addr + self.size))
        {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        Ok(core::slice::from_raw_parts(start, size))
    }

    pub unsafe fn get_bytes(&self, buf: &[u8; 0], size: usize) -> Result<&[u8], ErrorCode> {
        let start = buf.as_ptr();
        let start_addr = start as usize;
        if (start_addr < self.addr) || ((start_addr + size) > (self.addr + self.size)) {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        Ok(core::slice::from_raw_parts(start, size))
    }

    pub unsafe fn get_bytes_mut(
        &self,
        buf: &mut [u8; 0],
        size: usize,
    ) -> Result<&mut [u8], ErrorCode> {
        let start = buf.as_mut_ptr();
        let start_addr = start as usize;
        if (start_addr < self.addr) || ((start_addr + size) > (self.addr + self.size)) {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        Ok(core::slice::from_raw_parts_mut(start, size))
    }

    pub unsafe fn put_bytes(&self, src: &[u8], dst: &mut [u8; 0]) -> Result<(), ErrorCode> {
        let start = dst.as_mut_ptr();
        let start_addr = start as usize;
        if (start_addr < self.addr) || ((start_addr + src.len()) > (self.addr + self.size)) {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        core::intrinsics::copy_nonoverlapping(src.as_ptr(), start, src.len());
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ClientConnectionStatus {
    CONNECTED,
    NONE,
}

pub struct ClientConnection {
    status: ClientConnectionStatus,
    handle: SysHandle,
    smem_addr: u64,
    channel_size: ChannelSize,
    seq: u64,
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        if self.handle != SysHandle::NONE {
            SysObj::put(self.handle).unwrap();
        }

        if self.smem_addr == 0 {
            return;
        }
        match self.channel_size {
            ChannelSize::Small => {
                SysMem::unmap(SysHandle::SELF, 0, u64::MAX, self.smem_addr).unwrap();
            }
            ChannelSize::Mid => {
                SysMem::unmap(SysHandle::SELF, 0, u64::MAX, self.smem_addr).unwrap();
            }
        }
    }
}

impl ClientConnection {
    pub fn new(channel_size: ChannelSize) -> Result<Self, ErrorCode> {
        let addr = match channel_size {
            ChannelSize::Small => SysMem::map(
                SysHandle::SELF,
                SysMem::F_READABLE | SysMem::F_WRITABLE,
                u64::MAX,
                u64::MAX,
                sys_mem::PAGE_SIZE_SMALL,
                1,
            )?,
            ChannelSize::Mid => SysMem::map(
                SysHandle::SELF,
                SysMem::F_READABLE | SysMem::F_WRITABLE,
                u64::MAX,
                u64::MAX,
                sys_mem::PAGE_SIZE_MID,
                1,
            )?,
        };

        let self_ = Self {
            status: ClientConnectionStatus::NONE,
            handle: SysHandle::NONE,
            smem_addr: addr,
            channel_size,
            seq: 0,
        };

        assert_eq!(
            0,
            self_.resp::<ResponseHeader>().seq.load(Ordering::Acquire)
        );

        Ok(self_)
    }

    pub fn connect(&mut self, url: &str) -> Result<(), ErrorCode> {
        assert_eq!(self.status, ClientConnectionStatus::NONE);
        assert_eq!(self.handle, SysHandle::NONE);

        self.req::<RequestHeader>().seq.store(0, Ordering::Release);
        assert_eq!(0, self.seq);

        let full_url = alloc::format!(
            "shared:url={};address={};page_type={};page_num=1",
            url_encode(url),
            self.smem_addr,
            match self.channel_size {
                ChannelSize::Small => "small",
                ChannelSize::Mid => "mid",
            }
        );
        self.handle = SysObj::get(SysHandle::SELF, 0, &full_url)?;
        self.status = ClientConnectionStatus::CONNECTED;
        Ok(())
    }

    pub fn disconnect(&mut self) {
        if self.handle != SysHandle::NONE {
            SysObj::put(self.handle).unwrap();
            self.handle = SysHandle::NONE;
            self.status = ClientConnectionStatus::NONE;

            self.req::<RequestHeader>().seq.store(0, Ordering::Relaxed);
            self.seq = 0;
        }
    }

    pub fn connected(&self) -> bool {
        self.status == ClientConnectionStatus::CONNECTED
    }

    pub fn data(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self.smem_addr as usize as *const u8,
                self.channel_size.size(),
            )
        }
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(self.smem_addr as usize as *mut u8, self.channel_size.size())
        }
    }

    pub fn do_rpc(&mut self, timeout: Option<moto_rt::time::Instant>) -> Result<(), ErrorCode> {
        if self.connected() {
            fence(core::sync::atomic::Ordering::SeqCst);
            let seq = self
                .req::<RequestHeader>()
                .seq
                .fetch_add(1, Ordering::AcqRel);
            assert_eq!(seq, self.seq);
            assert_eq!(seq & 1, 0);
            self.seq = seq + 1;

            loop {
                let mut handles = [self.handle];
                let res = SysCpu::wait(&mut handles, self.handle, SysHandle::NONE, timeout);

                if res.is_ok() {
                    let seq = self.resp::<ResponseHeader>().seq.load(Ordering::SeqCst);
                    if self.seq == seq {
                        continue;
                    }
                    assert_eq!(self.seq + 1, seq);
                    self.seq += 1;
                } else if let Err(moto_rt::E_BAD_HANDLE) = res {
                    assert_eq!(handles[0], self.handle);
                    self.disconnect();
                } else {
                    assert_eq!(res.err().unwrap(), moto_rt::E_TIMED_OUT);
                }
                return res;
            }
        } else {
            Err(moto_rt::E_INVALID_ARGUMENT)
        }
    }

    pub fn req<T: Sized>(&mut self) -> &mut T {
        assert!(core::mem::size_of::<T>() <= self.channel_size.size());
        unsafe {
            (self.data_mut().as_mut_ptr() as *mut T)
                .as_mut()
                .unwrap_unchecked()
        }
    }

    pub fn resp<T: Sized>(&self) -> &T {
        assert!(core::mem::size_of::<T>() <= self.channel_size.size());
        unsafe {
            (self.data().as_ptr() as *const T)
                .as_ref()
                .unwrap_unchecked()
        }
    }

    pub fn raw_channel(&self) -> RawChannel {
        RawChannel {
            addr: self.smem_addr as usize,
            size: self.channel_size.size(),
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
enum LocalServerConnectionStatus {
    LISTENING,
    CONNECTED,
    NONE,
}

pub struct LocalServerConnection {
    status: LocalServerConnectionStatus,
    handle: SysHandle,
    smem_addr: u64,
    channel_size: ChannelSize,
    extension: Box<dyn Any>,
    seq: u64,
}

impl Drop for LocalServerConnection {
    fn drop(&mut self) {
        if self.handle != SysHandle::NONE {
            SysObj::put(self.handle).unwrap();
        }

        if self.smem_addr == 0 {
            return;
        }
        match self.channel_size {
            ChannelSize::Small => {
                SysMem::unmap(SysHandle::SELF, 0, u64::MAX, self.smem_addr).unwrap();
            }
            ChannelSize::Mid => {
                SysMem::unmap(SysHandle::SELF, 0, u64::MAX, self.smem_addr).unwrap();
            }
        }
    }
}

impl LocalServerConnection {
    pub fn new(channel_size: ChannelSize) -> Result<Self, ErrorCode> {
        let addr = match channel_size {
            ChannelSize::Small => SysMem::map(
                SysHandle::SELF,
                0, // Not mapped to a physical frame.
                u64::MAX,
                u64::MAX,
                sys_mem::PAGE_SIZE_SMALL,
                1,
            )?,
            ChannelSize::Mid => SysMem::map(
                SysHandle::SELF,
                0, // Not mapped to a physical frame.
                u64::MAX,
                u64::MAX,
                sys_mem::PAGE_SIZE_MID,
                1,
            )?,
        };

        Ok(Self {
            status: LocalServerConnectionStatus::NONE,
            handle: SysHandle::NONE,
            smem_addr: addr,
            channel_size,
            extension: Box::new(()),
            seq: 0,
        })
    }

    fn start_listening(&mut self, url: &str) -> Result<(), ErrorCode> {
        assert_eq!(self.status, LocalServerConnectionStatus::NONE);
        assert_eq!(self.handle, SysHandle::NONE);

        let full_url = alloc::format!(
            "shared:url={};address={};page_type={};page_num=1",
            url_encode(url),
            self.smem_addr,
            match self.channel_size {
                ChannelSize::Small => "small",
                ChannelSize::Mid => "mid",
            }
        );
        self.handle = SysObj::create(SysHandle::SELF, 0, &full_url)?;
        self.status = LocalServerConnectionStatus::LISTENING;

        Ok(())
    }

    pub fn channel_size(&self) -> usize {
        match self.channel_size {
            ChannelSize::Small => sys_mem::PAGE_SIZE_SMALL as usize,
            ChannelSize::Mid => sys_mem::PAGE_SIZE_MID as usize,
        }
    }

    pub fn data(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self.smem_addr as usize as *const u8,
                self.channel_size.size(),
            )
        }
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(self.smem_addr as usize as *mut u8, self.channel_size.size())
        }
    }

    pub fn raw_channel(&self) -> RawChannel {
        RawChannel {
            addr: self.smem_addr as usize,
            size: self.channel_size.size(),
        }
    }

    pub fn extension<'a, T: 'static>(&'a self) -> Option<&'a T> {
        self.extension.downcast_ref::<T>()
    }

    pub fn extension_mut<'a, T: 'static>(&'a mut self) -> Option<&'a mut T> {
        self.extension.downcast_mut::<T>()
    }

    pub fn set_extension<T: Any>(&mut self, ext: Box<T>) {
        self.extension = ext;
    }

    pub fn connected(&self) -> bool {
        self.status == LocalServerConnectionStatus::CONNECTED
    }

    pub fn disconnect(&mut self) {
        match self.status {
            LocalServerConnectionStatus::LISTENING | LocalServerConnectionStatus::CONNECTED => {
                SysObj::put(self.handle).unwrap();
                self.handle = SysHandle::NONE;
                self.status = LocalServerConnectionStatus::NONE;
                self.seq = 0;
            }
            LocalServerConnectionStatus::NONE => {}
        }
    }

    pub fn finish_rpc(&mut self) -> Result<(), ErrorCode> {
        if self.connected() {
            let seq = self
                .resp::<ResponseHeader>()
                .seq
                .fetch_add(1, Ordering::SeqCst);
            self.seq += 2;
            assert_eq!(self.seq, seq + 1);
            assert_eq!(0, self.seq & 1);
            SysCpu::wake(self.handle).map_err(|err| {
                assert_eq!(err, moto_rt::E_BAD_HANDLE);
                self.disconnect();
                err
            })
        } else {
            Err(moto_rt::E_INVALID_ARGUMENT)
        }
    }

    pub fn req<T: Sized>(&self) -> &T {
        assert!(core::mem::size_of::<T>() <= self.channel_size.size());
        unsafe {
            (self.data().as_ptr() as *const T)
                .as_ref()
                .unwrap_unchecked()
        }
    }

    pub fn resp<T: Sized>(&mut self) -> &mut T {
        assert!(core::mem::size_of::<T>() <= self.channel_size.size());
        unsafe {
            (self.data_mut().as_mut_ptr() as *mut T)
                .as_mut()
                .unwrap_unchecked()
        }
    }

    pub fn handle(&self) -> SysHandle {
        self.handle
    }

    pub fn have_req(&self) -> bool {
        let seq = self.req::<RequestHeader>().seq.load(Ordering::Acquire);
        if seq == self.seq {
            false
        } else {
            assert_eq!(seq, self.seq + 1);
            true
        }
    }
}

// LocalServer: not Send/Sync.
pub struct LocalServer {
    max_connections: u64,
    max_listeners: u64,
    channel_size: ChannelSize,

    url: String,

    listeners: BTreeMap<SysHandle, LocalServerConnection>,
    active_conns: BTreeMap<SysHandle, LocalServerConnection>,
}

impl LocalServer {
    pub fn new(
        url: &str,
        channel_size: ChannelSize,
        max_connections: u64,
        max_listeners: u64,
    ) -> Result<LocalServer, ErrorCode> {
        assert!(max_connections >= max_listeners);

        let mut self_ = Self {
            max_connections,
            max_listeners,
            channel_size,
            url: url.to_owned(),
            listeners: BTreeMap::new(),
            active_conns: BTreeMap::new(),
        };

        for _i in 0..self_.max_listeners {
            self_.add_listener()?;
        }

        Ok(self_)
    }

    fn add_listener(&mut self) -> Result<(), ErrorCode> {
        let mut listener = LocalServerConnection::new(self.channel_size)?;
        listener.start_listening(self.url.as_str())?;
        self.listeners.insert(listener.handle.clone(), listener);
        Ok(())
    }

    pub fn wait(
        &mut self,
        swap_target: SysHandle,
        extra_waiters: &[SysHandle],
    ) -> Result<Vec<SysHandle>, Vec<SysHandle>> {
        while self.listeners.len() < (self.max_listeners as usize)
            && (self.listeners.len() + self.active_conns.len() < (self.max_connections as usize))
        {
            self.add_listener().unwrap();
        }

        let mut waiters = Vec::with_capacity(
            self.listeners.len() + self.active_conns.len() + extra_waiters.len(),
        );

        for k in self.listeners.keys() {
            waiters.push(k.clone());
        }

        let mut bad_connections = Vec::new();
        for k in self.active_conns.keys() {
            let conn = self.active_conns.get(k).unwrap();
            if !conn.connected() {
                bad_connections.push(k.clone());
            } else {
                waiters.push(k.clone());
            }
        }
        for k in bad_connections {
            self.active_conns.remove(&k);
        }

        for k in extra_waiters {
            waiters.push(k.clone());
        }

        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        SysCpu::wait(&mut waiters[..], swap_target, SysHandle::NONE, None).map_err(|err| {
            assert_eq!(err, moto_rt::E_BAD_HANDLE);
            let mut bad_extras = Vec::new();
            for waiter in &waiters {
                if *waiter == SysHandle::NONE {
                    continue;
                }
                if let Some(mut conn) = self.active_conns.remove(&waiter) {
                    assert!(conn.connected());
                    conn.disconnect();
                } else if let Some(mut listener) = self.listeners.remove(&waiter) {
                    // A remote process can connect to the listener and then drop.
                    listener.disconnect();
                } else {
                    bad_extras.push(*waiter);
                }
            }
            bad_extras
        })?;

        let mut wakers = Vec::with_capacity(waiters.len());
        for h in &waiters {
            if *h == SysHandle::NONE {
                break;
            }
            let handle = h.clone();
            if let Some(mut conn) = self.listeners.remove(&handle) {
                assert_eq!(conn.status, LocalServerConnectionStatus::LISTENING);
                conn.status = LocalServerConnectionStatus::CONNECTED;
                let prev = self.active_conns.insert(handle.clone(), conn);
                assert!(prev.is_none());
            }
            wakers.push(handle);
        }

        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        Ok(wakers)
    }

    pub fn get_connection(&mut self, handle: SysHandle) -> Option<&mut LocalServerConnection> {
        self.active_conns.get_mut(&handle)
    }
}
