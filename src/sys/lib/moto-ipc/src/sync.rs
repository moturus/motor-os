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

    /// # Safety
    ///
    /// Assumes RawChannel is properly initialized and contains T.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_mut<T: Sized>(&self) -> &mut T {
        assert!(core::mem::size_of::<T>() <= self.size);
        (self.addr as *mut T).as_mut().unwrap_unchecked()
    }

    /// # Safety
    ///
    /// Assumes RawChannel is properly initialized and contains T.
    pub unsafe fn get<T: Sized>(&self) -> &T {
        assert!(core::mem::size_of::<T>() <= self.size);
        (self.addr as *const T).as_ref().unwrap_unchecked()
    }

    /// # Safety
    ///
    /// Assumes RawChannel is properly initialized and contains T.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_at_mut<T: Sized>(
        &self,
        buf: *mut T,
        size: usize,
    ) -> Result<&mut [T], ErrorCode> {
        let start_addr = buf as usize;
        if (start_addr < self.addr)
            || ((start_addr + core::mem::size_of::<T>() * size) > (self.addr + self.size))
        {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        Ok(core::slice::from_raw_parts_mut(buf, size))
    }

    /// # Safety
    ///
    /// Assumes RawChannel is properly initialized and contains T.
    pub unsafe fn get_at<T: Sized>(&self, buf: *const T, size: usize) -> Result<&[T], ErrorCode> {
        let start_addr = buf as usize;
        if (start_addr < self.addr)
            || ((start_addr + core::mem::size_of::<T>() * size) > (self.addr + self.size))
        {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        Ok(core::slice::from_raw_parts(buf, size))
    }

    /// # Safety
    ///
    /// Assumes RawChannel is properly initialized.
    pub unsafe fn get_bytes(&self, buf: *const u8, size: usize) -> Result<&[u8], ErrorCode> {
        let start_addr = buf as usize;
        if (start_addr < self.addr) || ((start_addr + size) > (self.addr + self.size)) {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        Ok(core::slice::from_raw_parts(buf, size))
    }

    /// # Safety
    ///
    /// Assumes RawChannel is properly initialized.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn get_bytes_mut(&self, buf: *mut u8, size: usize) -> Result<&mut [u8], ErrorCode> {
        let start_addr = buf as usize;
        if (start_addr < self.addr) || ((start_addr + size) > (self.addr + self.size)) {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        Ok(core::slice::from_raw_parts_mut(buf, size))
    }

    /// # Safety
    ///
    /// Assumes RawChannel is properly initialized.
    pub unsafe fn put_bytes(&self, src: &[u8], dst: *mut u8) -> Result<(), ErrorCode> {
        let start_addr = dst as usize;
        if (start_addr < self.addr) || ((start_addr + src.len()) > (self.addr + self.size)) {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ClientConnectionStatus {
    Connected,
    None,
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
            status: ClientConnectionStatus::None,
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
        assert_eq!(self.status, ClientConnectionStatus::None);
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
        self.status = ClientConnectionStatus::Connected;
        Ok(())
    }

    pub fn disconnect(&mut self) {
        if self.handle != SysHandle::NONE {
            SysObj::put(self.handle).unwrap();
            self.handle = SysHandle::NONE;
            self.status = ClientConnectionStatus::None;

            self.req::<RequestHeader>().seq.store(0, Ordering::Relaxed);
            self.seq = 0;
        }
    }

    pub fn connected(&self) -> bool {
        self.status == ClientConnectionStatus::Connected
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
                .fetch_add(1, Ordering::SeqCst);
            assert_eq!(seq, self.seq);
            assert_eq!(seq & 1, 0);
            self.seq += 1;

            // moto_rt::moto_log!("do_rpc 200 {:?}", self.handle);
            loop {
                let mut handles = [self.handle];
                let res = SysCpu::wait(&mut handles, self.handle, SysHandle::NONE, timeout);

                fence(core::sync::atomic::Ordering::SeqCst);
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
    Listening,
    Connected,
    None,
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
            status: LocalServerConnectionStatus::None,
            handle: SysHandle::NONE,
            smem_addr: addr,
            channel_size,
            extension: Box::new(()),
            seq: 0,
        })
    }

    fn start_listening(&mut self, url: &str) -> Result<(), ErrorCode> {
        assert_eq!(self.status, LocalServerConnectionStatus::None);
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
        self.status = LocalServerConnectionStatus::Listening;

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

    pub fn extension<T: 'static>(&self) -> Option<&T> {
        self.extension.downcast_ref::<T>()
    }

    pub fn extension_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.extension.downcast_mut::<T>()
    }

    pub fn set_extension<T: Any>(&mut self, ext: Box<T>) {
        self.extension = ext;
    }

    pub fn connected(&self) -> bool {
        self.status == LocalServerConnectionStatus::Connected
    }

    pub fn disconnect(&mut self) {
        match self.status {
            LocalServerConnectionStatus::Listening | LocalServerConnectionStatus::Connected => {
                SysObj::put(self.handle).unwrap();
                self.handle = SysHandle::NONE;
                self.status = LocalServerConnectionStatus::None;
                self.seq = 0;
            }
            LocalServerConnectionStatus::None => {}
        }
    }

    pub fn finish_rpc(&mut self) -> Result<(), ErrorCode> {
        if self.connected() {
            self.seq += 2;
            let seq = self
                .resp::<ResponseHeader>()
                .seq
                .fetch_add(1, Ordering::SeqCst);
            assert_eq!(self.seq, seq + 1);
            assert_eq!(0, self.seq & 1);
            SysCpu::wake(self.handle).inspect_err(|err| {
                assert_eq!(*err, moto_rt::E_BAD_HANDLE);
                self.disconnect();
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
        let seq = self.req::<RequestHeader>().seq.load(Ordering::SeqCst);
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
        self.listeners.insert(listener.handle, listener);
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
            waiters.push(*k);
        }

        let mut bad_connections = Vec::new();
        for k in self.active_conns.keys() {
            let conn = self.active_conns.get(k).unwrap();
            if !conn.connected() {
                bad_connections.push(*k);
            } else {
                waiters.push(*k);
            }
        }
        for k in bad_connections {
            self.active_conns.remove(&k);
        }

        for k in extra_waiters {
            waiters.push(*k);
        }

        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        SysCpu::wait(&mut waiters[..], swap_target, SysHandle::NONE, None).map_err(|err| {
            assert_eq!(err, moto_rt::E_BAD_HANDLE);
            let mut bad_extras = Vec::new();
            for waiter in &waiters {
                if *waiter == SysHandle::NONE {
                    continue;
                }
                if let Some(mut conn) = self.active_conns.remove(waiter) {
                    assert!(conn.connected());
                    conn.disconnect();
                } else if let Some(mut listener) = self.listeners.remove(waiter) {
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
            let handle = *h;
            if let Some(mut conn) = self.listeners.remove(&handle) {
                assert_eq!(conn.status, LocalServerConnectionStatus::Listening);
                conn.status = LocalServerConnectionStatus::Connected;
                let prev = self.active_conns.insert(handle, conn);
                assert!(prev.is_none());
            }
            wakers.push(handle);
        }

        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        Ok(wakers)
    }

    pub fn get_connection(&mut self, handle: SysHandle) -> Option<&mut LocalServerConnection> {
        self.active_conns.get_mut(&handle)
    }
}
