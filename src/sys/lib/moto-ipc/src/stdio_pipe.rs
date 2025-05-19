//! A simplex pipe used exclusively by rt.vdso for cross-process stdio.
//!
//! The module belongs into rt.vdso, but then it would be difficult to test it,
//! as `cargo test` isn't easy for cross-compiled stuff, and our vdso is an even
//! more exotic target than a normal motor-os binary.
//!
//! DO NOT USE outside of rt.vdso.

use core::sync::atomic::{AtomicUsize, Ordering};

use moto_rt::{spinlock::SpinLock, E_INVALID_ARGUMENT};
use moto_sys::*;

struct PipeBuffer {
    buf_addr: usize,
    work_buf_len: usize,
    work_buf: &'static mut [u8],
    error_code: ErrorCode,
    ipc_handle: SysHandle,
}

impl Drop for PipeBuffer {
    fn drop(&mut self) {
        moto_sys::SysObj::put(self.ipc_handle).unwrap();
        moto_sys::SysMem::unmap(SysHandle::SELF, 0, u64::MAX, self.buf_addr as u64).unwrap();
    }
}

impl PipeBuffer {
    const CACHELINE_SIZE: usize = 64;
    // Place reader/writer counters on their own cache lines.
    const READER_COUNTER_OFFSET: usize = 0;
    const WRITER_COUNTER_OFFSET: usize = Self::CACHELINE_SIZE;
    const DATA_OFFSET: usize = Self::CACHELINE_SIZE * 2;

    const VERSION_OFFSET: usize = Self::READER_COUNTER_OFFSET + 16;

    unsafe fn new(buf_addr: usize, buf_size: usize, ipc_handle: SysHandle) -> Self {
        assert!(buf_addr & (Self::CACHELINE_SIZE - 1) == 0); // Require cacheline alignment.
        assert!(buf_size & (Self::CACHELINE_SIZE - 1) == 0); // Require cacheline alignment.
        assert!((buf_size >> 1) + Self::DATA_OFFSET < buf_size);
        assert!(buf_size.is_power_of_two());

        assert!(Self::version(buf_addr) == 0);

        let work_buf_len = buf_size >> 1;
        PipeBuffer {
            buf_addr,
            work_buf_len,
            work_buf: core::slice::from_raw_parts_mut(
                (buf_addr + Self::DATA_OFFSET) as *mut u8,
                work_buf_len,
            ),
            error_code: moto_rt::E_OK,
            ipc_handle,
        }
    }

    fn version(buf_addr: usize) -> u64 {
        unsafe {
            let addr = buf_addr + Self::VERSION_OFFSET;
            *(addr as *const u64).as_ref().unwrap_unchecked()
        }
    }

    fn reader_counter(&self) -> &AtomicUsize {
        unsafe {
            let addr = self.buf_addr + Self::READER_COUNTER_OFFSET;
            (addr as *const AtomicUsize).as_ref().unwrap_unchecked()
        }
    }

    fn writer_counter(&self) -> &AtomicUsize {
        unsafe {
            let addr = self.buf_addr + Self::WRITER_COUNTER_OFFSET;
            (addr as *const AtomicUsize).as_ref().unwrap_unchecked()
        }
    }

    fn assert_invariants(&self) {
        assert!(
            self.reader_counter().load(Ordering::SeqCst)
                <= self.writer_counter().load(Ordering::SeqCst)
        );
    }

    fn can_read(&self) -> bool {
        self.reader_counter().load(Ordering::Relaxed)
            < self.writer_counter().load(Ordering::Relaxed)
    }

    fn can_write(&self) -> bool {
        self.writer_counter().load(Ordering::Relaxed)
            < ((self.reader_counter().load(Ordering::Relaxed)) + self.work_buf_len)
    }

    fn write(&mut self, src: &[u8]) -> usize {
        let reader_counter = self.reader_counter().load(Ordering::SeqCst);
        let writer_counter = self.writer_counter().load(Ordering::SeqCst);

        let mut to_write = reader_counter + self.work_buf_len - writer_counter;

        if to_write > src.len() {
            to_write = src.len();
        }

        if to_write == 0 {
            return 0;
        }

        let writer_offset = writer_counter & (self.work_buf_len - 1);
        if (writer_offset + to_write) <= self.work_buf_len {
            self.work_buf[writer_offset..(writer_offset + to_write)]
                .copy_from_slice(&src[0..to_write]);
            self.writer_counter().fetch_add(to_write, Ordering::SeqCst);
            return to_write;
        }

        let first_write = self.work_buf_len - writer_offset;
        self.work_buf[writer_offset..self.work_buf_len].copy_from_slice(&src[0..first_write]);

        let second_write = to_write - first_write;
        self.work_buf[0..second_write].copy_from_slice(&src[first_write..to_write]);

        self.writer_counter().fetch_add(to_write, Ordering::SeqCst);
        to_write
    }

    fn read(&mut self, dst: &mut [u8]) -> usize {
        let writer_counter = self.writer_counter().load(Ordering::SeqCst);
        let reader_counter = self.reader_counter().load(Ordering::SeqCst);

        let mut to_read = writer_counter - reader_counter;

        if to_read > dst.len() {
            to_read = dst.len();
        }

        if to_read == 0 {
            return 0;
        }

        let reader_offset = reader_counter & (self.work_buf_len - 1);
        if (reader_offset + to_read) <= self.work_buf_len {
            (&mut *dst)[0..to_read]
                .copy_from_slice(&self.work_buf[reader_offset..(reader_offset + to_read)]);
            self.reader_counter().fetch_add(to_read, Ordering::SeqCst);
            return to_read;
        }

        let first_read = self.work_buf_len - reader_offset;
        (&mut *dst)[0..first_read]
            .copy_from_slice(&self.work_buf[reader_offset..self.work_buf_len]);

        let second_read = to_read - first_read;
        (&mut *dst)[first_read..to_read].copy_from_slice(&self.work_buf[0..second_read]);

        self.reader_counter().fetch_add(to_read, Ordering::SeqCst);
        to_read
    }

    // Assuming the reader is gone, restore the unread bytes.
    fn unwrite(&mut self) -> usize {
        let writer_counter = self.writer_counter().load(Ordering::SeqCst);
        let reader_counter = self.reader_counter().load(Ordering::SeqCst);

        if writer_counter == reader_counter {
            return 0;
        }

        self.writer_counter()
            .store(reader_counter, Ordering::SeqCst);

        writer_counter - reader_counter
    }
}

pub struct StdioPipe {
    buffer: Option<SpinLock<PipeBuffer>>,
    is_reader: bool,
    handle: SysHandle,
}

impl StdioPipe {
    pub const fn new_empty() -> Self {
        Self {
            buffer: None,
            is_reader: false,
            handle: SysHandle::NONE,
        }
    }

    pub fn is_reader(&self) -> bool {
        self.is_reader
    }

    pub fn can_read(&self) -> bool {
        if !self.is_reader {
            return false;
        }

        let Some(buffer) = self.buffer.as_ref() else {
            return false;
        };

        buffer.lock().can_read()
    }

    pub fn can_write(&self) -> bool {
        if self.is_reader {
            return false;
        }

        let Some(buffer) = self.buffer.as_ref() else {
            return false;
        };

        buffer.lock().can_write()
    }

    pub fn is_err(&self) -> bool {
        let Some(buffer) = self.buffer.as_ref() else {
            return false;
        };

        buffer.lock().error_code != moto_rt::E_OK
    }

    /// Construct a reader pipe.
    ///
    /// # Safety
    ///
    /// pipe_data must be properly set up.
    pub unsafe fn new_reader(pipe_data: RawPipeData) -> Self {
        Self {
            buffer: Some(SpinLock::new(PipeBuffer::new(
                pipe_data.buf_addr,
                pipe_data.buf_size,
                SysHandle::from_u64(pipe_data.ipc_handle),
            ))),
            is_reader: true,
            handle: SysHandle::from_u64(pipe_data.ipc_handle),
        }
    }

    /// Construct a writer pipe.
    ///
    /// # Safety
    ///
    /// pipe_data must be properly set up.
    pub unsafe fn new_writer(pipe_data: RawPipeData) -> Self {
        Self {
            buffer: Some(SpinLock::new(PipeBuffer::new(
                pipe_data.buf_addr,
                pipe_data.buf_size,
                SysHandle::from_u64(pipe_data.ipc_handle),
            ))),
            is_reader: false,
            handle: SysHandle::from_u64(pipe_data.ipc_handle),
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_timeout(buf, None)
    }

    pub fn read_timeout(
        &self,
        buf: &mut [u8],
        timeout: Option<moto_rt::time::Instant>,
    ) -> Result<usize, ErrorCode> {
        if !self.is_reader {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        if let Some(buffer) = self.buffer.as_ref() {
            Self::read_timeout_impl(&mut buffer.lock(), buf, timeout)
        } else {
            Ok(0)
        }
    }

    pub fn nonblocking_read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        let Some(buffer) = self.buffer.as_ref() else {
            return Err(E_INVALID_ARGUMENT);
        };

        let mut buffer = buffer.lock();
        if buffer.error_code != moto_rt::E_OK {
            return Err(buffer.error_code);
        }

        let sz = buffer.read(buf);
        if sz == 0 {
            return Err(moto_rt::E_NOT_READY);
        }

        if let Err(e) = SysCpu::wake(self.handle) {
            // Cache the error.
            buffer.error_code = e;
            return Err(e);
        }

        Ok(sz)
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        self.write_timeout(buf, None)
    }

    pub fn flush_nonblocking(&self) -> Result<(), ErrorCode> {
        if self.is_reader {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let Some(buffer_ref) = self.buffer.as_ref() else {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        };

        let mut buffer = buffer_ref.lock();

        if buffer.error_code != moto_rt::E_OK {
            return Err(buffer.error_code);
        }

        if !buffer.can_read() {
            return Ok(());
        }

        if let Err(e) = SysCpu::wake(self.handle) {
            // Cache the error.
            buffer.error_code = e;
            return Err(e);
        }

        if !buffer.can_read() {
            return Ok(());
        }

        Err(moto_rt::E_NOT_READY)
    }

    pub fn flush(&self) -> Result<(), ErrorCode> {
        if self.is_reader {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let Some(buffer_ref) = self.buffer.as_ref() else {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        };

        let mut buffer = buffer_ref.lock();

        while buffer.can_read() {
            if let Err(err) = SysCpu::wait(
                &mut [buffer.ipc_handle],
                buffer.ipc_handle,
                SysHandle::NONE,
                None,
            ) {
                buffer.error_code = err;
                let _ = buffer.unwrite();
                if !buffer.can_read() {
                    return Ok(());
                } else {
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    pub fn write_timeout(
        &self,
        buf: &[u8],
        timeout: Option<moto_rt::time::Instant>,
    ) -> Result<usize, ErrorCode> {
        if self.is_reader {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        if let Some(buffer) = self.buffer.as_ref() {
            Self::write_timeout_impl(&mut buffer.lock(), buf, timeout)
        } else {
            Ok(0)
        }
    }

    pub fn nonblocking_write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        let Some(buffer) = self.buffer.as_ref() else {
            return Err(E_INVALID_ARGUMENT);
        };

        let mut buffer = buffer.lock();
        if buffer.error_code != moto_rt::E_OK {
            return Err(buffer.error_code);
        }

        let sz = buffer.write(buf);
        if sz == 0 {
            return Err(moto_rt::E_NOT_READY);
        }

        if let Err(e) = SysCpu::wake(self.handle) {
            // Cache the error.
            buffer.error_code = e;
            return Err(e);
        }

        Ok(sz)
    }

    pub fn handle(&self) -> SysHandle {
        self.handle
    }

    pub fn total_read(&self) -> usize {
        if !self.is_reader {
            return 0;
        }

        if let Some(buffer) = self.buffer.as_ref() {
            buffer.lock().reader_counter().load(Ordering::Relaxed)
        } else {
            0
        }
    }

    pub fn total_written(&self) -> usize {
        if self.is_reader {
            return 0;
        }
        if let Some(buffer) = self.buffer.as_ref() {
            buffer.lock().writer_counter().load(Ordering::Relaxed)
        } else {
            0
        }
    }

    fn read_timeout_impl(
        buffer: &mut PipeBuffer,
        buf: &mut [u8],
        timeout: Option<moto_rt::time::Instant>,
    ) -> Result<usize, ErrorCode> {
        buffer.assert_invariants();
        if buf.is_empty() {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        // Even if the remote end is gone (self.buffer.error_code.is_err()),
        // we should complete reading bytes left in the buffer.
        'outer: loop {
            while !buffer.can_read() {
                if buffer.error_code != moto_rt::E_OK {
                    break 'outer;
                }
                if let Err(e) = SysCpu::wait(
                    &mut [buffer.ipc_handle],
                    buffer.ipc_handle,
                    SysHandle::NONE,
                    timeout,
                ) {
                    buffer.error_code = e;
                    break 'outer;
                }
            }
            let read = buffer.read(buf);
            if read > 0 {
                if buffer.error_code != moto_rt::E_OK {
                    return Ok(read);
                }
                if let Err(e) = SysCpu::wake(buffer.ipc_handle) {
                    // Cache the error.
                    buffer.error_code = e;
                }
                return Ok(read);
            }
        }

        // One last read: if the remote process wrote something
        // and then exited, we don't want to lose that.
        let read = buffer.read(buf);
        if read > 0 {
            if buffer.error_code == moto_rt::E_TIMED_OUT {
                buffer.error_code = moto_rt::E_OK;
            }
            return Ok(read);
        }

        if buffer.error_code == moto_rt::E_TIMED_OUT {
            buffer.error_code = moto_rt::E_OK;
            Err(moto_rt::E_TIMED_OUT)
        } else {
            Err(buffer.error_code)
        }
    }

    fn write_timeout_impl(
        buffer: &mut PipeBuffer,
        buf: &[u8],
        timeout: Option<moto_rt::time::Instant>,
    ) -> Result<usize, ErrorCode> {
        if buffer.error_code != moto_rt::E_OK {
            return Err(buffer.error_code);
        }
        buffer.assert_invariants();
        if buf.is_empty() {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut written = 0_usize;

        loop {
            while !buffer.can_write() {
                if let Err(err) = SysCpu::wait(
                    &mut [buffer.ipc_handle],
                    buffer.ipc_handle,
                    SysHandle::NONE,
                    timeout,
                ) {
                    buffer.error_code = err;
                    written = written.saturating_sub(buffer.unwrite());
                    if written > 0 {
                        return Ok(written);
                    } else {
                        return Err(err);
                    }
                }
            }

            written += buffer.write(&buf[written..]);
            if written == buf.len() {
                if let Err(err) = SysCpu::wake(buffer.ipc_handle) {
                    // Cache the error.
                    buffer.error_code = err;
                    written = written.saturating_sub(buffer.unwrite());
                    if written > 0 {
                        return Ok(written);
                    } else {
                        return Err(err);
                    }
                }
                return Ok(written);
            }
        }
    }
}

#[repr(C)]
pub struct RawPipeData {
    pub buf_addr: usize,
    pub buf_size: usize,
    pub ipc_handle: u64,
}

impl RawPipeData {
    /// Release self (memory, handle).
    ///
    /// # Safety
    ///
    /// self must be properly initialized.
    pub unsafe fn release(self, owner_process: SysHandle) {
        moto_sys::SysObj::put_remote(owner_process, SysHandle::from_u64(self.ipc_handle)).unwrap();

        moto_sys::SysMem::unmap(owner_process, 0, u64::MAX, self.buf_addr as u64).unwrap();
    }

    pub fn unsafe_copy(&self) -> Self {
        Self {
            buf_addr: self.buf_addr,
            buf_size: self.buf_size,
            ipc_handle: self.ipc_handle,
        }
    }
}

// Make a simplex pipe. One of the handles must be SysHandle::Self.
pub fn make_pair(
    process_1: SysHandle,
    process_2: SysHandle,
) -> Result<(RawPipeData, RawPipeData), ErrorCode> {
    use moto_sys::syscalls::*;

    let remote_process = if process_1 == SysHandle::SELF {
        process_2
    } else {
        process_1
    };
    let flags = SysMem::F_SHARE_SELF | SysMem::F_READABLE | SysMem::F_WRITABLE;
    let (remote, local) = SysMem::map2(
        remote_process,
        flags,
        u64::MAX,
        u64::MAX,
        sys_mem::PAGE_SIZE_SMALL,
        1,
    )?;

    let (h1, h2) = SysObj::create_ipc_pair(process_1, process_2, 0).inspect_err(|_| {
        SysMem::unmap(remote_process, 0, u64::MAX, remote).unwrap();
        SysMem::unmap(SysHandle::SELF, 0, u64::MAX, local).unwrap();
    })?;

    if process_1 == SysHandle::SELF {
        Ok((
            RawPipeData {
                buf_addr: local as usize,
                buf_size: sys_mem::PAGE_SIZE_SMALL as usize,
                ipc_handle: h1.as_u64(),
            },
            RawPipeData {
                buf_addr: remote as usize,
                buf_size: sys_mem::PAGE_SIZE_SMALL as usize,
                ipc_handle: h2.as_u64(),
            },
        ))
    } else {
        Ok((
            RawPipeData {
                buf_addr: remote as usize,
                buf_size: sys_mem::PAGE_SIZE_SMALL as usize,
                ipc_handle: h1.as_u64(),
            },
            RawPipeData {
                buf_addr: local as usize,
                buf_size: sys_mem::PAGE_SIZE_SMALL as usize,
                ipc_handle: h2.as_u64(),
            },
        ))
    }
}
