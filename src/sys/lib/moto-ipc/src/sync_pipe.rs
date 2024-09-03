use core::sync::atomic::{fence, AtomicUsize, Ordering};

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
        if self.error_code.is_ok() {
            SysCpu::wake(self.ipc_handle).ok();
        }
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
        assert!(is_power_of_two(buf_size));

        assert!(Self::version(buf_addr) == 0);

        let work_buf_len = buf_size >> 1;
        PipeBuffer {
            buf_addr,
            work_buf_len,
            work_buf: core::slice::from_raw_parts_mut(
                (buf_addr + Self::DATA_OFFSET) as *mut u8,
                work_buf_len,
            ),
            error_code: ErrorCode::Ok,
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
            self.reader_counter().load(Ordering::Relaxed)
                <= self.writer_counter().load(Ordering::Relaxed)
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
        let reader_counter = self.reader_counter().load(Ordering::Acquire);
        let writer_counter = self.writer_counter().load(Ordering::Relaxed);

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
            fence(Ordering::Release);
            self.writer_counter().fetch_add(to_write, Ordering::AcqRel);
            return to_write;
        }

        let first_write = self.work_buf_len - writer_offset;
        self.work_buf[writer_offset..self.work_buf_len].copy_from_slice(&src[0..first_write]);

        let second_write = to_write - first_write;
        self.work_buf[0..second_write].copy_from_slice(&src[first_write..to_write]);
        fence(Ordering::Release);

        self.writer_counter().fetch_add(to_write, Ordering::AcqRel);
        to_write
    }

    fn read(&mut self, dst: &mut [u8]) -> usize {
        let writer_counter = self.writer_counter().load(Ordering::Acquire);
        let reader_counter = self.reader_counter().load(Ordering::Relaxed);

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
            self.reader_counter().fetch_add(to_read, Ordering::Release);
            return to_read;
        }

        let first_read = self.work_buf_len - reader_offset;
        (&mut *dst)[0..first_read]
            .copy_from_slice(&self.work_buf[reader_offset..self.work_buf_len]);

        let second_read = to_read - first_read;
        (&mut *dst)[first_read..to_read].copy_from_slice(&self.work_buf[0..second_read]);

        self.reader_counter().fetch_add(to_read, Ordering::Release);
        to_read
    }

    // Assuming the reader is gone, restore the unread bytes.
    fn unwrite(&mut self) -> usize {
        let writer_counter = self.writer_counter().load(Ordering::Acquire);
        let reader_counter = self.reader_counter().load(Ordering::Relaxed);

        if writer_counter == reader_counter {
            return 0;
        }

        self.writer_counter()
            .store(reader_counter, Ordering::Release);

        writer_counter - reader_counter
    }
}

pub struct Reader {
    buffer: PipeBuffer,
}

pub struct Writer {
    buffer: PipeBuffer,
}

const fn is_power_of_two(val: usize) -> bool {
    (val & (val - 1)) == 0
}

impl Reader {
    pub unsafe fn new(pipe_data: RawPipeData) -> Reader {
        Reader {
            buffer: PipeBuffer::new(
                pipe_data.buf_addr,
                pipe_data.buf_size,
                SysHandle::from_u64(pipe_data.ipc_handle),
            ),
        }
    }

    pub fn handle(&self) -> SysHandle {
        self.buffer.ipc_handle
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_timeout(buf, None)
    }

    pub fn read_timeout(
        &mut self,
        buf: &mut [u8],
        timeout: Option<moto_rt::time::Instant>,
    ) -> Result<usize, ErrorCode> {
        self.buffer.assert_invariants();
        if buf.len() == 0 {
            return Err(ErrorCode::InvalidArgument);
        }

        // Even if the remote end is gone (self.buffer.error_code.is_err()),
        // we should complete reading bytes left in the buffer.
        'outer: loop {
            while !self.buffer.can_read() {
                if self.buffer.error_code.is_err() {
                    break 'outer;
                }
                if let Err(e) = SysCpu::wait(
                    &mut [self.buffer.ipc_handle],
                    self.buffer.ipc_handle,
                    SysHandle::NONE,
                    timeout,
                ) {
                    self.buffer.error_code = e;
                    break 'outer;
                }
            }
            let read = self.buffer.read(buf);
            if read > 0 {
                if self.buffer.error_code.is_err() {
                    return Ok(read);
                }
                if let Err(e) = SysCpu::wake(self.buffer.ipc_handle) {
                    // Cache the error.
                    self.buffer.error_code = e;
                }
                return Ok(read);
            }
        }

        // One last read: if the remote process wrote something
        // and then exited, we don't want to lose that.
        let read = self.buffer.read(buf);
        if read > 0 {
            if self.buffer.error_code == ErrorCode::TimedOut {
                self.buffer.error_code = ErrorCode::Ok;
            }
            return Ok(read);
        }

        if self.buffer.error_code == ErrorCode::TimedOut {
            self.buffer.error_code = ErrorCode::Ok;
            Err(ErrorCode::TimedOut)
        } else {
            Err(self.buffer.error_code)
        }
    }

    pub fn total_read(&self) -> usize {
        self.buffer.reader_counter().load(Ordering::Relaxed)
    }
}

impl Writer {
    pub unsafe fn new(pipe_data: RawPipeData) -> Writer {
        Writer {
            buffer: PipeBuffer::new(
                pipe_data.buf_addr,
                pipe_data.buf_size,
                SysHandle::from_u64(pipe_data.ipc_handle),
            ),
        }
    }

    pub fn handle(&self) -> SysHandle {
        self.buffer.ipc_handle
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, ErrorCode> {
        self.write_timeout(buf, None)
    }

    pub fn write_timeout(
        &mut self,
        buf: &[u8],
        timeout: Option<moto_rt::time::Instant>,
    ) -> Result<usize, ErrorCode> {
        if self.buffer.error_code.is_err() {
            return Err(self.buffer.error_code);
        }
        self.buffer.assert_invariants();
        if buf.len() == 0 {
            return Err(ErrorCode::InvalidArgument);
        }

        let mut written = 0_usize;

        loop {
            while !self.buffer.can_write() {
                if let Err(err) = SysCpu::wait(
                    &mut [self.buffer.ipc_handle],
                    self.buffer.ipc_handle,
                    SysHandle::NONE,
                    timeout,
                ) {
                    self.buffer.error_code = err;
                    written = written.checked_sub(self.buffer.unwrite()).unwrap_or(0);
                    if written > 0 {
                        return Ok(written);
                    } else {
                        return Err(err);
                    }
                }
            }

            written += self.buffer.write(&buf[written..]);
            if written == buf.len() {
                if let Err(err) = SysCpu::wake(self.buffer.ipc_handle) {
                    // Cache the error.
                    self.buffer.error_code = err;
                    written = written.checked_sub(self.buffer.unwrite()).unwrap_or(0);
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

    pub fn total_written(&self) -> usize {
        self.buffer.writer_counter().load(Ordering::Relaxed)
    }
}

pub enum Pipe {
    Reader(Reader),
    Writer(Writer),
    Empty,
    Null,
}

impl Pipe {
    pub const fn new() -> Self {
        Self::Empty
    }

    pub const fn empty(&self) -> bool {
        match self {
            Self::Empty => true,
            _ => false,
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        self.read_timeout(buf, None)
    }

    pub fn read_timeout(
        &mut self,
        buf: &mut [u8],
        timeout: Option<moto_rt::time::Instant>,
    ) -> Result<usize, ErrorCode> {
        match self {
            Self::Reader(reader) => reader.read_timeout(buf, timeout),
            Self::Null => Ok(0),
            _ => Err(ErrorCode::InvalidArgument),
        }
    }

    pub fn read_to_end(&mut self, buf: &mut alloc::vec::Vec<u8>) -> Result<usize, ErrorCode> {
        let mut temp_vec = alloc::vec::Vec::new();
        let mut size = 0_usize;
        loop {
            temp_vec.resize(256, 0_u8);
            if let Ok(sz) = self.read(&mut temp_vec[..]) {
                if sz == 0 {
                    return Ok(size);
                }
                size += sz;
                temp_vec.truncate(sz);
                buf.append(&mut temp_vec);
            } else {
                if size != 0 {
                    return Ok(size);
                } else {
                    return Err(ErrorCode::InvalidArgument);
                }
            }
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, ErrorCode> {
        self.write_timeout(buf, None)
    }

    pub fn write_timeout(
        &mut self,
        buf: &[u8],
        timeout: Option<moto_rt::time::Instant>,
    ) -> Result<usize, ErrorCode> {
        match self {
            Self::Writer(writer) => writer.write_timeout(buf, timeout),
            Self::Null => Ok(0),
            _ => Err(ErrorCode::InvalidArgument),
        }
    }

    pub fn handle(&self) -> SysHandle {
        match self {
            Self::Reader(reader) => reader.buffer.ipc_handle,
            Self::Writer(writer) => writer.buffer.ipc_handle,
            _ => SysHandle::NONE,
        }
    }
}

pub struct RawPipeData {
    pub buf_addr: usize,
    pub buf_size: usize,
    pub ipc_handle: u64,
}

impl RawPipeData {
    // Release self (memory, handle).
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

    let (h1, h2) = SysObj::create_ipc_pair(process_1, process_2, 0).map_err(|err| {
        SysMem::unmap(remote_process, 0, u64::MAX, remote).unwrap();

        SysMem::unmap(SysHandle::SELF, 0, u64::MAX, local).unwrap();

        err
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
