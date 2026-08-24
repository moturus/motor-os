//! A simplex pipe used exclusively by rt.vdso for cross-process stdio.
//!
//! The module belongs into rt.vdso, but then it would be difficult to test it,
//! as `cargo test` isn't easy for cross-compiled stuff, and our vdso is an even
//! more exotic target than a normal motor-os binary.
//!
//! DO NOT USE outside of rt.vdso.

use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use moto_rt::spinlock::SpinLock;
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
    const WRITER_CLOSED_OFFSET: usize = Self::VERSION_OFFSET + 8;
    const READER_CLOSING_OFFSET: usize = Self::WRITER_CLOSED_OFFSET + 8;
    const CTRL_C_STATE_OFFSET: usize = Self::READER_CLOSING_OFFSET + 8;
    const CTRL_C_HANDLER_RAISED_OFFSET: usize = Self::CTRL_C_STATE_OFFSET + 8;

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

    /// The counters live on the shared page rather than behind the buffer
    /// lock, so [`Counters`] can read them without taking it.
    fn reader_counter_at(buf_addr: usize) -> &'static AtomicUsize {
        unsafe {
            let addr = buf_addr + Self::READER_COUNTER_OFFSET;
            (addr as *const AtomicUsize).as_ref().unwrap_unchecked()
        }
    }

    fn writer_counter_at(buf_addr: usize) -> &'static AtomicUsize {
        unsafe {
            let addr = buf_addr + Self::WRITER_COUNTER_OFFSET;
            (addr as *const AtomicUsize).as_ref().unwrap_unchecked()
        }
    }

    fn writer_closed_at(buf_addr: usize) -> &'static AtomicUsize {
        unsafe {
            let addr = buf_addr + Self::WRITER_CLOSED_OFFSET;
            (addr as *const AtomicUsize).as_ref().unwrap_unchecked()
        }
    }

    fn reader_closing_at(buf_addr: usize) -> &'static AtomicUsize {
        unsafe {
            let addr = buf_addr + Self::READER_CLOSING_OFFSET;
            (addr as *const AtomicUsize).as_ref().unwrap_unchecked()
        }
    }

    fn ctrl_c_state_at(buf_addr: usize) -> &'static AtomicU64 {
        unsafe {
            let addr = buf_addr + Self::CTRL_C_STATE_OFFSET;
            (addr as *const AtomicU64).as_ref().unwrap_unchecked()
        }
    }

    fn ctrl_c_handler_raised_at(buf_addr: usize) -> &'static AtomicU64 {
        unsafe {
            let addr = buf_addr + Self::CTRL_C_HANDLER_RAISED_OFFSET;
            (addr as *const AtomicU64).as_ref().unwrap_unchecked()
        }
    }

    fn reader_counter(&self) -> &AtomicUsize {
        Self::reader_counter_at(self.buf_addr)
    }

    fn writer_counter(&self) -> &AtomicUsize {
        Self::writer_counter_at(self.buf_addr)
    }

    fn writer_closed(&self) -> bool {
        Self::writer_closed_at(self.buf_addr).load(Ordering::Acquire) != 0
    }

    /// The reader is shutting this pipe down but has not gone yet: it will
    /// still drain what the ring holds, so bytes already published are
    /// delivered and no further ones may be added. Distinct from the reader
    /// being *gone*, which the writer learns from a failing wake and answers
    /// with [`Self::unwrite`] -- retracting undrained bytes is exactly what
    /// must not happen while the reader is still taking them.
    fn reader_closing(&self) -> bool {
        Self::reader_closing_at(self.buf_addr).load(Ordering::SeqCst) != 0
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

    // Assuming the reader is gone, recover and retract its unread bytes.
    fn take_unread(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let writer_counter = self.writer_counter().load(Ordering::SeqCst);
        let reader_counter = self.reader_counter().load(Ordering::SeqCst);
        let unread = writer_counter
            .checked_sub(reader_counter)
            .filter(|unread| *unread <= self.work_buf_len)
            .ok_or(moto_rt::E_INVALID_ARGUMENT)?;

        let mut result = vec![0; unread];
        let reader_offset = reader_counter & (self.work_buf_len - 1);
        let first = unread.min(self.work_buf_len - reader_offset);
        result[..first].copy_from_slice(&self.work_buf[reader_offset..reader_offset + first]);
        result[first..].copy_from_slice(&self.work_buf[..unread - first]);
        self.writer_counter()
            .store(reader_counter, Ordering::SeqCst);
        Ok(result)
    }
}

const CTRL_C_HANDLER: u64 = 1;
const CTRL_C_FORWARD: u64 = 2;
const CTRL_C_FIELD_BITS: u32 = 31;
const CTRL_C_FIELD_MASK: u64 = (1 << CTRL_C_FIELD_BITS) - 1;
const CTRL_C_GENERATION_SHIFT: u32 = 2;
const CTRL_C_COUNT_SHIFT: u32 = CTRL_C_GENERATION_SHIFT + CTRL_C_FIELD_BITS;
const CTRL_C_GENERATION_MASK: u64 = CTRL_C_FIELD_MASK << CTRL_C_GENERATION_SHIFT;
const CTRL_C_COUNT_MASK: u64 = CTRL_C_FIELD_MASK << CTRL_C_COUNT_SHIFT;

const _: () = assert!(PipeBuffer::CTRL_C_STATE_OFFSET == 40);
const _: () = assert!(PipeBuffer::CTRL_C_HANDLER_RAISED_OFFSET == 48);
const _: () = assert!(PipeBuffer::CTRL_C_HANDLER_RAISED_OFFSET + 8 <= PipeBuffer::DATA_OFFSET);
const _: () = assert!(CTRL_C_HANDLER | CTRL_C_FORWARD == 3);
const _: () = assert!(CTRL_C_GENERATION_MASK & CTRL_C_COUNT_MASK == 0);
const _: () = assert!(
    CTRL_C_HANDLER | CTRL_C_FORWARD | CTRL_C_GENERATION_MASK | CTRL_C_COUNT_MASK == u64::MAX
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CtrlCForwardRoute {
    generation: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CtrlCAction {
    Default,
    Handler(u64),
    Forward(CtrlCForwardRoute, u32),
    Dropped,
}

#[derive(Clone, Copy)]
struct CtrlCHeader {
    buf_addr: usize,
}

impl CtrlCHeader {
    fn state(&self) -> &AtomicU64 {
        PipeBuffer::ctrl_c_state_at(self.buf_addr)
    }

    fn handler_raised(&self) -> &AtomicU64 {
        PipeBuffer::ctrl_c_handler_raised_at(self.buf_addr)
    }

    fn register_handler(&self) -> Result<u64, ErrorCode> {
        let baseline = self.handler_raised().load(Ordering::SeqCst);
        let mut state = self.state().load(Ordering::SeqCst);
        loop {
            if state & CTRL_C_HANDLER != 0 {
                return Err(moto_rt::E_ALREADY_IN_USE);
            }
            match self.state().compare_exchange(
                state,
                state | CTRL_C_HANDLER,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(baseline),
                Err(current) => state = current,
            }
        }
    }

    fn install_forward(&self) -> CtrlCForwardRoute {
        let mut state = self.state().load(Ordering::SeqCst);
        loop {
            assert_eq!(state & CTRL_C_FORWARD, 0, "Ctrl+C route already installed");
            let generation = ((state & CTRL_C_GENERATION_MASK) >> CTRL_C_GENERATION_SHIFT)
                .checked_add(1)
                .filter(|value| *value <= CTRL_C_FIELD_MASK)
                .expect("Ctrl+C route generation exhausted");
            let new_state =
                (state & CTRL_C_HANDLER) | CTRL_C_FORWARD | (generation << CTRL_C_GENERATION_SHIFT);
            match self.state().compare_exchange(
                state,
                new_state,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return CtrlCForwardRoute {
                        generation: generation as u32,
                    };
                }
                Err(current) => state = current,
            }
        }
    }

    fn clear_forward(&self, route: CtrlCForwardRoute) -> bool {
        let state = self.state().load(Ordering::SeqCst);
        if state & CTRL_C_FORWARD == 0 || self.generation(state) != route.generation {
            return false;
        }
        self.state()
            .compare_exchange(
                state,
                state & !CTRL_C_FORWARD,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    fn raise(&self) -> CtrlCAction {
        self.raise_from(self.state().load(Ordering::SeqCst))
    }

    fn raise_from(&self, mut state: u64) -> CtrlCAction {
        loop {
            if state & CTRL_C_FORWARD == 0 {
                if state & CTRL_C_HANDLER == 0 {
                    return CtrlCAction::Default;
                }
                let sequence = self
                    .handler_raised()
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                        value.checked_add(1)
                    })
                    .expect("Ctrl+C handler sequence exhausted")
                    + 1;
                return CtrlCAction::Handler(sequence);
            }

            let generation = self.generation(state);
            let count = (state & CTRL_C_COUNT_MASK) >> CTRL_C_COUNT_SHIFT;
            let next = count
                .checked_add(1)
                .filter(|value| *value <= CTRL_C_FIELD_MASK)
                .expect("Ctrl+C forward-event count exhausted");
            let new_state = (state & !CTRL_C_COUNT_MASK) | (next << CTRL_C_COUNT_SHIFT);
            match self.state().compare_exchange(
                state,
                new_state,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return CtrlCAction::Forward(CtrlCForwardRoute { generation }, next as u32);
                }
                Err(current)
                    if current & CTRL_C_FORWARD != 0 && self.generation(current) == generation =>
                {
                    state = current;
                }
                Err(_) => return CtrlCAction::Dropped,
            }
        }
    }

    fn generation(&self, state: u64) -> u32 {
        ((state & CTRL_C_GENERATION_MASK) >> CTRL_C_GENERATION_SHIFT) as u32
    }

    fn forward_count(&self, route: CtrlCForwardRoute) -> Option<u32> {
        let state = self.state().load(Ordering::SeqCst);
        (state & CTRL_C_FORWARD != 0 && self.generation(state) == route.generation)
            .then_some(((state & CTRL_C_COUNT_MASK) >> CTRL_C_COUNT_SHIFT) as u32)
    }
}

/// A pipe's head and tail, read without the buffer lock.
///
/// Readiness is a comparison of two atomics on the shared page and needs no
/// exclusion, while a blocking read holds the buffer lock across a kernel
/// wait — so asking through the lock would spin a CPU for as long as the
/// reader sleeps. A poller asks here instead.
#[derive(Clone, Copy)]
struct Counters {
    buf_addr: usize,
    work_buf_len: usize,
}

impl Counters {
    fn can_read(&self) -> bool {
        PipeBuffer::reader_counter_at(self.buf_addr).load(Ordering::Relaxed)
            < PipeBuffer::writer_counter_at(self.buf_addr).load(Ordering::Relaxed)
    }

    fn can_write(&self) -> bool {
        PipeBuffer::writer_counter_at(self.buf_addr).load(Ordering::Relaxed)
            < PipeBuffer::reader_counter_at(self.buf_addr).load(Ordering::Relaxed)
                + self.work_buf_len
    }

    fn reader_total(&self) -> usize {
        PipeBuffer::reader_counter_at(self.buf_addr).load(Ordering::Acquire)
    }

    fn close_writer(&self) {
        PipeBuffer::writer_closed_at(self.buf_addr).store(1, Ordering::Release);
    }

    fn close_reader(&self) {
        PipeBuffer::reader_closing_at(self.buf_addr).store(1, Ordering::SeqCst);
    }
}

pub struct StdioPipe {
    buffer: Option<SpinLock<PipeBuffer>>,
    counters: Option<Counters>,
    is_reader: bool,
    handle: SysHandle,
}

impl StdioPipe {
    pub const fn new_empty(is_reader: bool) -> Self {
        Self {
            buffer: None,
            counters: None,
            is_reader,
            handle: SysHandle::NONE,
        }
    }

    pub fn is_reader(&self) -> bool {
        self.is_reader
    }

    pub fn can_read(&self) -> bool {
        self.is_reader && self.counters.is_none_or(|counters| counters.can_read())
    }

    pub fn can_write(&self) -> bool {
        !self.is_reader && self.counters.is_none_or(|counters| counters.can_write())
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
            counters: Some(Counters {
                buf_addr: pipe_data.buf_addr,
                work_buf_len: pipe_data.buf_size >> 1,
            }),
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
            counters: Some(Counters {
                buf_addr: pipe_data.buf_addr,
                work_buf_len: pipe_data.buf_size >> 1,
            }),
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
        if !self.is_reader {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let Some(buffer) = self.buffer.as_ref() else {
            return Ok(0);
        };

        let mut buffer = buffer.lock();

        // Read before looking at error_code: bytes the remote left in the buffer
        // are ours to deliver even once it is gone, so an error is reported only
        // after the buffer has been drained. read_timeout_impl() does the same.
        let sz = buffer.read(buf);
        if sz == 0 {
            if buffer.writer_closed() {
                return Ok(0);
            }
            if buffer.error_code != moto_rt::E_OK {
                return Err(buffer.error_code);
            }
            return Err(moto_rt::E_NOT_READY);
        }

        if buffer.error_code == moto_rt::E_OK {
            if let Err(e) = SysCpu::wake(self.handle) {
                // Cache the error: this read succeeded, so the error surfaces on
                // a later call, once there is nothing left to hand out. Returning
                // it now would drop the bytes already copied into the caller's
                // buffer.
                buffer.error_code = e;
            }
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
            return Ok(());
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
            return Ok(());
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
            Ok(buf.len())
        }
    }

    pub fn nonblocking_write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        if self.is_reader {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let Some(buffer) = self.buffer.as_ref() else {
            return Ok(buf.len());
        };

        let mut buffer = buffer.lock();
        if buffer.error_code != moto_rt::E_OK {
            return Err(buffer.error_code);
        }
        if buffer.reader_closing() {
            return Err(moto_rt::E_NOT_CONNECTED);
        }

        let sz = buffer.write(buf);
        if sz == 0 {
            return Err(moto_rt::E_NOT_READY);
        }
        if buffer.reader_closing() {
            return Err(moto_rt::E_NOT_CONNECTED);
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

    fn ctrl_c_header(&self) -> Result<CtrlCHeader, ErrorCode> {
        self.counters
            .map(|counters| CtrlCHeader {
                buf_addr: counters.buf_addr,
            })
            .ok_or(moto_rt::E_INVALID_ARGUMENT)
    }

    pub fn ctrl_c_register_handler(&self) -> Result<u64, ErrorCode> {
        self.ctrl_c_header()?.register_handler()
    }

    pub fn ctrl_c_handler_sequence(&self) -> Result<u64, ErrorCode> {
        Ok(self
            .ctrl_c_header()?
            .handler_raised()
            .load(Ordering::SeqCst))
    }

    pub fn ctrl_c_install_forward(&self) -> Result<CtrlCForwardRoute, ErrorCode> {
        Ok(self.ctrl_c_header()?.install_forward())
    }

    pub fn ctrl_c_clear_forward(&self, route: CtrlCForwardRoute) -> Result<bool, ErrorCode> {
        Ok(self.ctrl_c_header()?.clear_forward(route))
    }

    pub fn ctrl_c_raise(&self) -> Result<CtrlCAction, ErrorCode> {
        Ok(self.ctrl_c_header()?.raise())
    }

    pub fn ctrl_c_forward_count(&self, route: CtrlCForwardRoute) -> Result<Option<u32>, ErrorCode> {
        Ok(self.ctrl_c_header()?.forward_count(route))
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

    /// Return how many bytes the peer has consumed from this writer.
    pub fn peer_bytes_read(&self) -> Result<usize, ErrorCode> {
        if self.is_reader {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        self.counters
            .map(|counters| counters.reader_total())
            .ok_or(moto_rt::E_INVALID_ARGUMENT)
    }

    /// Recover bytes that a departed reader left in this writer's ring.
    pub fn take_unread(&self) -> Result<Vec<u8>, ErrorCode> {
        if self.is_reader {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let Some(buffer) = self.buffer.as_ref() else {
            return Ok(Vec::new());
        };
        buffer.lock().take_unread()
    }

    /// Stop the peer adding bytes, without giving up the ones already in the
    /// ring. A reader draining before it disappears -- a file relay flushing at
    /// process exit -- calls this first, so the drain that follows is bounded
    /// by the ring and cannot be extended by the writer.
    ///
    /// A writer already inside a publish is covered too. The flag and the ring
    /// counters are sequentially consistent, so if the writer's publish lands
    /// after the reader's last drain in that total order, the writer's recheck
    /// afterwards is guaranteed to observe this flag and disown those bytes.
    /// The reader may still have taken them, so the writer can under-report,
    /// never over-report: bytes it was told went through are never dropped.
    pub fn close_reader(&self) -> Result<(), ErrorCode> {
        if !self.is_reader {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let counters = self.counters.ok_or(moto_rt::E_INVALID_ARGUMENT)?;
        counters.close_reader();
        // Wake a writer blocked on a full ring so it observes the bit instead
        // of waiting for space that is about to stop mattering.
        let _ = SysCpu::wake(self.handle);
        Ok(())
    }

    /// Mark a writer-side close as EOF rather than an unexpected peer loss.
    pub fn close_writer(&self) -> Result<(), ErrorCode> {
        if self.is_reader {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let counters = self.counters.ok_or(moto_rt::E_INVALID_ARGUMENT)?;
        counters.close_writer();
        // The bit is authoritative. A wake failure only means the reader is
        // already gone; dropping this endpoint will wake a live reader too.
        let _ = SysCpu::wake(self.handle);
        Ok(())
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
                if buffer.writer_closed() {
                    return Ok(0);
                }
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

        if buffer.writer_closed() {
            return Ok(0);
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
        if buffer.reader_closing() {
            return Err(moto_rt::E_NOT_CONNECTED);
        }
        buffer.assert_invariants();
        if buf.is_empty() {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut written = 0_usize;

        loop {
            while !buffer.can_write() {
                // Do not unwrite here: the reader is still draining, so bytes
                // already in the ring are still on their way to it, and
                // rewinding the write counter under a live reader would race
                // with the counter it is advancing.
                if buffer.reader_closing() {
                    if written > 0 {
                        return Ok(written);
                    }
                    return Err(moto_rt::E_NOT_CONNECTED);
                }
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

            let published = written;
            written += buffer.write(&buf[written..]);
            if buffer.reader_closing() {
                if published > 0 {
                    return Ok(published);
                }
                return Err(moto_rt::E_NOT_CONNECTED);
            }
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

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::boxed::Box;
    use core::mem::ManuallyDrop;

    #[repr(C, align(64))]
    struct TestMapping([u8; 4096]);

    fn test_buffer() -> (Box<TestMapping>, ManuallyDrop<PipeBuffer>) {
        let mapping = Box::new(TestMapping([0; 4096]));
        let buffer = unsafe {
            PipeBuffer::new(
                mapping.0.as_ptr() as usize,
                mapping.0.len(),
                SysHandle::NONE,
            )
        };
        (mapping, ManuallyDrop::new(buffer))
    }

    fn ctrl_c_header(mapping: &TestMapping) -> CtrlCHeader {
        CtrlCHeader {
            buf_addr: mapping.0.as_ptr() as usize,
        }
    }

    #[test]
    fn ctrl_c_default_and_handler_classification() {
        let (mapping, _buffer) = test_buffer();
        let header = ctrl_c_header(&mapping);
        assert_eq!(header.raise(), CtrlCAction::Default);

        assert_eq!(header.register_handler(), Ok(0));
        assert_eq!(header.register_handler(), Err(moto_rt::E_ALREADY_IN_USE));
        assert_eq!(header.raise(), CtrlCAction::Handler(1));
        assert_eq!(header.raise(), CtrlCAction::Handler(2));
        assert_eq!(header.handler_raised().load(Ordering::SeqCst), 2);
    }

    #[test]
    fn ctrl_c_handler_publication_does_not_lose_a_post_registration_event() {
        use std::sync::{Arc, Barrier};

        let (mapping, _buffer) = test_buffer();
        let header = ctrl_c_header(&mapping);
        let barrier = Arc::new(Barrier::new(2));
        let (baseline, action) = std::thread::scope(|scope| {
            let register_barrier = barrier.clone();
            let register = scope.spawn(move || {
                register_barrier.wait();
                header.register_handler().unwrap()
            });
            let raise_barrier = barrier.clone();
            let raise = scope.spawn(move || {
                raise_barrier.wait();
                header.raise()
            });
            (register.join().unwrap(), raise.join().unwrap())
        });

        assert_eq!(baseline, 0);
        assert!(matches!(
            action,
            CtrlCAction::Default | CtrlCAction::Handler(1)
        ));
        if action == CtrlCAction::Handler(1) {
            assert!(header.handler_raised().load(Ordering::SeqCst) > baseline);
        }
    }

    #[test]
    fn ctrl_c_forward_counts_are_generation_scoped() {
        let (mapping, _buffer) = test_buffer();
        let header = ctrl_c_header(&mapping);
        let first = header.install_forward();
        assert_eq!(header.raise(), CtrlCAction::Forward(first, 1));
        assert_eq!(header.raise(), CtrlCAction::Forward(first, 2));
        assert_eq!(header.forward_count(first), Some(2));

        assert_eq!(header.register_handler(), Ok(0));
        assert_eq!(header.raise(), CtrlCAction::Forward(first, 3));
        assert_eq!(header.handler_raised().load(Ordering::SeqCst), 0);
        assert!(header.clear_forward(first));
        assert_eq!(header.raise(), CtrlCAction::Handler(1));
    }

    #[test]
    fn ctrl_c_route_boundary_drops_only_stale_writer_snapshots() {
        let (mapping, _buffer) = test_buffer();
        let header = ctrl_c_header(&mapping);

        let first = header.install_forward();
        let before_teardown = header.state().load(Ordering::SeqCst);
        assert_eq!(
            header.raise_from(before_teardown),
            CtrlCAction::Forward(first, 1)
        );
        assert!(header.clear_forward(first));
        assert_eq!(header.raise_from(before_teardown), CtrlCAction::Dropped);

        let second = header.install_forward();
        assert_ne!(first, second);
        assert_eq!(header.raise_from(before_teardown), CtrlCAction::Dropped);
        assert_eq!(header.forward_count(second), Some(0));
    }

    #[test]
    fn take_unread_returns_only_the_unread_tail() {
        let (_mapping, mut buffer) = test_buffer();
        assert_eq!(buffer.write(b"abcdef"), 6);
        let mut prefix = [0; 2];
        assert_eq!(buffer.read(&mut prefix), 2);
        assert_eq!(&prefix, b"ab");

        assert_eq!(buffer.take_unread().unwrap(), b"cdef");
        assert_eq!(
            buffer.reader_counter().load(Ordering::SeqCst),
            buffer.writer_counter().load(Ordering::SeqCst)
        );
    }

    #[test]
    fn take_unread_rejects_corrupt_counters() {
        let (_mapping, mut buffer) = test_buffer();
        buffer.reader_counter().store(2, Ordering::SeqCst);
        buffer.writer_counter().store(1, Ordering::SeqCst);
        assert_eq!(buffer.take_unread(), Err(moto_rt::E_INVALID_ARGUMENT));

        buffer.reader_counter().store(0, Ordering::SeqCst);
        buffer
            .writer_counter()
            .store(buffer.work_buf_len + 1, Ordering::SeqCst);
        assert_eq!(buffer.take_unread(), Err(moto_rt::E_INVALID_ARGUMENT));
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
    make_pair_with_page_count(process_1, process_2, 1)
}

/// Make a simplex pipe backed by `page_count` shared small pages.
///
/// The ring occupies half the mapping, so `page_count` must be a power of two
/// to preserve the ring's power-of-two indexing.
pub fn make_pair_with_page_count(
    process_1: SysHandle,
    process_2: SysHandle,
    page_count: u64,
) -> Result<(RawPipeData, RawPipeData), ErrorCode> {
    use moto_sys::syscalls::*;

    if page_count == 0 || !page_count.is_power_of_two() {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }
    let buf_size = sys_mem::PAGE_SIZE_SMALL
        .checked_mul(page_count)
        .ok_or(moto_rt::E_INVALID_ARGUMENT)?;

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
        page_count,
    )?;

    let (h1, h2) = SysObj::create_ipc_pair(process_1, process_2, 0).inspect_err(|_| {
        SysMem::unmap(remote_process, 0, u64::MAX, remote).unwrap();
        SysMem::unmap(SysHandle::SELF, 0, u64::MAX, local).unwrap();
    })?;

    if process_1 == SysHandle::SELF {
        Ok((
            RawPipeData {
                buf_addr: local as usize,
                buf_size: buf_size as usize,
                ipc_handle: h1.as_u64(),
            },
            RawPipeData {
                buf_addr: remote as usize,
                buf_size: buf_size as usize,
                ipc_handle: h2.as_u64(),
            },
        ))
    } else {
        Ok((
            RawPipeData {
                buf_addr: remote as usize,
                buf_size: buf_size as usize,
                ipc_handle: h1.as_u64(),
            },
            RawPipeData {
                buf_addr: local as usize,
                buf_size: buf_size as usize,
                ipc_handle: h2.as_u64(),
            },
        ))
    }
}
