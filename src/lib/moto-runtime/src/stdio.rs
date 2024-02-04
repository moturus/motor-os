use crate::mutex::Mutex;
use crate::sync_pipe::Pipe;
use crate::ErrorCode;
use crate::SysHandle;
use alloc::boxed::Box;
use alloc::vec::Vec;

pub struct StdinRt {}
pub struct StdoutRt {}
pub struct StderrRt {}

#[derive(Debug, PartialEq)]
pub enum StdioKind {
    Stdin,
    Stdout,
    Stderr,
}

impl StdioKind {
    pub fn is_reader(&self) -> bool {
        match self {
            StdioKind::Stdin => true,
            _ => false,
        }
    }
}

struct StdioImpl {
    kind: StdioKind,
    pipe: *mut Pipe,
}

unsafe impl Send for StdioImpl {}
unsafe impl Sync for StdioImpl {}

impl StdioImpl {
    const fn new(kind: StdioKind) -> Self {
        Self {
            kind,
            pipe: core::ptr::null_mut(),
        }
    }

    fn pipe(&mut self) -> &mut Pipe {
        self.ensure_init();
        unsafe { self.pipe.as_mut().unwrap_unchecked() }
    }

    fn ensure_init(&mut self) {
        if !self.pipe.is_null() {
            return;
        }

        let proc_data = match unsafe { crate::rt_api::process::ProcessData::get() } {
            Some(pd) => pd,
            None => return self.pipe = Box::leak(Box::new(Pipe::Null)),
        };

        unsafe {
            self.pipe = {
                let pipe_data = match self.kind {
                    StdioKind::Stdin => &proc_data.stdin,
                    StdioKind::Stdout => &proc_data.stdout,
                    StdioKind::Stderr => &proc_data.stderr,
                };
                if pipe_data.pipe_addr == 0 {
                    Box::leak(Box::new(Pipe::Null))
                } else {
                    if self.kind.is_reader() {
                        // Static stdio (STDIN below), never dropped.
                        Box::leak(Box::new(Pipe::Reader(crate::sync_pipe::Reader::new(
                            crate::sync_pipe::RawPipeData {
                                buf_addr: pipe_data.pipe_addr as usize,
                                buf_size: pipe_data.pipe_size as usize,
                                ipc_handle: pipe_data.handle,
                            },
                        ))))
                    } else {
                        // Static stdio (STDOUT/STDERR below), never dropped.
                        Box::leak(Box::new(Pipe::Writer(crate::sync_pipe::Writer::new(
                            crate::sync_pipe::RawPipeData {
                                buf_addr: pipe_data.pipe_addr as usize,
                                buf_size: pipe_data.pipe_size as usize,
                                ipc_handle: pipe_data.handle,
                            },
                        ))))
                    }
                }
            };
        }
    }
}

struct StdinImpl {
    stdio: StdioImpl,
    overflow: Vec<u8>,
}

impl StdinImpl {
    const fn new() -> Self {
        Self {
            stdio: StdioImpl::new(StdioKind::Stdin),
            overflow: Vec::new(),
        }
    }
}

static STDIN: Mutex<StdinImpl> = Mutex::new(StdinImpl::new());
static STDOUT: Mutex<StdioImpl> = Mutex::new(StdioImpl::new(StdioKind::Stdout));
static STDERR: Mutex<StdioImpl> = Mutex::new(StdioImpl::new(StdioKind::Stderr));

impl StdinRt {
    pub const fn new() -> Self {
        Self {}
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        let mut stdin_lock = STDIN.lock();
        let to_copy = buf.len().min(stdin_lock.overflow.len());
        if to_copy > 0 {
            unsafe {
                core::intrinsics::copy_nonoverlapping(
                    stdin_lock.overflow.as_ptr(),
                    buf.as_mut_ptr(),
                    to_copy,
                );
            }
            if to_copy < stdin_lock.overflow.len() {
                let mut remainder = Vec::new();
                remainder.extend_from_slice(&stdin_lock.overflow.as_slice()[to_copy..]);
                core::mem::swap(&mut stdin_lock.overflow, &mut remainder);
            } else {
                stdin_lock.overflow.clear();
            }
            Ok(to_copy)
        } else {
            stdin_lock.stdio.pipe().read(buf)
        }
    }
}

impl StdoutRt {
    pub const fn new() -> Self {
        Self {}
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, ErrorCode> {
        let res = STDOUT.lock().pipe().write(buf)?;
        // Without the yield below the current thread will continue
        // and the written bytes will be delivered asynchronously.
        // Yielding here makes the user experience better.
        moto_sys::syscalls::SysCpu::sched_yield();
        Ok(res)
    }

    pub fn flush(&mut self) -> Result<(), ErrorCode> {
        moto_sys::syscalls::SysCpu::sched_yield();
        Ok(())
    }
}

impl StderrRt {
    pub const fn new() -> Self {
        Self {}
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, ErrorCode> {
        let res = STDERR.lock().pipe().write(buf)?;
        // Without the yield below the current thread will continue
        // and the written bytes will be delivered asynchronously.
        // Yielding here makes the user experience better.
        moto_sys::syscalls::SysCpu::sched_yield();
        Ok(res)
    }

    pub fn flush(&mut self) -> Result<(), ErrorCode> {
        moto_sys::syscalls::SysCpu::sched_yield();
        Ok(())
    }
}

impl core::fmt::Write for StderrRt {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        self.write(s.as_bytes())
            .map(|_| ())
            .map_err(|_| core::fmt::Error {})
    }
}

// Returns the handle of the relay thread.
pub(super) fn set_relay(
    from: StdioKind,
    to: crate::sync_pipe::RawPipeData,
) -> Result<SysHandle, ErrorCode> {
    struct RelayArg {
        from: StdioKind,
        to: crate::sync_pipe::RawPipeData,
    }
    extern "C" fn relay_thread_fn(thread_arg: usize) {
        let arg = unsafe { Box::from_raw(thread_arg as *mut RelayArg) };
        let RelayArg { from, to } = *arg;

        if from == StdioKind::Stdin {
            // STDIN should not be shared, so we lock it for the whole time the child lives.
            //
            // See also https://devblogs.microsoft.com/oldnewthing/20111202-00/?p=8983.
            let mut stdin_lock = STDIN.lock();
            let mut dest = unsafe { crate::sync_pipe::Writer::new(to) };
            let mut buf = [0_u8; 80];
            loop {
                match stdin_lock.stdio.pipe().read(&mut buf) {
                    Ok(sz_read) => {
                        if sz_read > 0 {
                            match dest.write(&buf[0..sz_read]) {
                                Ok(sz_written) => {
                                    moto_sys::syscalls::SysCpu::sched_yield();
                                    if sz_written == sz_read {
                                        continue;
                                    } else {
                                        stdin_lock
                                            .overflow
                                            .extend_from_slice(&buf[sz_written..sz_read]);
                                        break;
                                    }
                                }
                                Err(_) => {
                                    stdin_lock.overflow.extend_from_slice(&buf[0..sz_read]);
                                    break;
                                }
                            }
                        } else {
                            break;
                        }
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        } else {
            let mut dest = unsafe { crate::sync_pipe::Reader::new(to) };
            let mut buf = [0_u8; 80];
            loop {
                match dest.read(&mut buf) {
                    Ok(sz) => {
                        if sz > 0 {
                            match from {
                                StdioKind::Stdout => {
                                    if STDOUT.lock().pipe().write(&buf[0..sz]).is_err() {
                                        break;
                                    }
                                    moto_sys::syscalls::SysCpu::sched_yield();
                                }
                                StdioKind::Stderr => {
                                    if STDERR.lock().pipe().write(&buf[0..sz]).is_err() {
                                        break;
                                    }
                                    moto_sys::syscalls::SysCpu::sched_yield();
                                }
                                _ => panic!(),
                            }
                        } else {
                            break;
                        }
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        }

        super::tls::thread_exiting();
        let _ = moto_sys::syscalls::SysCtl::put(SysHandle::SELF);
    }

    let local_copy = to.unsafe_copy();
    let thread_arg = Box::into_raw(Box::new(RelayArg { from, to })) as usize;

    super::thread::spawn(1024 * 64, relay_thread_fn as usize, thread_arg).map_err(|err| {
        unsafe {
            drop(Box::from_raw(thread_arg as *mut RelayArg));
            local_copy.release(SysHandle::SELF);
        }

        err
    })
}
