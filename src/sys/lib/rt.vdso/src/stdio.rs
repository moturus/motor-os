use crate::{rt_process::ProcessData, rt_process::StdioData, spin::Mutex};
use alloc::{boxed::Box, vec::Vec};
use moto_ipc::sync_pipe::Pipe;
use moto_rt::{ErrorCode, RtFd, E_BAD_HANDLE, E_INVALID_ARGUMENT};
use moto_sys::SysHandle;

#[derive(Debug, PartialEq)]
pub enum StdioKind {
    Stdin,
    Stdout,
    Stderr,
}

impl StdioKind {
    pub fn is_reader(&self) -> bool {
        matches!(self, StdioKind::Stdin)
    }

    pub fn get(&self) -> &'static Stdio {
        let fd = match self {
            Self::Stdin => moto_rt::FD_STDIN,
            Self::Stdout => moto_rt::FD_STDOUT,
            Self::Stderr => moto_rt::FD_STDERR,
        };
        let fd = crate::util::fd::DESCRIPTORS.get(fd).unwrap();

        match fd.as_ref() {
            crate::util::fd::Fd::Stdio(stdio) => unsafe {
                (stdio as *const _ as usize as *const Stdio)
                    .as_ref()
                    .unwrap()
            },

            _ => panic!(),
        }
    }
}
struct StdioImpl {
    kind: StdioKind,
    pipe: Pipe,
    overflow: Vec<u8>,
}

impl StdioImpl {
    fn new(kind: StdioKind) -> Self {
        let proc_data = ProcessData::get();

        let pipe = unsafe {
            let pipe_data = match kind {
                StdioKind::Stdin => &proc_data.stdin,
                StdioKind::Stdout => &proc_data.stdout,
                StdioKind::Stderr => &proc_data.stderr,
            };
            if pipe_data.pipe_addr == 0 {
                Pipe::Null
            } else if kind.is_reader() {
                Pipe::Reader(moto_ipc::sync_pipe::Reader::new(
                    moto_ipc::sync_pipe::RawPipeData {
                        buf_addr: pipe_data.pipe_addr as usize,
                        buf_size: pipe_data.pipe_size as usize,
                        ipc_handle: pipe_data.handle,
                    },
                ))
            } else {
                Pipe::Writer(moto_ipc::sync_pipe::Writer::new(
                    moto_ipc::sync_pipe::RawPipeData {
                        buf_addr: pipe_data.pipe_addr as usize,
                        buf_size: pipe_data.pipe_size as usize,
                        ipc_handle: pipe_data.handle,
                    },
                ))
            }
        };
        Self {
            kind,
            pipe,
            overflow: Vec::new(),
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        if !self.kind.is_reader() {
            return Err(E_INVALID_ARGUMENT);
        }
        let to_copy = buf.len().min(self.overflow.len());
        if to_copy > 0 {
            unsafe {
                core::intrinsics::copy_nonoverlapping(
                    self.overflow.as_ptr(),
                    buf.as_mut_ptr(),
                    to_copy,
                );
            }
            if to_copy < self.overflow.len() {
                let mut remainder = Vec::new();
                remainder.extend_from_slice(&self.overflow.as_slice()[to_copy..]);
                core::mem::swap(&mut self.overflow, &mut remainder);
            } else {
                self.overflow.clear();
            }
            Ok(to_copy)
        } else {
            match self.pipe.read(buf) {
                Ok(n) => {
                    if n == 0 {
                        panic!("zero read")
                    } else {
                        Ok(n)
                    }
                }
                Err(err) => Err(err),
            }
        }
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<usize, ErrorCode> {
        if self.kind.is_reader() {
            return Err(E_INVALID_ARGUMENT);
        }
        let res = self.pipe.write(buf)?;
        // Without the yield below the current thread will continue
        // and the written bytes will be delivered asynchronously.
        // Yielding here makes the user experience better.
        moto_sys::SysCpu::sched_yield();
        Ok(res)
    }

    pub fn flush(&mut self) -> Result<(), ErrorCode> {
        moto_sys::SysCpu::sched_yield();
        Ok(())
    }
}

pub struct Stdio {
    inner: Mutex<StdioImpl>,
}

impl Stdio {
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        self.inner.lock().read(buf)
    }
    pub fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        self.inner.lock().write(buf)
    }
    pub fn flush(&self) -> Result<(), ErrorCode> {
        self.inner.lock().flush()
    }
}

// Returns the handle of the relay thread.
pub fn set_relay(from: moto_rt::RtFd, to: *const u8) -> Result<SysHandle, ErrorCode> {
    use moto_ipc::sync_pipe::RawPipeData;

    let from = match from {
        moto_rt::FD_STDIN => StdioKind::Stdin,
        moto_rt::FD_STDOUT => StdioKind::Stdout,
        moto_rt::FD_STDERR => StdioKind::Stderr,
        _ => panic!("bad stdio FD: {from}"),
    };

    let to: RawPipeData =
        unsafe { (to as usize as *const RawPipeData).as_ref().unwrap() }.unsafe_copy();

    struct RelayArg {
        from: StdioKind,
        to: RawPipeData,
    }
    extern "C" fn relay_thread_fn(thread_arg: u64) {
        let arg = unsafe { Box::from_raw(thread_arg as usize as *mut RelayArg) };
        let RelayArg { from, to } = *arg;

        if from == StdioKind::Stdin {
            // STDIN should not be shared, so we lock it for the whole time the child lives.
            //
            // See also https://devblogs.microsoft.com/oldnewthing/20111202-00/?p=8983.
            let stdin = from.get();
            let mut stdin_lock = stdin.inner.lock();
            let mut dest = unsafe { moto_ipc::sync_pipe::Writer::new(to) };
            let mut buf = [0_u8; 80];

            // We need to break if the child exits, so we wait for the child or for the data,
            // and read with a short timeout.
            let wait_handles = [stdin_lock.pipe.handle(), dest.handle()];
            let mut had_error = false;
            loop {
                let mut handles = wait_handles;
                if moto_sys::SysCpu::wait(&mut handles, SysHandle::NONE, SysHandle::NONE, None)
                    .is_err()
                {
                    if had_error {
                        break;
                    } else {
                        // Don't exit on the first error, as there may be something
                        // in the buffer to process.
                        had_error = true;
                    }
                }

                let timeout = moto_rt::time::Instant::now() + core::time::Duration::new(0, 1_000);
                match stdin_lock.pipe.read_timeout(&mut buf, Some(timeout)) {
                    Ok(sz_read) => {
                        if sz_read > 0 {
                            match dest.write(&buf[0..sz_read]) {
                                Ok(sz_written) => {
                                    moto_sys::SysCpu::sched_yield();
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
                    Err(err) => {
                        if err == moto_rt::E_TIMED_OUT {
                            continue;
                        }
                        break;
                    }
                }
            } // loop
        } else {
            let mut dest = unsafe { moto_ipc::sync_pipe::Reader::new(to) };
            let mut buf = [0_u8; 80];
            while let Ok(sz) = dest.read(&mut buf) {
                if sz > 0 {
                    if from.get().inner.lock().pipe.write(&buf[0..sz]).is_err() {
                        break;
                    }
                    moto_sys::SysCpu::sched_yield();
                }
            }
        }
        let _ = moto_sys::SysObj::put(SysHandle::SELF);
        unreachable!()
    } // relay_thread_fn

    let local_copy = to.unsafe_copy();
    let thread_arg = Box::into_raw(Box::new(RelayArg { from, to })) as usize as u64;

    #[cfg(debug_assertions)]
    const RELAY_THREAD_STACK_SIZE: usize = 1024 * 16;
    #[cfg(not(debug_assertions))]
    const RELAY_THREAD_STACK_SIZE: usize = 1024 * 4;

    moto_sys::SysCpu::spawn(
        SysHandle::SELF,
        RELAY_THREAD_STACK_SIZE as u64,
        relay_thread_fn as usize as u64,
        thread_arg,
    )
    .inspect_err(|_| unsafe {
        drop(Box::from_raw(thread_arg as *mut RelayArg));
        local_copy.release(SysHandle::SELF);
    })
    .map(SysHandle::from)
}

pub fn init() {
    use crate::util::fd::{Fd, DESCRIPTORS};
    use alloc::sync::Arc;

    let stdin_fd = DESCRIPTORS.push(Arc::new(Fd::Stdio(Stdio {
        inner: Mutex::new(StdioImpl::new(StdioKind::Stdin)),
    })));
    assert_eq!(moto_rt::FD_STDIN, stdin_fd);

    let stdout_fd = DESCRIPTORS.push(Arc::new(Fd::Stdio(Stdio {
        inner: Mutex::new(StdioImpl::new(StdioKind::Stdout)),
    })));
    assert_eq!(moto_rt::FD_STDOUT, stdout_fd);

    let stderr_fd = DESCRIPTORS.push(Arc::new(Fd::Stdio(Stdio {
        inner: Mutex::new(StdioImpl::new(StdioKind::Stderr)),
    })));
    assert_eq!(moto_rt::FD_STDERR, stderr_fd);
}

pub fn create_child_stdio(
    remote_process: moto_sys::SysHandle,
    remote_process_data: *mut ProcessData,
    args_rt: &moto_rt::process::SpawnArgsRt,
) -> Result<(RtFd, RtFd, RtFd), ErrorCode> {
    // If command has stdin/out/err, take those, otherwise use default.
    let (stdin, stdin_theirs) =
        create_stdio_pipes(remote_process, args_rt.stdin, moto_rt::FD_STDIN)?;
    let (stdout, stdout_theirs) =
        create_stdio_pipes(remote_process, args_rt.stdout, moto_rt::FD_STDOUT)?;
    let (stderr, stderr_theirs) =
        create_stdio_pipes(remote_process, args_rt.stderr, moto_rt::FD_STDERR)?;

    unsafe {
        let pd = remote_process_data.as_mut().unwrap();
        pd.stdin = stdin_theirs;
        pd.stdout = stdout_theirs;
        pd.stderr = stderr_theirs;
    }

    Ok((stdin, stdout, stderr))
}

fn create_stdio_pipes(
    remote_process: moto_sys::SysHandle,
    stdio: RtFd,
    kind: RtFd,
) -> Result<(RtFd, StdioData), ErrorCode> {
    use crate::util::fd::{Fd, DESCRIPTORS};
    use alloc::sync::Arc;

    fn null_data() -> StdioData {
        StdioData {
            pipe_addr: 0,
            pipe_size: 0,
            handle: 0,
        }
    }
    match stdio {
        moto_rt::process::STDIO_NULL => Ok((moto_rt::process::STDIO_NULL, null_data())),
        moto_rt::process::STDIO_INHERIT => {
            let (local_data, remote_data) =
                moto_ipc::sync_pipe::make_pair(moto_sys::SysHandle::SELF, remote_process)?;

            let pdata = &local_data as *const _ as usize as *const u8;
            let thread = set_relay(kind, pdata).inspect_err(|_| unsafe {
                remote_data.unsafe_copy().release(remote_process);
            })?;

            // These relay threads are "detached" below (we release the handles).
            // TODO: remote shutdowns are now detected via bad remote handle IPCs.
            //       Should we set up a protocol to do it explicitly?
            //       But why? On remote errors/panics we need to handle bad IPCs
            //       anyway.
            moto_sys::SysObj::put(thread).unwrap();

            Ok((
                moto_rt::process::STDIO_NULL,
                StdioData {
                    pipe_addr: remote_data.buf_addr as u64,
                    pipe_size: remote_data.buf_size as u64,
                    handle: remote_data.ipc_handle,
                },
            ))
        }
        moto_rt::process::STDIO_MAKE_PIPE => {
            let (local_data, remote_data) =
                moto_ipc::sync_pipe::make_pair(moto_sys::SysHandle::SELF, remote_process)?;
            if kind == moto_rt::FD_STDIN {
                let pipe = unsafe {
                    moto_ipc::sync_pipe::Pipe::Writer(moto_ipc::sync_pipe::Writer::new(local_data))
                };
                let pipe_fd = DESCRIPTORS.push(Arc::new(Fd::Pipe(Mutex::new(pipe))));
                Ok((
                    pipe_fd,
                    StdioData {
                        pipe_addr: remote_data.buf_addr as u64,
                        pipe_size: remote_data.buf_size as u64,
                        handle: remote_data.ipc_handle,
                    },
                ))
            } else {
                let pipe = unsafe {
                    moto_ipc::sync_pipe::Pipe::Reader(moto_ipc::sync_pipe::Reader::new(local_data))
                };
                let pipe_fd = DESCRIPTORS.push(Arc::new(Fd::Pipe(Mutex::new(pipe))));
                Ok((
                    pipe_fd,
                    StdioData {
                        pipe_addr: remote_data.buf_addr as u64,
                        pipe_size: remote_data.buf_size as u64,
                        handle: remote_data.ipc_handle,
                    },
                ))
            }
        }
        fd => panic!("fd: {fd}"),
    }
}
