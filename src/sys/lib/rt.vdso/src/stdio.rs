use crate::posix::PosixFile;
use crate::posix::{self, PosixKind};
use crate::{rt_process::ProcessData, rt_process::StdioData};
use alloc::sync::Arc;
use alloc::{boxed::Box, vec::Vec};
use core::any::Any;
use core::sync::atomic::*;
use moto_ipc::stdio_pipe::StdioPipe;
use moto_rt::poll::Interests;
use moto_rt::poll::Token;
use moto_rt::spinlock::SpinLock;
use moto_rt::{E_BAD_HANDLE, E_INVALID_ARGUMENT, ErrorCode, RtFd};
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

    fn get(&self) -> Arc<SelfStdio> {
        let idx = match self {
            Self::Stdin => 0,
            Self::Stdout => 1,
            Self::Stderr => 2,
        };
        SELF_STDIO.lock()[idx].as_ref().unwrap().clone()
    }
}

// The process's own stdin/out/err, set in init(). Also in the FD
// table; this direct reference is for the relay tasks.
static SELF_STDIO: SpinLock<[Option<Arc<SelfStdio>>; 3]> = SpinLock::new([None, None, None]);
struct StdioImpl {
    kind: StdioKind,
    pipe: StdioPipe,
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
                StdioPipe::new_empty()
            } else if kind.is_reader() {
                StdioPipe::new_reader(moto_ipc::stdio_pipe::RawPipeData {
                    buf_addr: pipe_data.pipe_addr as usize,
                    buf_size: pipe_data.pipe_size as usize,
                    ipc_handle: pipe_data.handle,
                })
            } else {
                StdioPipe::new_writer(moto_ipc::stdio_pipe::RawPipeData {
                    buf_addr: pipe_data.pipe_addr as usize,
                    buf_size: pipe_data.pipe_size as usize,
                    ipc_handle: pipe_data.handle,
                })
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
                core::ptr::copy_nonoverlapping(self.overflow.as_ptr(), buf.as_mut_ptr(), to_copy);
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

struct SelfStdio {
    // None while a stdin relay task owns the reader (design 7.2).
    inner: SpinLock<Option<StdioImpl>>,
}

impl SelfStdio {
    fn with_impl<R>(&self, f: impl FnOnce(&mut StdioImpl) -> R) -> R {
        // Claim the impl instead of running `f` under the lock: `f`
        // may block in the kernel for as long as it likes (a stdin
        // read waiting for input), and anyone touching the lock
        // meanwhile would spin through that entire wait.
        let mut owned = loop {
            if let Some(owned) = self.inner.lock().take() {
                break owned;
            }
            // Claimed by a stdin relay for a child's lifetime, or by
            // a concurrent op on this fd; block as before.
            moto_sys::SysCpu::sched_yield();
        };
        let result = f(&mut owned);
        *self.inner.lock() = Some(owned);
        result
    }
}

impl PosixFile for SelfStdio {
    fn kind(&self) -> PosixKind {
        PosixKind::SelfStdio
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        self.with_impl(|inner| inner.read(buf))
    }
    fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        self.with_impl(|inner| inner.write(buf))
    }
    fn flush(&self) -> Result<(), ErrorCode> {
        self.with_impl(|inner| inner.flush())
    }
    fn close(&self, _rt_fd: RtFd) -> Result<(), ErrorCode> {
        todo!()
    }
}

// Sets up relaying between this process's stdio and an inherited-stdio
// child's pipe.
pub fn set_relay(from: moto_rt::RtFd, to: *const u8) {
    use moto_ipc::stdio_pipe::RawPipeData;

    let from = match from {
        moto_rt::FD_STDIN => StdioKind::Stdin,
        moto_rt::FD_STDOUT => StdioKind::Stdout,
        moto_rt::FD_STDERR => StdioKind::Stderr,
        _ => panic!("bad stdio FD: {from}"),
    };

    let to: RawPipeData =
        unsafe { (to as usize as *const RawPipeData).as_ref().unwrap() }.unsafe_copy();

    let stdio = from.get();
    if from == StdioKind::Stdin {
        crate::stdio_relay::spawn(move || relay_in(stdio, to));
    } else {
        crate::stdio_relay::spawn(move || async move {
            // Safety: the pair was made for this process; see make_pair().
            let dest = unsafe { StdioPipe::new_reader(to) };
            relay_out(stdio, dest).await;
        });
    }
}

/// Relays this process's stdin into an inherited-stdio child, as a
/// task on the relay runtime. Owns the stdin reader for the child's
/// lifetime; bytes the child did not consume return to the parent's
/// stream via the overflow stash.
async fn relay_in(stdio: Arc<SelfStdio>, to: moto_ipc::stdio_pipe::RawPipeData) {
    use futures::future::Either;
    use moto_async::AsFuture;

    // Safety: the pair was made for this process; see make_pair().
    let dest = unsafe { StdioPipe::new_writer(to) };

    // Only one child may consume stdin at a time; relays used to
    // serialize on the stdio spinlock, now on the claim itself. The
    // parent may sit in a blocking read holding the claim for the
    // child's whole lifetime (tokio-tests does), so also watch for
    // child death: an unserved child must not pin this task forever.
    let mut owned = loop {
        if let Some(owned) = stdio.inner.lock().take() {
            break owned;
        }
        let nap = core::pin::pin!(moto_async::sleep(core::time::Duration::from_millis(1)));
        if let Either::Right((result, _)) =
            futures::future::select(nap, dest.handle().as_future()).await
            && result.is_err()
        {
            return;
        }
    };

    let mut buf = [0_u8; 80];
    'relay: loop {
        match owned.pipe.nonblocking_read(&mut buf) {
            Ok(sz) if sz > 0 => {
                let mut chunk = &buf[..sz];
                while !chunk.is_empty() {
                    match dest.nonblocking_write(chunk) {
                        Ok(written) => {
                            chunk = &chunk[written..];
                            moto_sys::SysCpu::sched_yield();
                        }
                        Err(moto_rt::E_NOT_READY) => {
                            if dest.handle().as_future().await.is_err() {
                                owned.overflow.extend_from_slice(chunk);
                                break 'relay;
                            }
                        }
                        Err(_) => {
                            owned.overflow.extend_from_slice(chunk);
                            break 'relay;
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(moto_rt::E_NOT_READY) => {
                // Wait for parent stdin data or for the child to go
                // away; a spurious child-side signal just re-loops.
                let stdin_ready = owned.pipe.handle().as_future();
                let dest_alive = dest.handle().as_future();
                match futures::future::select(stdin_ready, dest_alive).await {
                    Either::Left((result, _)) => {
                        if result.is_err() {
                            break 'relay;
                        }
                    }
                    Either::Right((result, _)) => {
                        if result.is_err() {
                            break 'relay;
                        }
                    }
                }
            }
            Err(_) => break 'relay,
        }
    }

    // Return the reader (and any stash) to the parent.
    *stdio.inner.lock() = Some(owned);
}

/// Relays an inherited-stdio child's stdout/stderr into this process's
/// own, as a task on the relay runtime. Exits when either pipe dies,
/// draining what the child wrote first.
async fn relay_out(stdio: Arc<SelfStdio>, dest: StdioPipe) {
    use moto_async::AsFuture;

    let mut buf = [0_u8; 80];
    let mut dest_dead = false;
    loop {
        match dest.nonblocking_read(&mut buf) {
            Ok(sz) => {
                if sz > 0 && !relay_write(&stdio, &buf[..sz]).await {
                    return;
                }
            }
            Err(moto_rt::E_NOT_READY) => {
                if dest_dead {
                    return;
                }
                dest_dead = dest.handle().as_future().await.is_err();
            }
            Err(_) => return,
        }
    }
}

/// Writes all of `buf` into this process's own stdio pipe, awaiting
/// pipe room. Returns false if the pipe is gone.
async fn relay_write(stdio: &SelfStdio, mut buf: &[u8]) -> bool {
    use moto_async::AsFuture;

    // Claim per write instead of using with_impl: a user thread may
    // hold the claim across a blocking write, and this runtime must
    // sleep through that wait, not spin through it.
    while !buf.is_empty() {
        let mut owned = loop {
            if let Some(owned) = stdio.inner.lock().take() {
                break owned;
            }
            moto_async::sleep(core::time::Duration::from_millis(1)).await;
        };
        let result = owned.pipe.nonblocking_write(buf);
        let handle = owned.pipe.handle();
        *stdio.inner.lock() = Some(owned);
        match result {
            Ok(written) => {
                buf = &buf[written..];
                // Give the consumer a chance to run now, as the thread
                // relays did.
                moto_sys::SysCpu::sched_yield();
            }
            Err(moto_rt::E_NOT_READY) => {
                if handle.as_future().await.is_err() {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

pub fn init() {
    use alloc::sync::Arc;
    use posix::PosixFile;

    let stdin = Arc::new(SelfStdio {
        inner: SpinLock::new(Some(StdioImpl::new(StdioKind::Stdin))),
    });
    let stdout = Arc::new(SelfStdio {
        inner: SpinLock::new(Some(StdioImpl::new(StdioKind::Stdout))),
    });
    let stderr = Arc::new(SelfStdio {
        inner: SpinLock::new(Some(StdioImpl::new(StdioKind::Stderr))),
    });
    *SELF_STDIO.lock() = [
        Some(stdin.clone()),
        Some(stdout.clone()),
        Some(stderr.clone()),
    ];

    assert_eq!(moto_rt::FD_STDIN, posix::push_file(stdin));
    assert_eq!(moto_rt::FD_STDOUT, posix::push_file(stdout));
    assert_eq!(moto_rt::FD_STDERR, posix::push_file(stderr));
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
    use crate::posix::PosixFile;
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
                moto_ipc::stdio_pipe::make_pair(moto_sys::SysHandle::SELF, remote_process)?;

            let pdata = &local_data as *const _ as usize as *const u8;
            // TODO: remote shutdowns are now detected via bad remote handle IPCs.
            //       Should we set up a protocol to do it explicitly?
            //       But why? On remote errors/panics we need to handle bad IPCs
            //       anyway.
            set_relay(kind, pdata);

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
                moto_ipc::stdio_pipe::make_pair(moto_sys::SysHandle::SELF, remote_process)?;
            if kind == moto_rt::FD_STDIN {
                let pipe = unsafe { StdioPipe::new_writer(local_data) };
                let pipe_fd = posix::push_file(ChildStdio::from_inner(pipe));
                Ok((
                    pipe_fd,
                    StdioData {
                        pipe_addr: remote_data.buf_addr as u64,
                        pipe_size: remote_data.buf_size as u64,
                        handle: remote_data.ipc_handle,
                    },
                ))
            } else {
                let pipe = unsafe { StdioPipe::new_reader(local_data) };
                let pipe_fd = posix::push_file(ChildStdio::from_inner(pipe));
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

struct ChildStdio {
    inner: StdioPipe,
    nonblocking: AtomicBool,
    event_source: Arc<super::runtime::EventSourceUnmanaged>,
}

impl ChildStdio {
    fn from_inner(inner: StdioPipe) -> Arc<Self> {
        let wait_handle = inner.handle();
        // Tokio uses both readable and writable by default.
        // We can probably hack it so that it sends only relevant
        // interests, but why complicate things?
        let supported_interests = moto_rt::poll::POLL_READABLE | moto_rt::poll::POLL_WRITABLE;

        Arc::new_cyclic(|me| Self {
            inner,
            nonblocking: AtomicBool::new(false),
            event_source: super::runtime::EventSourceUnmanaged::new(
                wait_handle,
                me.clone() as _,
                supported_interests,
            ),
        })
    }
}

impl super::runtime::UnmanagedEventSourceHolder for ChildStdio {
    fn check_interests(&self, interests: Interests) -> moto_rt::poll::EventBits {
        if self.event_source.is_closed() {
            return 0;
        }
        let mut events = 0;

        if (interests & moto_rt::poll::POLL_READABLE != 0) && self.inner.can_read() {
            events |= moto_rt::poll::POLL_READABLE;
        }

        if (interests & moto_rt::poll::POLL_WRITABLE != 0) && self.inner.can_write() {
            events |= moto_rt::poll::POLL_WRITABLE;
        }

        events
    }

    fn on_handle_error(&self) {
        self.event_source.on_closed_remotely(true);
    }
}

impl PosixFile for ChildStdio {
    fn kind(&self) -> PosixKind {
        PosixKind::ChildStdio
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        if self.event_source.is_closed() {
            // The peer is gone; deliver what remains in the ring
            // before reporting EOF, or a fast-exiting child's final
            // output is lost.
            return match self.inner.nonblocking_read(buf) {
                Ok(sz) => Ok(sz),
                Err(_) => Ok(0),
            };
        }
        let res = if self.nonblocking.load(Ordering::Acquire) {
            self.inner.nonblocking_read(buf).inspect_err(|_| {
                self.event_source
                    .reset_interest(moto_rt::poll::POLL_READABLE);
            })
        } else {
            self.inner.read(buf)
        };
        match res {
            // The remote end is gone (remote shutdowns are signalled via
            // bad-remote-handle IPC errors): report EOF, not an error.
            Err(moto_rt::E_BAD_HANDLE) => Ok(0),
            other => other,
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        if self.event_source.is_closed() {
            // return Ok(0);
            return Err(moto_rt::E_BAD_HANDLE);
        }
        if self.nonblocking.load(Ordering::Acquire) {
            self.inner.nonblocking_write(buf).inspect_err(|_| {
                self.event_source
                    .reset_interest(moto_rt::poll::POLL_WRITABLE);
            })
        } else {
            self.inner.write(buf)
        }
    }

    fn flush(&self) -> Result<(), ErrorCode> {
        if self.nonblocking.load(Ordering::Acquire) {
            self.inner.flush_nonblocking()
        } else {
            self.inner.flush()
        }
    }

    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        self.event_source.on_closed_locally(rt_fd);
        Ok(())
    }

    fn set_nonblocking(&self, val: bool) -> Result<(), ErrorCode> {
        self.nonblocking.store(val, Ordering::Release);
        Ok(())
    }

    fn poll_add(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.event_source
            .add_interests(r_id, source_fd, token, interests)
    }

    fn poll_set(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.event_source
            .set_interests(r_id, source_fd, token, interests)
    }

    fn poll_del(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        self.event_source.del_interests(r_id, source_fd)
    }
}
