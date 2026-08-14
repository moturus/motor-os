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

#[derive(Clone, Copy, Debug, PartialEq)]
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
    pipe: Arc<StdioPipe>,
    overflow: Vec<u8>,
}

/// This process's end of one of its three stdio pipes, and whether the
/// spawner marked that stream a terminal endpoint.
fn open_pipe(kind: StdioKind, data: &StdioData) -> Result<(StdioPipe, bool, bool), ErrorCode> {
    let Some((pipe_addr, pipe_size, handle, terminal)) = data.pipe_data()? else {
        if data.is_null() {
            return Ok((StdioPipe::new_empty(kind.is_reader()), false, true));
        }
        return Err(moto_rt::E_INVALID_ARGUMENT);
    };
    let raw = moto_ipc::stdio_pipe::RawPipeData {
        buf_addr: pipe_addr as usize,
        buf_size: pipe_size as usize,
        ipc_handle: handle,
    };
    let pipe = if kind.is_reader() {
        unsafe { StdioPipe::new_reader(raw) }
    } else {
        unsafe { StdioPipe::new_writer(raw) }
    };
    Ok((pipe, terminal, false))
}

impl StdioImpl {
    fn new(kind: StdioKind, pipe: Arc<StdioPipe>) -> Self {
        Self {
            kind,
            pipe,
            overflow: Vec::new(),
        }
    }

    pub fn read(&mut self, buf: &mut [u8], nonblocking: bool) -> Result<usize, ErrorCode> {
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
        } else if nonblocking {
            self.pipe.nonblocking_read(buf)
        } else {
            match self.pipe.read(buf) {
                Ok(n) => Ok(n),
                Err(err) => Err(err),
            }
        }
    }

    pub fn write(&mut self, buf: &[u8], nonblocking: bool) -> Result<usize, ErrorCode> {
        if self.kind.is_reader() {
            return Err(E_INVALID_ARGUMENT);
        }
        let res = if nonblocking {
            self.pipe.nonblocking_write(buf)?
        } else {
            self.pipe.write(buf)?
        };
        // Without the yield below the current thread will continue
        // and the written bytes will be delivered asynchronously.
        // Yielding here makes the user experience better.
        moto_sys::SysCpu::sched_yield();
        Ok(res)
    }

    pub fn flush(&mut self, nonblocking: bool) -> Result<(), ErrorCode> {
        // Writers only: a non-blocking flush is `E_NOT_READY` until the reader
        // has taken everything, which is the answer a non-blocking writer
        // wants and an error the reader side does not have.
        if nonblocking && !self.kind.is_reader() {
            return self.pipe.flush_nonblocking();
        }
        moto_sys::SysCpu::sched_yield();
        Ok(())
    }
}

struct SelfStdio {
    kind: StdioKind,
    /// Shared with [`StdioImpl`], and the reason readiness needs no claim:
    /// `can_read`/`can_write` are counters on the shared page, so a poller
    /// can ask while a user thread sleeps inside a blocking read.
    pipe: Arc<StdioPipe>,
    // None while a stdin relay task owns the reader (design 7.2).
    inner: SpinLock<Option<StdioImpl>>,
    /// Set while a relay owns stdin: those bytes are the child's, not ours.
    relayed: AtomicBool,
    /// Bytes a relay handed back, readable though the pipe itself is empty.
    stashed: AtomicUsize,
    nonblocking: AtomicBool,
    /// Whether the spawner declared this stream a terminal endpoint.
    /// Immutable for the life of the process: nothing after startup — in
    /// particular no environment mutation — can change it.
    terminal: bool,
    /// Whether this endpoint was created from `STDIO_NULL`.
    null: bool,
    event_source: Arc<super::runtime::EventSourceUnmanaged>,
}

impl SelfStdio {
    fn new(kind: StdioKind, data: &StdioData) -> Result<Arc<Self>, ErrorCode> {
        let (pipe, terminal, null) = open_pipe(kind, data)?;
        let pipe = Arc::new(pipe);
        let wait_handle = pipe.handle();
        let for_impl = pipe.clone();
        // Both interests on all three, as `ChildStdio` does: mio registers
        // read and write together, and `check_interests` is what reports
        // only the one a given pipe can ever have.
        let supported = moto_rt::poll::POLL_READABLE | moto_rt::poll::POLL_WRITABLE;

        Ok(Arc::new_cyclic(|me| Self {
            kind,
            pipe,
            inner: SpinLock::new(Some(StdioImpl::new(kind, for_impl))),
            relayed: AtomicBool::new(false),
            stashed: AtomicUsize::new(0),
            nonblocking: AtomicBool::new(false),
            terminal,
            null,
            event_source: super::runtime::EventSourceUnmanaged::new(
                wait_handle,
                me.clone() as _,
                supported,
            ),
        }))
    }

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

    /// Whether a read would return now: what a relay handed back, or what the
    /// pipe holds — and nothing while a relay owns the reader, because until
    /// it gives the claim back those bytes belong to the child.
    fn readable(&self) -> bool {
        !self.relayed.load(Ordering::Acquire)
            && (self.stashed.load(Ordering::Relaxed) > 0 || self.pipe.can_read())
    }
}

impl super::runtime::UnmanagedEventSourceHolder for SelfStdio {
    fn check_interests(&self, interests: Interests) -> moto_rt::poll::EventBits {
        if self.event_source.is_closed() {
            return 0;
        }
        let mut events = 0;

        if (interests & moto_rt::poll::POLL_READABLE != 0) && self.readable() {
            events |= moto_rt::poll::POLL_READABLE;
        }

        if (interests & moto_rt::poll::POLL_WRITABLE != 0) && self.pipe.can_write() {
            events |= moto_rt::poll::POLL_WRITABLE;
        }

        events
    }

    fn on_handle_error(&self) {
        self.event_source.on_closed_remotely(true);
    }
}

impl PosixFile for SelfStdio {
    fn kind(&self) -> PosixKind {
        PosixKind::SelfStdio
    }
    fn descriptor_attr(
        &self,
        object_id: core::num::NonZeroU64,
    ) -> Result<moto_rt::fs::FileAttr, ErrorCode> {
        let file_type = if self.terminal || self.null {
            moto_rt::fs::FILETYPE_CHARACTER_DEVICE
        } else {
            moto_rt::fs::FILETYPE_FIFO
        };
        Ok(posix::synthetic_attr(file_type, object_id))
    }
    fn is_terminal(&self) -> bool {
        self.terminal
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        let nonblocking = self.nonblocking.load(Ordering::Acquire);
        let (result, stashed) = self.with_impl(|inner| {
            let result = inner.read(buf, nonblocking);
            (result, inner.overflow.len())
        });
        self.stashed.store(stashed, Ordering::Relaxed);
        // A registry reports an interest once and then holds it reported, so
        // what this read consumed has to be un-reported for the next arrival
        // to be an edge again.
        self.event_source
            .rearm_interest(moto_rt::poll::POLL_READABLE);
        result
    }
    fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        let nonblocking = self.nonblocking.load(Ordering::Acquire);
        let result = self.with_impl(|inner| inner.write(buf, nonblocking));
        self.event_source
            .rearm_interest(moto_rt::poll::POLL_WRITABLE);
        result
    }
    fn flush(&self) -> Result<(), ErrorCode> {
        let nonblocking = self.nonblocking.load(Ordering::Acquire);
        self.with_impl(|inner| inner.flush(nonblocking))
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

/// A relay between this process's stdio and an inherited-stdio child's pipe.
/// It is prepared with the other child streams, then started only after every
/// stream has been created and one completion group can cover them all.
struct InheritedRelayTask {
    from: StdioKind,
    to: moto_ipc::stdio_pipe::RawPipeData,
}

fn prepare_inherited_relay(from: moto_rt::RtFd, to: *const u8) -> InheritedRelayTask {
    use moto_ipc::stdio_pipe::RawPipeData;

    let from = match from {
        moto_rt::FD_STDIN => StdioKind::Stdin,
        moto_rt::FD_STDOUT => StdioKind::Stdout,
        moto_rt::FD_STDERR => StdioKind::Stderr,
        _ => panic!("bad stdio FD: {from}"),
    };

    let to: RawPipeData =
        unsafe { (to as usize as *const RawPipeData).as_ref().unwrap() }.unsafe_copy();

    InheritedRelayTask { from, to }
}

impl InheritedRelayTask {
    fn spawn(self, group: Arc<crate::stdio_relay::CompletionGroup>) {
        let stdio = self.from.get();
        crate::stdio_relay::spawn(move || async move {
            if self.from == StdioKind::Stdin {
                relay_in(stdio, self.to).await;
            } else {
                // Safety: the pair was made for this process; see make_pair().
                let dest = unsafe { StdioPipe::new_reader(self.to) };
                relay_out(stdio, dest).await;
            }
            group.complete_one();
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
            // A poller of this process's own stdin must not be told those
            // bytes are its to read; they are the child's until the claim
            // comes back.
            stdio.relayed.store(true, Ordering::Release);
            stdio
                .event_source
                .reset_interest(moto_rt::poll::POLL_READABLE);
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

    // Return the reader (and any stash) to the parent. A stash arrives with
    // no handle edge behind it, so readiness is reported here rather than
    // waited for.
    stdio.stashed.store(owned.overflow.len(), Ordering::Relaxed);
    *stdio.inner.lock() = Some(owned);
    stdio.relayed.store(false, Ordering::Release);
    stdio.event_source.check_interests_all();
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

// Relay throughput is set by how much each filesystem request carries, so it
// scales with the ring until the requests are large enough to stop mattering.
// Measured on a 64 MiB transfer through inherited file stdout, against a
// 376 MiB/s direct route and a ~500 MiB/s plain sequential write:
//
//      4 pages ( 8 KiB ring)  175 MiB/s
//      8 pages (16 KiB ring)  285 MiB/s
//     16 pages (32 KiB ring)  416 MiB/s
//     32 pages (64 KiB ring)  524 MiB/s
//
// 32 pages is where the relay stops being the bottleneck: it passes the direct
// route and reaches the plain-write ceiling, so a larger ring would buy
// nothing. It costs 192 KiB per file relay -- 128 KiB of shared pages plus the
// 64 KiB reusable buffer below -- and only a child that inherits file-backed
// stdio has one at all. Peak process memory is unchanged by the
// ring size -- it stays payload-independent, which is the property that
// matters; the shell pump this replaces peaked at +203 MiB for the same
// 64 MiB.
const FILE_RELAY_PIPE_PAGES: u64 = 32;
const FILE_RELAY_BUFFER_SIZE: usize =
    (moto_sys::sys_mem::PAGE_SIZE_SMALL * FILE_RELAY_PIPE_PAGES) as usize / 2;

/// What ended a wait for the relay's peer.
enum PeerWait {
    /// The peer signalled; there may be work.
    Signalled,
    /// The peer is gone; drain and finish.
    Gone,
    /// This process is exiting; close the pipe and finish.
    Exiting,
}

/// Park until the peer signals or this process starts exiting.
///
/// A relay waits on its *peer's* handle, which only the peer can signal, so
/// exit cannot reach it that way; the shutdown signal is the second arm.
async fn wait_for_peer(
    pipe: &StdioPipe,
    shutdown: &mut moto_async::oneshot::Receiver<()>,
) -> PeerWait {
    use futures::future::Either;
    use moto_async::AsFuture;

    if crate::stdio_relay::shutting_down() {
        return PeerWait::Exiting;
    }
    match futures::future::select(pipe.handle().as_future(), &mut *shutdown).await {
        Either::Left((result, _)) if result.is_err() => PeerWait::Gone,
        Either::Left(_) => PeerWait::Signalled,
        Either::Right(_) => PeerWait::Exiting,
    }
}

async fn relay_file_output(
    claim: &FileRelayClaim,
    pipe: StdioPipe,
    mut shutdown: moto_async::oneshot::Receiver<()>,
) -> Result<(), ErrorCode> {
    let result = transfer_file_output(claim, &pipe, &mut shutdown).await;
    claim.source.file().cancel_output_relay();
    // Before `pipe` drops and its handle goes back to the kernel, so process
    // exit can never wake a number that has since been handed to something
    // else.
    crate::stdio_relay::unregister_file_relay(pipe.handle());
    result
}

async fn transfer_file_output(
    claim: &FileRelayClaim,
    pipe: &StdioPipe,
    shutdown: &mut moto_async::oneshot::Receiver<()>,
) -> Result<(), ErrorCode> {
    let mut buf = alloc::vec![0; FILE_RELAY_BUFFER_SIZE];
    // Set once no further bytes can arrive -- the child died, or this process
    // is exiting and told it to stop. Either way: drain the ring, then finish.
    let mut input_closed = false;
    loop {
        match pipe.nonblocking_read(&mut buf) {
            // The writer end announced EOF: there is nothing left to drain and
            // no reason to reserve an empty range and ask again.
            Ok(0) => return Ok(()),
            Ok(read) => {
                let start = claim.source.file().reserve_output_relay_range(read)?;
                let mut written = 0;
                while written < read {
                    let offset = start
                        .checked_add(written as u64)
                        .ok_or(moto_rt::E_INVALID_ARGUMENT)?;
                    let (returned, result) = claim
                        .source
                        .client
                        .write_owned(claim.source.file().entry_id(), offset, buf, written..read)
                        .await;
                    buf = returned;
                    match result {
                        Ok(0) => return Err(moto_rt::E_UNEXPECTED_EOF),
                        Ok(count) => written += count,
                        Err(err) => return Err(err as ErrorCode),
                    }
                }
            }
            Err(moto_rt::E_NOT_READY) if !input_closed => {
                match wait_for_peer(pipe, shutdown).await {
                    PeerWait::Signalled => {}
                    PeerWait::Gone => input_closed = true,
                    PeerWait::Exiting => {
                        // Stop the child adding bytes first: after this the
                        // ring is all there can be, so the flush below is
                        // bounded by its size, not by the child's lifetime.
                        let _ = pipe.close_reader();
                        input_closed = true;
                    }
                }
            }
            Err(moto_rt::E_NOT_READY) => return Ok(()),
            Err(_) => return Ok(()),
        }
    }
}

async fn relay_file_input(
    claim: &FileRelayClaim,
    pipe: StdioPipe,
    mut shutdown: moto_async::oneshot::Receiver<()>,
) -> Result<(), ErrorCode> {
    let FileRelayKind::Input { start } = claim.kind else {
        unreachable!();
    };
    let transfer = transfer_file_input(claim, &pipe, start, &mut shutdown).await;
    crate::stdio_relay::unregister_file_relay(pipe.handle());
    let finish = match pipe.peer_bytes_read() {
        Ok(consumed) => claim.source.file().finish_input_relay(start, consumed),
        Err(err) => {
            claim.source.file().cancel_input_relay();
            Err(err)
        }
    };
    transfer.and(finish)
}

async fn transfer_file_input(
    claim: &FileRelayClaim,
    pipe: &StdioPipe,
    start: u64,
    shutdown: &mut moto_async::oneshot::Receiver<()>,
) -> Result<(), ErrorCode> {
    let mut buf = alloc::vec![0; FILE_RELAY_BUFFER_SIZE];
    let mut offset = start;
    loop {
        // Nothing is headed for the filesystem in this direction, so exit does
        // not flush: it hands the child a clean end of input instead of the
        // peer loss it would see once this process is gone.
        if crate::stdio_relay::shutting_down() {
            return pipe.close_writer();
        }
        let (returned, result) = claim
            .source
            .client
            .read_owned(claim.source.file().entry_id(), offset, buf)
            .await;
        buf = returned;
        let read = match result {
            Ok(read) => read,
            Err(err) => {
                // Bytes from earlier successful reads are already the child's;
                // let it take them before the pipe closes, exactly as at EOF.
                // The pipe protocol cannot carry the error itself, so the
                // writer is dropped rather than closed: the child's next read
                // fails instead of reporting a clean end of input.
                wait_for_input_drain(pipe, shutdown).await?;
                return Err(err as ErrorCode);
            }
        };
        if read == 0 {
            wait_for_input_drain(pipe, shutdown).await?;
            return pipe.close_writer();
        }
        offset = offset
            .checked_add(read as u64)
            .ok_or(moto_rt::E_INVALID_ARGUMENT)?;

        let mut sent = 0;
        while sent < read {
            match pipe.nonblocking_write(&buf[sent..read]) {
                Ok(written) => sent += written,
                Err(moto_rt::E_NOT_READY) => match wait_for_peer(pipe, shutdown).await {
                    PeerWait::Signalled => {}
                    PeerWait::Gone => return Ok(()),
                    PeerWait::Exiting => return pipe.close_writer(),
                },
                Err(_) => return Ok(()),
            }
        }
    }
}

async fn wait_for_input_drain(
    pipe: &StdioPipe,
    shutdown: &mut moto_async::oneshot::Receiver<()>,
) -> Result<(), ErrorCode> {
    loop {
        match pipe.flush_nonblocking() {
            Ok(()) => return Ok(()),
            Err(moto_rt::E_NOT_READY) => match wait_for_peer(pipe, shutdown).await {
                PeerWait::Signalled => {}
                // Exit does not wait for a child to finish reading its stdin:
                // nothing here is headed for the filesystem.
                PeerWait::Gone | PeerWait::Exiting => return Ok(()),
            },
            Err(_) => return Ok(()),
        }
    }
}

pub fn init() {
    use posix::PosixFile;

    let process_data = ProcessData::get();
    let streams = [
        (StdioKind::Stdin, &process_data.stdin),
        (StdioKind::Stdout, &process_data.stdout),
        (StdioKind::Stderr, &process_data.stderr),
    ];
    let mut self_stdio = [None, None, None];
    let mut files: Vec<(u64, Arc<crate::rt_fs::File>)> = Vec::new();

    for (idx, (kind, data)) in streams.into_iter().enumerate() {
        let descriptor: Arc<dyn PosixFile> = if let Some(snapshot) = data
            .file_data()
            .expect("invalid file-backed stdio bootstrap data")
        {
            if let Some((_, file)) = files
                .iter()
                .find(|(parent_open_id, _)| *parent_open_id == snapshot.parent_open_id)
            {
                file.clone()
            } else {
                let file = Arc::new(crate::rt_fs::File::from_stdio_snapshot(snapshot));
                files.push((snapshot.parent_open_id, file.clone()));
                file
            }
        } else {
            let stdio =
                SelfStdio::new(kind, data).expect("invalid pipe-backed stdio bootstrap data");
            self_stdio[idx] = Some(stdio.clone());
            stdio
        };
        assert_eq!(idx as RtFd, posix::push_file(descriptor));
    }
    *SELF_STDIO.lock() = self_stdio;
}

#[derive(Clone)]
struct FileRelaySource {
    descriptor: Arc<dyn PosixFile>,
    open_id: u64,
    client: &'static crate::rt_fs::AsyncFsClient,
}

impl FileRelaySource {
    fn file(&self) -> &crate::rt_fs::File {
        (self.descriptor.as_ref() as &dyn Any)
            .downcast_ref::<crate::rt_fs::File>()
            .unwrap()
    }
}

enum PreparedStdio {
    Null,
    Inherit(RtFd),
    MakePipe,
    File(crate::rt_process::StdioFileData),
    Relay(FileRelaySource),
}

pub(crate) struct PreparedChildStdio {
    stdin: PreparedStdio,
    stdout: PreparedStdio,
    stderr: PreparedStdio,
    file_relays: RegisteredFileRelays,
}

pub(crate) fn prepare_child_stdio(
    args_rt: &moto_rt::process::SpawnArgsRt,
) -> Result<PreparedChildStdio, ErrorCode> {
    let mut snapshots = Vec::new();
    let stdin = prepare_stdio_value(args_rt.stdin, StdioKind::Stdin, &mut snapshots)?;
    let stdout = prepare_stdio_value(args_rt.stdout, StdioKind::Stdout, &mut snapshots)?;
    let stderr = prepare_stdio_value(args_rt.stderr, StdioKind::Stderr, &mut snapshots)?;
    let mut prepared = PreparedChildStdio {
        stdin,
        stdout,
        stderr,
        file_relays: RegisteredFileRelays::new_empty(),
    };
    validate_stdio_aliases(&prepared)?;
    prepared.file_relays = RegisteredFileRelays::new(&prepared)?;
    Ok(prepared)
}

fn prepare_stdio_value(
    stdio: RtFd,
    destination: StdioKind,
    snapshots: &mut Vec<(u64, crate::rt_process::StdioFileData)>,
) -> Result<PreparedStdio, ErrorCode> {
    match stdio {
        moto_rt::process::STDIO_NULL => Ok(PreparedStdio::Null),
        moto_rt::process::STDIO_MAKE_PIPE => Ok(PreparedStdio::MakePipe),
        moto_rt::process::STDIO_INHERIT => prepare_inherited_stdio(destination.fd(), destination),
        moto_rt::process::STDIO_PARENT_STDIN => {
            prepare_inherited_stdio(moto_rt::FD_STDIN, destination)
        }
        moto_rt::process::STDIO_PARENT_STDOUT => {
            prepare_inherited_stdio(moto_rt::FD_STDOUT, destination)
        }
        moto_rt::process::STDIO_PARENT_STDERR => {
            prepare_inherited_stdio(moto_rt::FD_STDERR, destination)
        }
        fd if fd >= 0 => {
            let Some(source) = posix::get_file(fd) else {
                return Err(moto_rt::E_BAD_HANDLE);
            };
            let Some(file) = (source.as_ref() as &dyn Any).downcast_ref::<crate::rt_fs::File>()
            else {
                return Err(moto_rt::E_NOT_IMPLEMENTED);
            };
            let parent_open_id = file.parent_open_id();
            let snapshot = if let Some((_, snapshot)) = snapshots
                .iter()
                .find(|(open_id, _)| *open_id == parent_open_id)
            {
                *snapshot
            } else {
                let snapshot = file.stdio_snapshot()?;
                snapshots.push((parent_open_id, snapshot));
                snapshot
            };
            Ok(PreparedStdio::File(snapshot))
        }
        _ => Err(moto_rt::E_INVALID_ARGUMENT),
    }
}

impl StdioKind {
    fn fd(self) -> RtFd {
        match self {
            Self::Stdin => moto_rt::FD_STDIN,
            Self::Stdout => moto_rt::FD_STDOUT,
            Self::Stderr => moto_rt::FD_STDERR,
        }
    }

    fn of_fd(fd: RtFd) -> Option<Self> {
        match fd {
            moto_rt::FD_STDIN => Some(Self::Stdin),
            moto_rt::FD_STDOUT => Some(Self::Stdout),
            moto_rt::FD_STDERR => Some(Self::Stderr),
            _ => None,
        }
    }
}

fn prepare_inherited_stdio(
    source_fd: RtFd,
    destination: StdioKind,
) -> Result<PreparedStdio, ErrorCode> {
    let Some(source) = posix::get_file(source_fd) else {
        return Err(moto_rt::E_BAD_HANDLE);
    };
    if (source_fd == moto_rt::FD_STDIN) != destination.is_reader() {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }
    match source.kind() {
        PosixKind::File => {
            let file = (source.as_ref() as &dyn Any)
                .downcast_ref::<crate::rt_fs::File>()
                .ok_or(moto_rt::E_BAD_HANDLE)?;
            if (destination.is_reader() && !file.readable())
                || (!destination.is_reader() && !file.writable())
            {
                return Err(moto_rt::E_NOT_ALLOWED);
            }
            let client =
                crate::rt_fs::AsyncFsClient::get().map_err(|err| err as moto_rt::ErrorCode)?;
            Ok(PreparedStdio::Relay(FileRelaySource {
                open_id: file.parent_open_id(),
                descriptor: source,
                client,
            }))
        }
        PosixKind::SelfStdio => {
            let self_stdio = (source.as_ref() as &dyn Any)
                .downcast_ref::<SelfStdio>()
                .ok_or(moto_rt::E_BAD_HANDLE)?;
            // The only `SelfStdio`s that exist are the three built by init(),
            // so a matching kind proves this descriptor is the canonical one
            // for `source_fd` -- which is what the inherited relay will resolve. A
            // different stream duplicated onto a canonical fd would silently
            // relay the wrong one, so it is rejected rather than guessed at.
            if StdioKind::of_fd(source_fd) != Some(self_stdio.kind) {
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }
            if self_stdio.pipe.handle() == moto_sys::SysHandle::NONE {
                Ok(PreparedStdio::Null)
            } else {
                Ok(PreparedStdio::Inherit(source_fd))
            }
        }
        _ => Err(moto_rt::E_NOT_IMPLEMENTED),
    }
}

fn validate_stdio_aliases(stdio: &PreparedChildStdio) -> Result<(), ErrorCode> {
    let streams = [&stdio.stdin, &stdio.stdout, &stdio.stderr];
    for left in 0..streams.len() {
        for right in (left + 1)..streams.len() {
            let left_id = match streams[left] {
                PreparedStdio::File(file) => Some((file.parent_open_id, false)),
                PreparedStdio::Relay(source) => Some((source.open_id, true)),
                _ => None,
            };
            let right_id = match streams[right] {
                PreparedStdio::File(file) => Some((file.parent_open_id, false)),
                PreparedStdio::Relay(source) => Some((source.open_id, true)),
                _ => None,
            };
            let (Some((left_id, left_relay)), Some((right_id, right_relay))) = (left_id, right_id)
            else {
                continue;
            };
            if left_id != right_id {
                continue;
            }
            if left_relay != right_relay {
                // One open description cannot be both an independent transfer
                // and a shared offset authority.
                return Err(moto_rt::E_NOT_IMPLEMENTED);
            }
            if left_relay && (left == 0 || right == 0) {
                // An input relay excludes every other relay on its open
                // description, in the same spawn as across spawns.
                return Err(moto_rt::E_ALREADY_IN_USE);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum FileRelayKind {
    Input { start: u64 },
    Output,
}

#[derive(Clone)]
struct FileRelayClaim {
    source: FileRelaySource,
    kind: FileRelayKind,
}

struct RegisteredFileRelays {
    claims: [Option<FileRelayClaim>; 3],
    committed: bool,
}

impl RegisteredFileRelays {
    fn new_empty() -> Self {
        Self {
            claims: core::array::from_fn(|_| None),
            committed: false,
        }
    }

    fn new(stdio: &PreparedChildStdio) -> Result<Self, ErrorCode> {
        let streams = [&stdio.stdin, &stdio.stdout, &stdio.stderr];
        let mut registered = Self::new_empty();
        for (idx, stream) in streams.into_iter().enumerate() {
            let PreparedStdio::Relay(source) = stream else {
                continue;
            };
            let kind = if idx == 0 {
                FileRelayKind::Input {
                    start: source.file().register_input_relay()?,
                }
            } else {
                source.file().register_output_relay()?;
                FileRelayKind::Output
            };
            registered.claims[idx] = Some(FileRelayClaim {
                source: source.clone(),
                kind,
            });
        }
        Ok(registered)
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for RegisteredFileRelays {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for claim in self.claims.iter().flatten() {
            match claim.kind {
                FileRelayKind::Input { .. } => claim.source.file().cancel_input_relay(),
                FileRelayKind::Output => claim.source.file().cancel_output_relay(),
            }
        }
    }
}

enum FileRelayTask {
    Input {
        claim: FileRelayClaim,
        pipe: StdioPipe,
    },
    Output {
        claim: FileRelayClaim,
        pipe: StdioPipe,
    },
}

impl FileRelayTask {
    fn spawn(self, group: Arc<crate::stdio_relay::CompletionGroup>) {
        let (Self::Input { pipe, .. } | Self::Output { pipe, .. }) = &self;
        let shutdown = crate::stdio_relay::register_file_relay(pipe.handle());
        crate::stdio_relay::spawn(move || async move {
            let result = match self {
                Self::Input { claim, pipe } => relay_file_input(&claim, pipe, shutdown).await,
                Self::Output { claim, pipe } => relay_file_output(&claim, pipe, shutdown).await,
            };
            if let Err(err) = result {
                log::warn!("child file-stdio relay failed: {err}");
            }
            group.complete_one();
        });
    }
}

pub fn create_child_stdio(
    remote_process: moto_sys::SysHandle,
    remote_process_data: *mut ProcessData,
    stdio: &mut PreparedChildStdio,
    terminal_hint: bool,
) -> Result<(RtFd, RtFd, RtFd), ErrorCode> {
    let relay_claims = stdio.file_relays.claims.clone();
    let mut file_tasks = Vec::new();
    let mut inherited_tasks = Vec::new();
    // The caller-side heuristic in old `moto-rt` copies embedded in
    // already-built toolchains synthesizes the terminal hint whenever stdin
    // and stdout are both inherited, terminal or not. Inherited streams
    // derive their answer from the parent's descriptors instead, so for
    // that shape the hint carries no information and is dropped; a real
    // terminal provider (sys-tty, russhd, rmux) creates all three of its
    // child's streams explicitly.
    let terminal_hint = terminal_hint
        && !(matches!(stdio.stdin, PreparedStdio::Inherit(_))
            && matches!(stdio.stdout, PreparedStdio::Inherit(_)));

    // If command has stdin/out/err, take those, otherwise use default.
    let (stdin, stdin_theirs) = create_stdio_pipes(
        remote_process,
        &stdio.stdin,
        relay_claims[0].as_ref(),
        moto_rt::FD_STDIN,
        terminal_hint,
        &mut file_tasks,
        &mut inherited_tasks,
    )?;
    let (stdout, stdout_theirs) = create_stdio_pipes(
        remote_process,
        &stdio.stdout,
        relay_claims[1].as_ref(),
        moto_rt::FD_STDOUT,
        terminal_hint,
        &mut file_tasks,
        &mut inherited_tasks,
    )?;
    let (stderr, stderr_theirs) = create_stdio_pipes(
        remote_process,
        &stdio.stderr,
        relay_claims[2].as_ref(),
        moto_rt::FD_STDERR,
        terminal_hint,
        &mut file_tasks,
        &mut inherited_tasks,
    )?;

    unsafe {
        let pd = remote_process_data.as_mut().unwrap();
        pd.stdin = stdin_theirs;
        pd.stdout = stdout_theirs;
        pd.stderr = stderr_theirs;
    }

    let pending = file_tasks.len() + inherited_tasks.len();
    if pending != 0 {
        let group = crate::stdio_relay::install_completion_group(remote_process.as_u64(), pending);
        if !file_tasks.is_empty() {
            stdio.file_relays.commit();
        }
        for task in file_tasks {
            task.spawn(group.clone());
        }
        for task in inherited_tasks {
            task.spawn(group.clone());
        }
    }

    Ok((stdin, stdout, stderr))
}

fn create_stdio_pipes(
    remote_process: moto_sys::SysHandle,
    stdio: &PreparedStdio,
    relay_claim: Option<&FileRelayClaim>,
    kind: RtFd,
    terminal_hint: bool,
    file_tasks: &mut Vec<FileRelayTask>,
    inherited_tasks: &mut Vec<InheritedRelayTask>,
) -> Result<(RtFd, StdioData), ErrorCode> {
    use crate::posix::PosixFile;
    use alloc::sync::Arc;

    match stdio {
        PreparedStdio::Null => Ok((moto_rt::process::STDIO_NULL, StdioData::null())),
        PreparedStdio::File(snapshot) => {
            Ok((moto_rt::process::STDIO_NULL, StdioData::file(*snapshot)))
        }
        PreparedStdio::Relay(_) => {
            let claim = relay_claim.cloned().unwrap();
            let (local_data, remote_data) = moto_ipc::stdio_pipe::make_pair_with_page_count(
                moto_sys::SysHandle::SELF,
                remote_process,
                FILE_RELAY_PIPE_PAGES,
            )?;
            let task = if kind == moto_rt::FD_STDIN {
                FileRelayTask::Input {
                    claim,
                    pipe: unsafe { StdioPipe::new_writer(local_data) },
                }
            } else {
                FileRelayTask::Output {
                    claim,
                    pipe: unsafe { StdioPipe::new_reader(local_data) },
                }
            };
            file_tasks.push(task);
            Ok((
                moto_rt::process::STDIO_NULL,
                StdioData::pipe(
                    remote_data.buf_addr as u64,
                    remote_data.buf_size as u64,
                    remote_data.ipc_handle,
                    false,
                ),
            ))
        }
        PreparedStdio::Inherit(source) => {
            let (local_data, remote_data) =
                moto_ipc::stdio_pipe::make_pair(moto_sys::SysHandle::SELF, remote_process)?;

            let pdata = &local_data as *const _ as usize as *const u8;
            // TODO: remote shutdowns are now detected via bad remote handle IPCs.
            //       Should we set up a protocol to do it explicitly?
            //       But why? On remote errors/panics we need to handle bad IPCs
            //       anyway.
            inherited_tasks.push(prepare_inherited_relay(*source, pdata));

            // An inherited stream is a terminal iff this process's matching
            // stream is one: the relay extends the same endpoint to the child.
            let terminal = posix::get_file(*source).is_some_and(|file| file.is_terminal());

            Ok((
                moto_rt::process::STDIO_NULL,
                StdioData::pipe(
                    remote_data.buf_addr as u64,
                    remote_data.buf_size as u64,
                    remote_data.ipc_handle,
                    terminal,
                ),
            ))
        }
        PreparedStdio::MakePipe => {
            let (local_data, remote_data) =
                moto_ipc::stdio_pipe::make_pair(moto_sys::SysHandle::SELF, remote_process)?;
            // A captured stream is a pipe to this process, which is a
            // terminal for the child only if this process said it will act
            // as one. The parent-side `ChildStdio` below stays non-terminal
            // either way: it is the provider's end of the connection.
            if kind == moto_rt::FD_STDIN {
                let pipe = unsafe { StdioPipe::new_writer(local_data) };
                let pipe_fd = posix::push_file(ChildStdio::from_inner(pipe));
                Ok((
                    pipe_fd,
                    StdioData::pipe(
                        remote_data.buf_addr as u64,
                        remote_data.buf_size as u64,
                        remote_data.ipc_handle,
                        terminal_hint,
                    ),
                ))
            } else {
                let pipe = unsafe { StdioPipe::new_reader(local_data) };
                let pipe_fd = posix::push_file(ChildStdio::from_inner(pipe));
                Ok((
                    pipe_fd,
                    StdioData::pipe(
                        remote_data.buf_addr as u64,
                        remote_data.buf_size as u64,
                        remote_data.ipc_handle,
                        terminal_hint,
                    ),
                ))
            }
        }
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

    fn descriptor_attr(
        &self,
        object_id: core::num::NonZeroU64,
    ) -> Result<moto_rt::fs::FileAttr, ErrorCode> {
        Ok(posix::synthetic_attr(moto_rt::fs::FILETYPE_FIFO, object_id))
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
            // The pipe ran dry, so un-report readable -- and look again,
            // because a write may have landed since this read looked
            // (`EventSourceUnmanaged::rearm_interest`).
            self.inner.nonblocking_read(buf).inspect_err(|_| {
                self.event_source
                    .rearm_interest(moto_rt::poll::POLL_READABLE);
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
                    .rearm_interest(moto_rt::poll::POLL_WRITABLE);
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
