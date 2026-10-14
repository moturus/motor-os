//! sys-io's half of the executable pager: drains the kernel's queue of page
//! requests and retirements, reads requested pages through the block cache,
//! and installs them. Each live mapping holds one executable-lock reference,
//! released when the kernel retires the mapping.

use super::elf;
use super::{ExecLocks, SpawnStats, native, read_range};
use crate::runtime::fs::FsRuntime;
use async_fs::{EntryId, Role};
use moto_async::AsFuture;
use moto_sys::{SysHandle, SysMem};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

const PAGE: u64 = elf::PAGE;
/// The largest adaptive read window, in pages.
const MAX_WINDOW: u64 = 32;
/// Fills in flight at once; with `MAX_WINDOW` this bounds their page
/// buffers to 4 MiB.
const MAX_SERVES: usize = 32;

pub(crate) struct Mapping {
    entry: EntryId,
    role: Role,
    segment: elf::Segment,
    /// Adaptive window: doubles while faults continue where the last
    /// window ended, and drops back to one page otherwise.
    next: Cell<u64>,
    window: Cell<u64>,
}

impl Mapping {
    pub fn new(entry: EntryId, role: Role, segment: elf::Segment) -> Self {
        Self {
            entry,
            role,
            segment,
            next: Cell::new(u64::MAX),
            window: Cell::new(1),
        }
    }
}

pub(crate) struct Pager {
    mappings: RefCell<BTreeMap<u64, Rc<Mapping>>>,
    pending: RefCell<VecDeque<(u64, u64)>>,
    exec_locks: Rc<RefCell<ExecLocks>>,
    pub faults: Cell<u64>,
    pub filled_pages: Cell<u64>,
    /// Requests answered by killing the waiters: a read or an allocation
    /// failed.
    pub failed_fills: Cell<u64>,
    /// Microseconds spent serving fills, excluding the wait for a ticket.
    pub serve_us: Cell<u64>,
}

impl Pager {
    pub fn new(exec_locks: Rc<RefCell<ExecLocks>>) -> Self {
        Self {
            mappings: RefCell::new(BTreeMap::new()),
            pending: RefCell::new(VecDeque::new()),
            exec_locks,
            faults: Cell::new(0),
            filled_pages: Cell::new(0),
            failed_fills: Cell::new(0),
            serve_us: Cell::new(0),
        }
    }

    pub fn num_mappings(&self) -> u64 {
        self.mappings.borrow().len() as u64
    }

    /// Registers a reserved mapping; it holds a lock reference until retired.
    pub fn add(&self, id: u64, mapping: Mapping) {
        self.exec_locks.borrow_mut().acquire(mapping.entry);
        self.mappings.borrow_mut().insert(id, Rc::new(mapping));
    }

    /// Moves every queued kernel event into `pending`, applying retirements
    /// now. Retirements are queued before an exit becomes visible, so a
    /// drain lets a mutation that follows a waited-for exit proceed.
    pub fn drain(&self) {
        let mut events = [(0_u64, 0_u64); SysMem::PAGER_MAX_EVENTS];
        loop {
            let count = match SysMem::pager_dequeue(&mut events) {
                Ok(count) => count,
                Err(err) => {
                    log::error!("pager_dequeue failed: {err}");
                    return;
                }
            };
            for &(id, page) in &events[..count] {
                if page == SysMem::PAGER_RETIRED {
                    if let Some(mapping) = self.mappings.borrow_mut().remove(&id) {
                        self.exec_locks.borrow_mut().release(mapping.entry);
                    }
                } else {
                    self.pending.borrow_mut().push_back((id, page));
                }
            }
            if count < events.len() {
                return;
            }
        }
    }

    fn is_live(&self, id: u64) -> bool {
        self.drain();
        self.mappings.borrow().contains_key(&id)
    }

    fn fill_failed(&self, id: u64, page: u64) {
        match SysMem::pager_fail(id, page) {
            Ok(()) => self.failed_fills.set(self.failed_fills.get() + 1),
            Err(moto_rt::E_BAD_HANDLE) => {} // Retired meanwhile.
            Err(err) => log::error!("pager_fail({id}, 0x{page:x}) failed: {err}"),
        }
    }
}

/// Page-aligned scratch memory for fills.
struct PageBuf {
    ptr: *mut u8,
    pages: usize,
}

impl PageBuf {
    fn layout(pages: usize) -> std::alloc::Layout {
        std::alloc::Layout::from_size_align(pages * PAGE as usize, PAGE as usize).unwrap()
    }

    fn new(pages: usize) -> Option<Self> {
        let ptr = unsafe { std::alloc::alloc_zeroed(Self::layout(pages)) };
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr, pages })
        }
    }

    fn bytes(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.pages * PAGE as usize) }
    }
}

impl Drop for PageBuf {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ptr, Self::layout(self.pages)) };
    }
}

/// Reads a segment's file bytes into a zeroed page window; padding stays zero.
async fn read_pages(
    runtime: &FsRuntime,
    mapping: &Mapping,
    start: u64,
    buf: &mut [u8],
) -> std::io::Result<()> {
    let segment = &mapping.segment;
    let file_end = segment.vaddr + segment.filesz;
    let from = start.max(segment.vaddr);
    let to = (start + buf.len() as u64).min(file_end);
    if from >= to {
        return Ok(());
    }
    let offset = segment.offset + (from - segment.vaddr);
    let dst = &mut buf[(from - start) as usize..(to - start) as usize];
    read_range(runtime, mapping.role, mapping.entry, offset, dst).await
}

async fn serve(runtime: FsRuntime, id: u64, page: u64) {
    let pager = &runtime.pager;
    pager.drain();
    let Some(mapping) = pager.mappings.borrow().get(&id).cloned() else {
        return;
    };
    pager.faults.set(pager.faults.get() + 1);
    let started = moto_rt::time::Instant::now();
    let window = if page == mapping.next.get() {
        (mapping.window.get() * 2).min(MAX_WINDOW)
    } else {
        1
    };
    let mut count = window.min((mapping.segment.page_end() - page) / PAGE);
    loop {
        let read: std::io::Result<_> = async {
            let mut buf = PageBuf::new(count as usize).ok_or(std::io::ErrorKind::OutOfMemory)?;
            read_pages(&runtime, &mapping, page, buf.bytes()).await?;
            Ok(buf)
        }
        .await;
        // Retirement releases the executable lock. Discard bytes read
        // across it; the kernel also checks the ID at installation.
        if !pager.is_live(id) {
            return;
        }
        let result = match read {
            Ok(buf) => match SysMem::pager_fill(id, page, buf.ptr as u64, count) {
                Err(moto_rt::E_BAD_HANDLE) => return,
                result => result.map_err(native),
            },
            Err(err) => Err(err),
        };
        match result {
            Ok(installed) => {
                mapping.window.set(count);
                mapping.next.set(page + count * PAGE);
                pager.filled_pages.set(pager.filled_pages.get() + installed);
                SpawnStats::add_us(&pager.serve_us, started);
                return;
            }
            Err(_) if count > 1 => {
                // Read-ahead is optional: retry only the required page, with
                // the larger buffer already freed. A one-page failure is final.
                count = 1;
            }
            Err(err) => {
                log::warn!("pager: fill failed for page 0x{page:x}: {err}");
                pager.fill_failed(id, page);
                return;
            }
        }
    }
}

/// The pager task: waits for kernel events and serves each request.
pub(crate) async fn run(runtime: FsRuntime, notify: SysHandle) {
    let mut signal = notify.as_future();
    // Tickets bound the fills in flight; a serve returns its ticket when done.
    let (ticket_tx, mut ticket_rx) = moto_async::channel(MAX_SERVES);
    for _ in 0..MAX_SERVES {
        let _ = ticket_tx.send(()).await;
    }
    loop {
        let pager = runtime.pager.clone();
        pager.drain();
        loop {
            let Some((id, page)) = pager.pending.borrow_mut().pop_front() else {
                break;
            };
            if !pager.mappings.borrow().contains_key(&id) {
                continue; // Retired before it was served.
            }
            let _ticket = ticket_rx.recv().await;
            let runtime = runtime.clone();
            let ticket_tx = ticket_tx.clone();
            moto_async::LocalRuntime::spawn(async move {
                serve(runtime, id, page).await;
                let _ = ticket_tx.send(()).await;
            });
        }
        signal.rearm();
        let _ = (&mut signal).await;
    }
}
