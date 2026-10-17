//! The kernel half of the executable pager. sys-io reserves sparse
//! file-paged segments in a child's address space; a fault on an absent page
//! parks the faulting thread and queues one request per page; sys-io reads
//! the page, the fill installs a private copy, and the waiters resume. When
//! the address space exits, is dropped, or unmaps such a segment, the
//! mappings are retired and sys-io is told through the same queue; nothing
//! here waits for sys-io.

use super::process::Thread;
use super::syscall::{ResultBuilder, SyscallArgs};
use super::SysObject;
use crate::mm::user::UserAddressSpace;
use crate::util::SpinLock;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use moto_sys::{syscalls::SyscallResult, ErrorCode, SysHandle, SysMem};

mod mapping;
use mapping::{Mapping, Waiter};

const PAGE: u64 = crate::mm::PAGE_SIZE_SMALL;
/// The most pages one fill installs.
const MAX_FILL_PAGES: u64 = 64;

/// Owned by one address space. Its lock protects mapping identity and
/// commitment through segment creation, installation and removal. Lock order
/// is space -> region/page table, or space -> registry; never the reverse.
/// Source pins and thread resumes are taken outside the space lock.
#[derive(Default)]
pub(crate) struct MappingState {
    retired: bool,
    mappings: BTreeMap<u64, Mapping>, // Segment start -> mapping.
}

impl MappingState {
    fn get_mut(&mut self, start: u64, id: u64) -> Result<&mut Mapping, ErrorCode> {
        // An ID lookup may have raced with unmap and replacement at `start`.
        self.mappings
            .get_mut(&start)
            .filter(|mapping| mapping.id == id)
            .ok_or(moto_rt::E_BAD_HANDLE)
    }
}

struct Pager {
    /// ID -> (address space, segment start). Mapping state lives in the space.
    mappings: BTreeMap<u64, (Weak<UserAddressSpace>, u64)>,
    /// (mapping id, page) requests, or (mapping id, PAGER_RETIRED).
    events: VecDeque<(u64, u64)>,
    notify: Option<Arc<SysObject>>,
    next_id: u64,
}

/// The registry: one for the kernel, held by `KernelAddressSpace`.
pub(crate) struct PagerRegistry(SpinLock<Pager>);

impl PagerRegistry {
    pub(crate) const fn new() -> Self {
        Self(SpinLock::new(Pager {
            mappings: BTreeMap::new(),
            events: VecDeque::new(),
            notify: None,
            next_id: 1,
        }))
    }
}

fn registry() -> &'static SpinLock<Pager> {
    &crate::mm::virt::pager_registry().0
}

fn lookup(id: u64) -> Result<(Arc<UserAddressSpace>, u64), ErrorCode> {
    let (space, start) = registry()
        .lock(line!())
        .mappings
        .get(&id)
        .cloned()
        .ok_or(moto_rt::E_BAD_HANDLE)?;
    // Release the registry before acquiring a space reference or its lock.
    Ok((space.upgrade().ok_or(moto_rt::E_BAD_HANDLE)?, start))
}

pub(super) fn sys_pager(thread: &Thread, args: &SyscallArgs) -> SyscallResult {
    let caller = thread.owner();
    if caller.pid() != super::process::SYS_IO_PID {
        return ResultBuilder::result(moto_rt::E_NOT_ALLOWED);
    }
    // sys-io has no file-paged segments, so its buffers need no page-fault retry.
    let result = match args.flags {
        SysMem::F_PAGER_INIT => init(&caller),
        SysMem::F_PAGER_RESERVE => reserve(&caller, args),
        SysMem::F_PAGER_DEQUEUE => dequeue(&caller, args.args[1], args.args[2]),
        SysMem::F_PAGER_FILL => fill(&caller, args),
        SysMem::F_PAGER_FAIL => fail(args.args[1], args.args[2]).map(|_| 0),
        SysMem::F_PAGER_ZERO_FROM => zero_from(args.args[1], args.args[2]).map(|_| 0),
        _ => Err(moto_rt::E_INVALID_ARGUMENT),
    };
    match result {
        Ok(value) => ResultBuilder::ok_1(value),
        Err(err) => ResultBuilder::result(err),
    }
}

fn init(caller: &Arc<super::Process>) -> Result<u64, ErrorCode> {
    let mut pager = registry().lock(line!());
    if pager.notify.is_some() {
        return Err(moto_rt::E_ALREADY_IN_USE);
    }
    let notify = SysObject::new(Arc::new(alloc::string::String::from("pager")));
    let handle = caller.add_object(notify.clone());
    pager.notify = Some(notify);
    Ok(handle.as_u64())
}

fn reserve(caller: &Arc<super::Process>, args: &SyscallArgs) -> Result<u64, ErrorCode> {
    let space = super::sysobject::object_from_handle::<UserAddressSpace>(
        caller,
        SysHandle::from_u64(args.args[0]),
    )
    .ok_or(moto_rt::E_BAD_HANDLE)?;
    let (start, pages, prot) = (args.args[1], args.args[2], args.args[3]);
    let end = pages
        .checked_mul(PAGE)
        .and_then(|len| start.checked_add(len))
        .ok_or(moto_rt::E_INVALID_ARGUMENT)?;
    if !start.is_multiple_of(PAGE) || pages == 0 || prot & !3 != 0 {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }
    let reservation = crate::mm::admission::commit(
        space.mem_class(),
        crate::mm::admission::mapping_charge(pages, pages),
    )?;
    let mut state = space.pager.lock(line!());
    if state.retired {
        return Err(moto_rt::E_BAD_HANDLE);
    }
    // The registry is taken twice on purpose: every check that can fail
    // precedes `reserve_file`, so nothing needs rolling back.
    let id = {
        let mut pager = registry().lock(line!());
        if pager.notify.is_none() {
            return Err(moto_rt::E_NOT_READY);
        }
        let id = pager.next_id;
        pager.next_id = id.checked_add(1).ok_or(moto_rt::E_OUT_OF_MEMORY)?;
        id
    };
    // The space guard makes segment creation and publication atomic with
    // respect to faults, unmap and whole-space retirement.
    space.reserve_file(start, pages, prot & 2 != 0, prot & 1 != 0)?;
    state.mappings.insert(
        start,
        Mapping {
            id,
            reservation,
            start,
            end,
            zero_from: u64::MAX,
            queued: BTreeSet::new(),
            waiters: Vec::new(),
        },
    );
    registry()
        .lock(line!())
        .mappings
        .insert(id, (Arc::downgrade(&space), start));
    Ok(id)
}

fn dequeue(caller: &Arc<super::Process>, buf: u64, capacity: u64) -> Result<u64, ErrorCode> {
    let mut batch = [[0_u64; 2]; SysMem::PAGER_MAX_EVENTS];
    let count = {
        let mut pager = registry().lock(line!());
        let count = (capacity as usize).min(batch.len()).min(pager.events.len());
        for slot in batch.iter_mut().take(count) {
            let (id, page) = pager.events.pop_front().unwrap();
            *slot = [id, page];
        }
        count
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            batch.as_ptr() as *const u8,
            core::mem::size_of_val(&batch[..count]),
        )
    };
    if let Err(err) = caller.address_space().copy_to_user(bytes, buf) {
        // Requeue, so a bad buffer loses nothing.
        let mut pager = registry().lock(line!());
        for &[id, page] in batch[..count].iter().rev() {
            pager.events.push_front((id, page));
        }
        return Err(err.into());
    }
    Ok(count as u64)
}

fn resume(waiters: Vec<Waiter>, success: bool) {
    for waiter in waiters {
        if let Some(thread) = waiter.thread.upgrade() {
            thread.resume_file_fault(false, success);
        }
    }
}

/// Installs private copies of `count` contiguous caller pages at `source`
/// from `dest` on; returns how many pages were installed.
fn fill(caller: &Arc<super::Process>, args: &SyscallArgs) -> Result<u64, ErrorCode> {
    let (id, dest, source, count) = (args.args[1], args.args[2], args.args[3], args.args[4]);
    if count == 0 || count > MAX_FILL_PAGES || !dest.is_multiple_of(PAGE) {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }
    let len = count * PAGE;
    let dest_end = dest.checked_add(len).ok_or(moto_rt::E_INVALID_ARGUMENT)?;
    source.checked_add(len).ok_or(moto_rt::E_INVALID_ARGUMENT)?;
    let (space, start) = lookup(id)?;
    // Pin all caller pages before locking the destination, including when
    // source and destination are in the same address space.
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(count as usize)
        .map_err(|_| moto_rt::E_OUT_OF_MEMORY)?;
    for idx in 0..count {
        sources.push(
            caller.address_space().get_user_page_as_kernel(
                source + idx * PAGE,
                crate::mm::MappingOptions::READABLE,
            )?,
        );
    }
    let (installed, waiters) = {
        let mut state = space.pager.lock(line!());
        let mapping = state.get_mut(start, id)?;
        if dest < mapping.start || dest_end > mapping.end {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let (installed, result) = space.fill_file(dest, &sources);
        // A failed fill may still have installed a prefix of the window.
        mapping.reservation.release(installed);
        result?;
        (installed, mapping.take_waiters(dest, dest_end))
    };
    resume(waiters, true);
    Ok(installed)
}

fn fail(id: u64, page: u64) -> Result<(), ErrorCode> {
    let (space, start) = lookup(id)?;
    let waiters = {
        let mut state = space.pager.lock(line!());
        state.get_mut(start, id)?.fail_page(page)?
    };
    resume(waiters, false);
    Ok(())
}

fn zero_from(id: u64, start: u64) -> Result<(), ErrorCode> {
    let (space, mapping_start) = lookup(id)?;
    let mut state = space.pager.lock(line!());
    let mapping = state.get_mut(mapping_start, id)?;
    if !start.is_multiple_of(PAGE) || start < mapping.start || start > mapping.end {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }
    mapping.zero_from = start;
    Ok(())
}

/// What a fault needs after releasing the address-space guard.
enum Next {
    /// Resolved locally; resume or kill the thread according to the result.
    Resume(bool),
    /// Queued for sys-io; wake it.
    Request(Arc<SysObject>),
}

/// Called for a not-present fault in a file-paged segment, after the thread
/// was parked (Preempted, no resume job). Returns false if no pager serves
/// the address: the fault is then fatal.
pub(super) fn on_fault(thread: &Thread, addr: u64) -> bool {
    let owner = thread.owner();
    let space = owner.address_space();
    let page = addr & !(PAGE - 1);
    let next = {
        let mut state = space.pager.lock(line!());
        let Some((_, mapping)) = state.mappings.range_mut(..=page).next_back() else {
            return false;
        };
        if page >= mapping.end {
            return false;
        }
        if space.virt_to_phys(page).is_some() {
            Next::Resume(true)
        } else if page >= mapping.zero_from {
            let filled = space.fill_file_zero(page);
            if filled == Ok(true) {
                mapping.reservation.release(1);
            }
            Next::Resume(filled.is_ok())
        } else {
            mapping.waiters.push(Waiter {
                page,
                thread: thread.get_weak(),
            });
            if !mapping.queued.insert(page) {
                return true; // Already requested; this thread just waits too.
            }
            let mut pager = registry().lock(line!());
            // Reserve requires initialization; the notification is permanent.
            let notify = pager.notify.as_ref().unwrap().clone();
            pager.events.push_back((mapping.id, page));
            Next::Request(notify)
        }
    };
    match next {
        Next::Resume(success) => thread.resume_file_fault(true, success),
        Next::Request(notify) => notify.wake(false),
    }
    true
}

/// Retires every mapping before process exit is published, or on drop if
/// the address space was never used by a process. Retirement is terminal.
pub(crate) fn retire_space(space: &UserAddressSpace) {
    let (mappings, notify) = {
        let mut state = space.pager.lock(line!());
        state.retired = true;
        let mappings = core::mem::take(&mut state.mappings);
        if mappings.is_empty() {
            return;
        }
        let mut pager = registry().lock(line!());
        for mapping in mappings.values() {
            pager.mappings.remove(&mapping.id);
            pager.events.push_back((mapping.id, SysMem::PAGER_RETIRED));
        }
        (mappings, pager.notify.clone())
    };
    // Move the collections out, keeping their commitments until no fill can
    // reach them. No snapshot of addresses or merged waiter buffer is needed.
    for mapping in mappings.into_values() {
        resume(mapping.waiters, false);
    }
    if let Some(notify) = notify {
        notify.wake(false);
    }
}

/// Serializes segment removal and exact-ID retirement against reserve/fill.
/// The callback only removes the segment and updates its memory statistics.
pub(crate) fn unmap(
    space: &UserAddressSpace,
    start: u64,
    unmap_segment: impl FnOnce() -> Result<(), ErrorCode>,
) -> Result<(), ErrorCode> {
    let (mapping, notify) = {
        let mut state = space.pager.lock(line!());
        unmap_segment()?;
        let Some(mapping) = state.mappings.remove(&start) else {
            return Ok(());
        };
        let mut pager = registry().lock(line!());
        pager.mappings.remove(&mapping.id);
        pager.events.push_back((mapping.id, SysMem::PAGER_RETIRED));
        (mapping, pager.notify.clone())
    };
    resume(mapping.waiters, false);
    if let Some(notify) = notify {
        notify.wake(false);
    }
    Ok(())
}
