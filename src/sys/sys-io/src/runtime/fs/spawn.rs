//! Building child processes on a client's behalf (CMD_SPAWN): sys-io
//! authorizes and locks the executable, loads it into a new address space,
//! adds the vDSO, and creates the process with the client as its parent. The
//! child stays stopped; its parent writes the startup data and wakes it.

mod elf;
pub(crate) mod pager;
#[cfg(debug_assertions)]
pub(super) mod self_test;
mod vdso;

use super::FsRuntime;
use async_fs::{AccessPermissions, EntryId, EntryKind, FileSystem, Role};
use moto_sys::{SysHandle, SysMem, SysObj, syscalls::RaiiHandle};
use moto_sys_io::api_fs;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::{ErrorKind, Result};

use elf::PAGE;

fn native(code: moto_rt::ErrorCode) -> std::io::Error {
    std::io::Error::from_raw_os_error(code as i32)
}

/// A zeroed buffer, or an error instead of aborting sys-io.
fn try_zeroed(len: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| std::io::Error::from(ErrorKind::OutOfMemory))?;
    bytes.resize(len, 0);
    Ok(bytes)
}

/// Executables that must not change: each reference is a construction in
/// progress or a live demand-paged mapping of the file.
#[derive(Default)]
pub(crate) struct ExecLocks {
    refs: BTreeMap<EntryId, u32>,
}

impl ExecLocks {
    pub(crate) fn is_locked(&self, entry: EntryId) -> bool {
        self.refs.contains_key(&entry)
    }

    pub(crate) fn num_locked(&self) -> usize {
        self.refs.len()
    }

    fn acquire(&mut self, entry: EntryId) {
        *self.refs.entry(entry).or_insert(0) += 1;
    }

    fn release(&mut self, entry: EntryId) {
        let count = self
            .refs
            .get_mut(&entry)
            .expect("an executable lock reference");
        *count -= 1;
        if *count == 0 {
            self.refs.remove(&entry);
        }
    }
}

/// Counters for the stats responder.
#[derive(Default)]
pub(crate) struct SpawnStats {
    pub requests: Cell<u64>,
    /// Microseconds spent building children, in their relocation passes, and
    /// installing their vDSOs.
    pub build_us: Cell<u64>,
    pub scan_us: Cell<u64>,
    pub vdso_us: Cell<u64>,
}

impl SpawnStats {
    fn add_us(counter: &Cell<u64>, since: moto_rt::time::Instant) {
        counter.set(counter.get() + since.elapsed().as_micros() as u64);
    }
}

/// A construction reference on an executable, released on drop.
struct ConstructionLock {
    runtime: FsRuntime,
    entry: EntryId,
}

impl ConstructionLock {
    fn new(runtime: &FsRuntime, entry: EntryId) -> Self {
        runtime.exec_locks.borrow_mut().acquire(entry);
        Self {
            runtime: runtime.clone(),
            entry,
        }
    }
}

impl Drop for ConstructionLock {
    fn drop(&mut self) {
        self.runtime.exec_locks.borrow_mut().release(self.entry);
    }
}

/// Reads exactly `dst.len()` bytes at `offset`, block by block.
async fn read_exact_at(
    runtime: &FsRuntime,
    role: Role,
    entry: EntryId,
    mut offset: u64,
    mut dst: &mut [u8],
) -> Result<()> {
    let block = async_fs::BLOCK_SIZE as u64;
    let fs = runtime.fs.read().await;
    while !dst.is_empty() {
        let in_block = ((block - offset % block) as usize).min(dst.len());
        let (head, tail) = dst.split_at_mut(in_block);
        let read = fs.read(role, entry, offset, head).await?;
        if read != in_block {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        offset += in_block as u64;
        dst = tail;
    }
    Ok(())
}

/// Reads a file range in batches, prefetching each batch so its blocks are
/// fetched from the device concurrently.
async fn read_range(
    runtime: &FsRuntime,
    role: Role,
    entry: EntryId,
    offset: u64,
    dst: &mut [u8],
) -> Result<()> {
    const BATCH: usize = 64 * 4096;
    let block = async_fs::BLOCK_SIZE as u64;
    let mut done = 0;
    while done < dst.len() {
        let len = (dst.len() - done).min(BATCH);
        let first_key = (offset + done as u64) / block;
        let last_key = (offset + (done + len) as u64 - 1) / block;
        runtime
            .fs
            .read()
            .await
            .prefetch(entry, first_key, last_key - first_key + 1)
            .await;
        read_exact_at(
            runtime,
            role,
            entry,
            offset + done as u64,
            &mut dst[done..done + len],
        )
        .await?;
        done += len;
    }
    Ok(())
}

async fn read_vec(
    runtime: &FsRuntime,
    role: Role,
    entry: EntryId,
    offset: u64,
    len: u64,
) -> Result<Vec<u8>> {
    let mut bytes = try_zeroed(len as usize)?;
    read_range(runtime, role, entry, offset, &mut bytes).await?;
    Ok(bytes)
}

/// The local R+W aliases of the child's eagerly loaded segments, in address
/// order, and the segments left to the pager.
struct Aliases {
    regions: Vec<(elf::Segment, u64)>,
    paged: Vec<elf::Segment>,
}

impl Aliases {
    /// The local address of child bytes `[vaddr, vaddr + len)` if one
    /// segment holds them.
    fn local(&self, vaddr: u64, len: u64) -> Option<u64> {
        let idx = self
            .regions
            .partition_point(|(segment, _)| segment.page_end() <= vaddr);
        let (segment, alias) = self.regions.get(idx)?;
        (vaddr >= segment.page_start()
            && vaddr
                .checked_add(len)
                .is_some_and(|end| end <= segment.page_end()))
        .then(|| alias + (vaddr - segment.page_start()))
    }
}

impl Drop for Aliases {
    fn drop(&mut self) {
        for (_, alias) in &self.regions {
            SysMem::unmap(SysHandle::SELF, 0, u64::MAX, *alias).unwrap();
        }
    }
}

/// Maps a segment's pages into the child with its own protection and fills
/// them with its file bytes through a local alias; the rest stays zero.
async fn load_segment(
    runtime: &FsRuntime,
    role: Role,
    entry: EntryId,
    space: SysHandle,
    segment: &elf::Segment,
    aliases: &mut Aliases,
) -> Result<()> {
    let mut flags = SysMem::F_SHARE_SELF | SysMem::F_READABLE;
    if segment.writable {
        flags |= SysMem::F_WRITABLE;
    }
    if segment.executable {
        flags |= SysMem::F_EXECUTABLE;
    }
    let (remote, local) = SysMem::map2(
        space,
        flags,
        u64::MAX,
        segment.page_start(),
        PAGE,
        segment.num_pages(),
    )
    .map_err(native)?;
    aliases.regions.push((*segment, local));
    if remote != segment.page_start() {
        return Err(ErrorKind::InvalidData.into());
    }
    let dst = unsafe {
        core::slice::from_raw_parts_mut(
            (local + (segment.vaddr - segment.page_start())) as usize as *mut u8,
            segment.filesz as usize,
        )
    };
    read_range(runtime, role, entry, segment.offset, dst).await
}

/// How the pager finds a lazily relocated page's records, built by one
/// validating pass over the table at load: `first[i]` is the first record
/// that may overlap page `i` (destination at least the page start minus 7);
/// pages past the end of `first` start at `count`.
pub(crate) struct RelocIndex {
    pub table_offset: u64,
    pub first: Vec<u32>,
    /// One past this segment's last record, not the whole table's end.
    pub count: u32,
}

/// The most pages a relocation index spans (256 MiB of relocated data); a
/// larger span is loaded eagerly rather than indexed.
const MAX_INDEXED_PAGES: usize = 65536;

/// A writable segment being prepared for the pager.
struct LazyData {
    segment: elf::Segment,
    first: Vec<u32>,
    count: u32,
    last_dst: u64,
    /// One past the last byte any relocation writes.
    reloc_end: u64,
}

impl LazyData {
    fn new(segment: elf::Segment) -> Self {
        Self {
            segment,
            first: Vec::new(),
            count: 0,
            last_dst: 0,
            reloc_end: 0,
        }
    }

    /// Indexes record `idx`; false if the segment's records are unsorted or
    /// span too many pages to index.
    fn add(&mut self, idx: u64, dst: u64) -> bool {
        let Ok(count) = u32::try_from(idx + 1) else {
            return false;
        };
        if dst < self.last_dst {
            return false;
        }
        self.last_dst = dst;
        self.count = count;
        self.reloc_end = self.reloc_end.max(dst + 8);
        let pages = self.segment.num_pages() as usize;
        while self.first.len() < pages
            && (self.segment.page_start() + self.first.len() as u64 * PAGE).saturating_sub(7) <= dst
        {
            if self.first.len() == MAX_INDEXED_PAGES || self.first.try_reserve(1).is_err() {
                return false;
            }
            self.first.push(count - 1);
        }
        true
    }
}

/// One pass over the RELA table: validates every record, applies those that
/// land in eagerly loaded segments, and indexes those for lazily relocated
/// ones. Images are linked at their run address, so the addend is the value.
/// Returns a fallback plan when a segment cannot be served lazily.
async fn scan_relocations(
    runtime: &FsRuntime,
    role: Role,
    entry: EntryId,
    relocations: &elf::Relocations,
    aliases: &Aliases,
    lazy: &mut [LazyData],
) -> Result<Option<Plan>> {
    const CHUNK: u64 = 2730 * elf::RELA_ENTRY_SIZE;
    let mut buf = try_zeroed(relocations.size.min(CHUNK) as usize)?;
    let mut done = 0;
    let mut idx = 0_u64;
    while done < relocations.size {
        let len = (relocations.size - done).min(CHUNK);
        read_range(
            runtime,
            role,
            entry,
            relocations.offset + done,
            &mut buf[..len as usize],
        )
        .await?;
        for record in buf[..len as usize]
            .as_chunks::<{ elf::RELA_ENTRY_SIZE as usize }>()
            .0
        {
            let (dst, kind, addend) = elf::rela_at(record);
            match kind {
                elf::R_X86_64_NONE => {}
                elf::R_X86_64_RELATIVE => {
                    if let Some(local) = aliases.local(dst, 8) {
                        unsafe { (local as usize as *mut u64).write_unaligned(addend) };
                    } else if let Some(data) = lazy.iter_mut().find(|d| {
                        dst >= d.segment.page_start()
                            && dst
                                .checked_add(8)
                                .is_some_and(|end| end <= d.segment.page_end())
                    }) {
                        if !data.add(idx, dst) {
                            return Ok(Some(Plan::PagedText));
                        }
                    } else if aliases.paged.iter().any(|s| {
                        dst >= s.page_start()
                            && dst.checked_add(8).is_some_and(|end| end <= s.page_end())
                    }) {
                        // A relocated read-only page cannot be demand-paged
                        // from the file: the caller loads the image eagerly.
                        return Ok(Some(Plan::Eager));
                    } else {
                        return Err(ErrorKind::InvalidInput.into());
                    }
                }
                _ => return Err(ErrorKind::InvalidInput.into()),
            }
            idx += 1;
        }
        done += len;
    }
    Ok(None)
}

/// The file's size, once the requester's role is allowed to run it.
async fn executable_size(runtime: &FsRuntime, role: Role, entry: EntryId) -> Result<u64> {
    let metadata = runtime.fs.read().await.metadata(role, entry).await?;
    if metadata.kind() != EntryKind::File {
        return Err(ErrorKind::InvalidInput.into());
    }
    if !matches!(
        metadata.access(role)?,
        AccessPermissions::Rwx | AccessPermissions::Rx
    ) {
        return Err(ErrorKind::PermissionDenied.into());
    }
    Ok(metadata.size)
}

/// Files below this size are loaded eagerly: a demand fault costs more than
/// copying a few pages up front.
const PAGED_MIN_FILE: u64 = 1 << 20;

/// Builds the child; returns sys-io's own handle to it and the number of the
/// handle in the requester's table.
async fn build(
    runtime: &FsRuntime,
    role: Role,
    connection: SysHandle,
    req: &api_fs::SpawnRequest,
) -> Result<(RaiiHandle, u64)> {
    let entry = req.entry_id;
    // Authorize as the requester before reading a byte or locking the file.
    let file_size = executable_size(runtime, role, entry).await?;
    // No await separates authorization from locking on the cooperative FS
    // runtime. Mutations check this lock under the FS write guard, so even
    // writers already queued behind the metadata read must respect it.
    let _lock = ConstructionLock::new(runtime, entry);

    let header_bytes = read_vec(runtime, role, entry, 0, file_size.min(64)).await?;
    let header = elf::parse_header(&header_bytes, file_size)?;
    let table = read_vec(runtime, role, entry, header.phoff, header.phnum * 56).await?;
    let image = elf::parse_program_headers(&header, &table, file_size)?;
    let relocations = match image.dynamic {
        Some((offset, size)) => {
            let bytes = read_vec(runtime, role, entry, offset, size).await?;
            elf::parse_dynamic(&image, &bytes, file_size)?
        }
        None => elf::Relocations::default(),
    };

    let mut plan = if file_size < PAGED_MIN_FILE {
        Plan::Eager
    } else {
        Plan::PagedAll
    };
    // Images the paged plans cannot serve are rebuilt with a simpler plan:
    // unsorted relocations need eager data, relocated read-only pages an
    // eager image.
    let space = loop {
        match load_image(runtime, role, req, &image, &relocations, plan).await? {
            Load::Ready(space) => break space,
            Load::Fallback(next) => plan = next,
        }
    };

    let vdso_started = moto_rt::time::Instant::now();
    vdso::load(space.syshandle()).map_err(native)?;
    SpawnStats::add_us(&runtime.spawn_stats.vdso_us, vdso_started);

    let url = format!(
        "process:entry_point={};capabilities={};detached={};requester={}",
        image.entry,
        req.capabilities,
        u64::from(req.detached),
        connection.as_u64()
    );
    let (own, theirs) = SysObj::create_res1(space.syshandle(), 0, &url).map_err(native)?;
    Ok((RaiiHandle::from(own), theirs))
}

/// How the image is loaded.
#[derive(Clone, Copy, PartialEq)]
enum Plan {
    Eager,
    /// Read-only segments paged, writable ones eager.
    PagedText,
    /// Writable segments paged and relocated on demand too.
    PagedAll,
}

enum Load {
    Ready(RaiiHandle),
    Fallback(Plan),
}

/// Creates the child's address space and loads the image into it.
async fn load_image(
    runtime: &FsRuntime,
    role: Role,
    req: &api_fs::SpawnRequest,
    image: &elf::Image,
    relocations: &elf::Relocations,
    plan: Plan,
) -> Result<Load> {
    let entry = req.entry_id;
    let space = RaiiHandle::from(
        SysObj::create(
            SysHandle::NONE,
            0,
            &format!(
                "address_space:debug_name={}",
                moto_sys::url_encode(&req.debug_name)
            ),
        )
        .map_err(native)?,
    );

    let mut aliases = Aliases {
        regions: Vec::with_capacity(image.segments.len()),
        paged: Vec::new(),
    };
    let mut lazy = Vec::new();
    for segment in &image.segments {
        if plan != Plan::Eager
            && segment.congruent()
            && segment.page_end() <= moto_sys::USERSPACE_REGION_END
        {
            if !segment.writable {
                aliases.paged.push(*segment);
                continue;
            }
            if plan == Plan::PagedAll {
                lazy.push(LazyData::new(*segment));
                continue;
            }
        }
        load_segment(
            runtime,
            role,
            entry,
            space.syshandle(),
            segment,
            &mut aliases,
        )
        .await?;
    }
    let scan_started = moto_rt::time::Instant::now();
    let fallback = scan_relocations(runtime, role, entry, relocations, &aliases, &mut lazy).await?;
    SpawnStats::add_us(&runtime.spawn_stats.scan_us, scan_started);
    if let Some(plan) = fallback {
        return Ok(Load::Fallback(plan));
    }

    // Reserve paged segments only now that the image is known to be
    // loadable this way. Each is registered at once: if the build fails
    // later, dropping the address space retires it and releases its lock.
    for segment in &aliases.paged {
        let id = SysMem::pager_reserve(
            space.syshandle(),
            segment.page_start(),
            segment.num_pages(),
            false,
            segment.executable,
        )
        .map_err(native)?;
        runtime
            .pager
            .add(id, pager::Mapping::new(entry, role, *segment, None));
    }
    for data in lazy {
        let segment = data.segment;
        let id = SysMem::pager_reserve(
            space.syshandle(),
            segment.page_start(),
            segment.num_pages(),
            true,
            false,
        )
        .map_err(native)?;
        let index = RelocIndex {
            table_offset: relocations.offset,
            first: data.first,
            count: data.count,
        };
        runtime
            .pager
            .add(id, pager::Mapping::new(entry, role, segment, Some(index)));
        // Pages past both the file bytes and every relocation are zeros.
        let file_end = (segment.vaddr + segment.filesz).next_multiple_of(PAGE);
        let zero_from = file_end.max(data.reloc_end.next_multiple_of(PAGE));
        if zero_from < segment.page_end() {
            SysMem::pager_zero_from(id, zero_from).map_err(native)?;
        }
    }
    Ok(Load::Ready(space))
}

pub(super) async fn on_cmd_spawn(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let mut req = api_fs::spawn_msg_decode(msg, sender).map_err(crate::util::map_native_error)?;
    req.entry_id = runtime.entry_ids.decode(req.entry_id);
    let stats = &runtime.spawn_stats;
    stats.requests.set(stats.requests.get() + 1);
    let started = moto_rt::time::Instant::now();
    let (own, theirs) = build(&runtime, role, sender.remote_handle(), &req).await?;
    SpawnStats::add_us(&stats.build_us, started);

    // A send into the ring succeeds even when the requester has already
    // closed the connection, so check after sending too. Abandoning kills
    // the child and withdraws the requester's handle only if nobody has woken
    // it, so a requester that read the response in time keeps its child.
    let delivered = sender
        .send(api_fs::spawn_resp_encode(msg.id, theirs))
        .await
        .is_ok()
        && SysObj::is_connected(sender.remote_handle()).unwrap_or(false);
    if !delivered {
        let _ = SysObj::put_remote_1(
            own.syshandle(),
            SysHandle::from_u64(theirs),
            SysObj::ABANDON_DELEGATED,
        );
    }
    Ok(())
}
