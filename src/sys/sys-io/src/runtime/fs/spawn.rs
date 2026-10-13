//! Building child processes on a client's behalf (CMD_SPAWN): sys-io
//! authorizes and locks the executable, loads it into a new address space,
//! adds the vDSO, and creates the process with the client as its parent. The
//! child stays stopped; its parent writes the startup data and wakes it.

mod elf;
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
/// progress.
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
    /// Microseconds spent building children, and installing their vDSOs.
    pub build_us: Cell<u64>,
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

/// The local R+W aliases of the child's segments, in address order.
struct Aliases {
    regions: Vec<(elf::Segment, u64)>,
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

/// One pass over the RELA table: validates every record and applies the
/// `R_X86_64_RELATIVE` ones through the segment aliases. Images are linked
/// at their run address, so the addend is the value.
async fn scan_relocations(
    runtime: &FsRuntime,
    role: Role,
    entry: EntryId,
    relocations: &elf::Relocations,
    aliases: &Aliases,
) -> Result<()> {
    const CHUNK: u64 = 2730 * elf::RELA_ENTRY_SIZE;
    let mut buf = try_zeroed(relocations.size.min(CHUNK) as usize)?;
    let mut done = 0;
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
                    let local = aliases.local(dst, 8).ok_or(ErrorKind::InvalidInput)?;
                    unsafe { (local as usize as *mut u64).write_unaligned(addend) };
                }
                _ => return Err(ErrorKind::InvalidInput.into()),
            }
        }
        done += len;
    }
    Ok(())
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
    executable_size(runtime, role, entry).await?;
    let _lock = ConstructionLock::new(runtime, entry);
    // Neither can change any more: every mutation is refused while the
    // executable is locked.
    let file_size = executable_size(runtime, role, entry).await?;

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
    let space = load_image(runtime, role, req, &image, &relocations).await?;

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

/// Creates the child's address space and loads the image into it.
async fn load_image(
    runtime: &FsRuntime,
    role: Role,
    req: &api_fs::SpawnRequest,
    image: &elf::Image,
    relocations: &elf::Relocations,
) -> Result<RaiiHandle> {
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
    };
    for segment in &image.segments {
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
    scan_relocations(runtime, role, entry, relocations, &aliases).await?;
    Ok(space)
}

pub(super) async fn on_cmd_spawn(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let req = api_fs::spawn_msg_decode(msg, sender).map_err(crate::util::map_native_error)?;
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
