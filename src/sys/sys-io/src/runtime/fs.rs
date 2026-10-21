use async_fs::AccessPermissions;
use async_fs::EntryId;
use async_fs::Role;
use async_fs::RolePermissions;
use async_fs::{EntryKind, FileSystem};
use async_trait::async_trait;
use moto_async::AsFuture;
use moto_sys_io::api_fs;
use moto_sys_io::api_fs::FS_URL;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::io::Result;
use std::rc::Rc;

use moto_sys::caps::ProcessRole;

use crate::runtime::channel_budget;
use crate::runtime::fs::virtio_partition::VirtioPartition;
use crate::util::map_err_into_native;
use crate::util::map_native_error;

pub(crate) mod admission;
mod block_io;
mod config;
mod entry_ids;
mod lock_manager;
mod mbr;
mod mounts;
#[cfg(debug_assertions)]
mod self_test;
mod spawn;
pub mod stats;
mod virtio_partition;

/// The fs runtime's self-tests, gathered here because the module holding them
/// is private to this one. See [`crate::self_test`].
#[cfg(debug_assertions)]
pub(crate) const SELF_TESTS: &[&[crate::self_test::SelfTest]] = &[
    entry_ids::self_test::TESTS,
    lock_manager::self_test::TESTS,
    mounts::self_test::TESTS,
    config::self_test::TESTS,
    admission::self_test::TESTS,
    self_test::TESTS,
    &[
        ("fs::spawn::queued_mutations", stats::test_executable_locks),
        ("fs::pager::coalesced_windows", stats::test_pager_windows),
    ],
];

/// The max number of "requests" in flight per connection.
const MAX_IN_FLIGHT: usize = 64;

/// How far sequential readahead prefetches past the current read (in 4K
/// blocks). See `maybe_readahead` and `on_cmd_read_multi`.
const READAHEAD_BLOCKS: u64 = 32;

/// The block cache follows the guest's memory: 1 MiB per 32 MiB of RAM, at
/// least 1 MiB, and 16 MiB from 256 MiB up.
fn block_cache_blocks() -> usize {
    let ram_mib = super::guest_ram_mib();
    let cache_mib = if ram_mib >= super::SMALL_GUEST_MIB {
        16
    } else {
        (ram_mib / 32).max(1)
    };
    ((cache_mib << 20) / async_fs::BLOCK_SIZE as u64) as usize
}

const _: () = {
    assert!(ProcessRole::None as u8 == Role::None as u8);
    assert!(ProcessRole::Interactive as u8 == Role::Interactive as u8);
    assert!(ProcessRole::System as u8 == Role::System as u8);
};

fn fs_role(capabilities: u64) -> Role {
    match ProcessRole::from_caps(capabilities) {
        ProcessRole::None => Role::None,
        ProcessRole::Interactive => Role::Interactive,
        ProcessRole::System => Role::System,
    }
}

// We allow(private_interfaces) to hide a warning that VirtioPartition
// has less visibility than enum FS, which is by design: the enum
// has crate visibility to allow internal/async FS access, but
// VirtioPartition is an internal detail of mod fs.
#[allow(private_interfaces)]
// Each mount already allocates its FS in an Rc. Keep direct enum dispatch
// instead of adding another allocation and indirection for the disk backend.
#[allow(clippy::large_enum_variant)]
pub(crate) enum FS {
    MotorFs(motor_fs::MotorFs<VirtioPartition>),
    MemFs(memfs::MemFs),
}

impl FS {
    fn kind(&self) -> api_fs::MountKind {
        match self {
            FS::MotorFs(_) => api_fs::MountKind::MotorFs,
            FS::MemFs(_) => api_fs::MountKind::MemFs,
        }
    }

    /// Best-effort readahead; see [`motor_fs::MotorFs::prefetch`].
    async fn prefetch(&self, file_id: EntryId, first_key: u64, count: u64) {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.prefetch(file_id, first_key, count).await,
            FS::MemFs(_) => {}
        }
    }

    /// Block cache hit/miss/dedup counters. Diagnostics only.
    fn cache_stats(&self) -> Option<async_fs::block_cache::BlockCacheStats> {
        match self {
            FS::MotorFs(motor_fs) => Some(motor_fs.cache_stats()),
            FS::MemFs(_) => None,
        }
    }

    /// A name lookup without the traverse check, for sys-io's own protections.
    async fn lookup_unchecked(
        &self,
        parent: EntryId,
        name: &str,
    ) -> Result<Option<(EntryId, EntryKind)>> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.lookup_unchecked(parent, name).await,
            FS::MemFs(fs) => fs.lookup_unchecked(parent, name),
        }
    }
}

#[async_trait(?Send)]
impl FileSystem for FS {
    /// Find a file or directory by its full path.
    async fn stat(
        &self,
        role: Role,
        parent_id: EntryId,
        filename: &str,
    ) -> Result<Option<(EntryId, EntryKind)>> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.stat(role, parent_id, filename).await,
            FS::MemFs(fs) => fs.stat_sync(role, parent_id, filename),
        }
    }

    /// Create a file or directory.
    async fn create_entry(
        &mut self,
        role: Role,
        parent_id: EntryId,
        kind: EntryKind,
        name: &str, // Leaf name.
        permissions: RolePermissions,
    ) -> Result<EntryId> {
        match self {
            FS::MemFs(fs) => fs.create_entry_sync(role, parent_id, kind, name, permissions),
            FS::MotorFs(motor_fs) => {
                motor_fs
                    .create_entry(role, parent_id, kind, name, permissions)
                    .await
            }
        }
    }

    /// Change one role's permission on an entry.
    async fn set_permissions(
        &mut self,
        caller: Role,
        entry_id: EntryId,
        target: Role,
        access: AccessPermissions,
    ) -> Result<()> {
        match self {
            FS::MemFs(fs) => fs.set_permissions_sync(caller, entry_id, target, access),
            FS::MotorFs(motor_fs) => {
                motor_fs
                    .set_permissions(caller, entry_id, target, access)
                    .await
            }
        }
    }

    async fn set_all_permissions(
        &mut self,
        caller: Role,
        entry_id: EntryId,
        permissions: RolePermissions,
    ) -> Result<()> {
        match self {
            FS::MemFs(fs) => fs.set_all_permissions_sync(caller, entry_id, permissions),
            FS::MotorFs(motor_fs) => {
                motor_fs
                    .set_all_permissions(caller, entry_id, permissions)
                    .await
            }
        }
    }

    /// Delete the file or directory.
    async fn delete_entry(&mut self, role: Role, entry_id: EntryId) -> Result<()> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.delete_entry(role, entry_id).await,
            FS::MemFs(fs) => fs.delete_entry_sync(role, entry_id),
        }
    }

    /// Rename and/or move the file or directory.
    async fn move_entry(
        &mut self,
        role: Role,
        entry_id: EntryId,
        new_parent_id: EntryId,
        new_name: &str,
    ) -> Result<()> {
        match self {
            FS::MemFs(fs) => fs.move_entry_sync(role, entry_id, new_parent_id, new_name),
            FS::MotorFs(motor_fs) => {
                motor_fs
                    .move_entry(role, entry_id, new_parent_id, new_name)
                    .await
            }
        }
    }

    async fn move_noreplace(
        &mut self,
        role: Role,
        entry_id: EntryId,
        new_parent_id: EntryId,
        new_name: &str,
    ) -> Result<()> {
        match self {
            FS::MemFs(fs) => fs.move_noreplace_sync(role, entry_id, new_parent_id, new_name),
            FS::MotorFs(motor_fs) => {
                motor_fs
                    .move_noreplace(role, entry_id, new_parent_id, new_name)
                    .await
            }
        }
    }

    /// Get the first entry in a directory.
    async fn get_first_entry(&self, role: Role, parent_id: EntryId) -> Result<Option<EntryId>> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.get_first_entry(role, parent_id).await,
            FS::MemFs(fs) => fs.get_first_entry_sync(role, parent_id),
        }
    }

    /// Get the next entry in a directory.
    async fn get_next_entry(&self, role: Role, entry_id: EntryId) -> Result<Option<EntryId>> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.get_next_entry(role, entry_id).await,
            FS::MemFs(fs) => fs.get_next_entry_sync(role, entry_id),
        }
    }

    /// Get the parent of the entry.
    async fn get_parent(&self, role: Role, entry_id: EntryId) -> Result<Option<EntryId>> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.get_parent(role, entry_id).await,
            FS::MemFs(fs) => fs.get_parent_sync(role, entry_id),
        }
    }

    /// Filename of the entry, without parent directories.
    async fn name(&self, role: Role, entry_id: EntryId) -> Result<String> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.name(role, entry_id).await,
            FS::MemFs(fs) => fs.name_sync(role, entry_id),
        }
    }

    /// The metadata of the directory entry.
    async fn metadata(&self, role: Role, entry_id: EntryId) -> Result<async_fs::Metadata> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.metadata(role, entry_id).await,
            FS::MemFs(fs) => fs.metadata_sync(role, entry_id),
        }
    }

    /// Read bytes from a file.
    /// Note that cross-block reads may not be supported.
    async fn read(
        &self,
        role: Role,
        file_id: EntryId,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.read(role, file_id, offset, buf).await,
            FS::MemFs(fs) => fs.read_sync(role, file_id, offset, buf),
        }
    }

    /// Write bytes to a file.
    /// Note that cross-block writes may not be supported.
    async fn write(
        &mut self,
        role: Role,
        file_id: EntryId,
        offset: u64,
        buf: &[u8],
    ) -> Result<usize> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.write(role, file_id, offset, buf).await,
            FS::MemFs(fs) => fs.write_sync(role, file_id, offset, buf),
        }
    }

    /// Resize the file.
    async fn resize(&mut self, role: Role, file_id: EntryId, new_size: u64) -> Result<()> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.resize(role, file_id, new_size).await,
            FS::MemFs(fs) => fs.resize_sync(role, file_id, new_size),
        }
    }

    /// Copies bytes from one file to another.
    async fn copy_file_range(
        &mut self,
        role: Role,
        from: EntryId,
        from_offset: u64,
        to: EntryId,
        to_offset: u64,
        size: u64,
    ) -> Result<u64> {
        match self {
            FS::MemFs(fs) => fs.copy_file_range_sync(role, from, from_offset, to, to_offset, size),
            FS::MotorFs(motor_fs) => {
                motor_fs
                    .copy_file_range(role, from, from_offset, to, to_offset, size)
                    .await
            }
        }
    }

    /// The total number of blocks in the FS.
    fn num_blocks(&self) -> u64 {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.num_blocks(),
            FS::MemFs(fs) => fs.num_blocks(),
        }
    }

    async fn empty_blocks(&self) -> Result<u64> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.empty_blocks().await,
            FS::MemFs(fs) => fs.empty_blocks_sync(),
        }
    }

    async fn flush(&mut self) -> Result<()> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.flush().await,
            FS::MemFs(fs) => fs.flush_sync(),
        }
    }
}

/// The FS runtime handle passed around the message handlers: the filesystem
/// plus its data-path stats. Cheap to clone (shared via `Rc`). Mirrors
/// `runtime::net::NetRuntime`.
#[derive(Clone)]
pub(crate) struct FsRuntime {
    mounts: Rc<RefCell<mounts::MountTable>>,
    pub(crate) free_caches: Rc<admission::FreeCaches>,
    entry_ids: Rc<entry_ids::EntryIds>,
    fs_stats: Rc<stats::FsStats>,
    locks: Rc<RefCell<lock_manager::LockManager<PendingLockResponse>>>,
    channel_budget: Rc<channel_budget::ChannelBudget>,
    exec_locks: Rc<RefCell<spawn::ExecLocks>>,
    spawn_stats: Rc<spawn::SpawnStats>,
    pager: Rc<spawn::pager::Pager>,
}

impl FsRuntime {
    fn resolve(&self, internal: EntryId) -> Result<mounts::Resolved> {
        mounts::Resolved::resolve(&self.mounts, internal)
    }

    fn decode(&self, wire: EntryId) -> Result<mounts::Resolved> {
        self.resolve(self.entry_ids.decode(wire))
    }

    pub(crate) fn root(&self) -> Result<mounts::Resolved> {
        mounts::Resolved::on_mount(&self.mounts, 0, async_fs::ROOT_ID)
    }

    pub(crate) async fn read_root_file(&self, path: &str) -> Result<Option<Vec<u8>>> {
        config::read_root_file(&self.mounts, path).await
    }

    fn admit_allocation(&self, command: u16, destination: &mounts::Resolved) -> Result<()> {
        if admission::needs_reserve(command, destination.kind) {
            self.free_caches.reserve(&self.fs_stats)?;
        }
        Ok(())
    }

    fn pressure_refused(&self) -> std::io::Error {
        self.fs_stats
            .pressure_refused
            .set(self.fs_stats.pressure_refused.get() + 1);
        ErrorKind::OutOfMemory.into()
    }
}

/// Every mutation of an executable that is being loaded or is mapped for
/// demand paging is refused; see `spawn::ExecLocks`.
/// Call with the FS write guard held: a writer queued behind spawn's metadata
/// reader must observe the construction lock acquired when that reader finishes.
fn refuse_if_executing(runtime: &FsRuntime, entry: EntryId) -> Result<()> {
    if !runtime.exec_locks.borrow().is_locked(entry) {
        return Ok(());
    }
    // Apply retirements already queued: a waited-for exit has queued its own.
    runtime.pager.drain();
    if runtime.exec_locks.borrow().is_locked(entry) {
        return Err(std::io::Error::from_raw_os_error(
            moto_rt::E_NOT_ALLOWED as i32,
        ));
    }
    Ok(())
}

struct PendingLockResponse {
    entry_id: EntryId,
    access: mounts::Resolved,
    connection_id: u64,
    open_id: u64,
    sender: channel_budget::ClientSender,
    response: moto_ipc::io_channel::Msg,
}

pub(super) async fn init(
    block_device: virtio_async::VirtioDevice,
    channel_budget: Rc<channel_budget::ChannelBudget>,
) -> Result<FsRuntime> {
    let block_device = virtio_async::BlockDevice::from(block_device)?;
    let fs_stats = Rc::new(stats::FsStats::default());

    use zerocopy::FromZeros;

    let first_block = moto_tooling::iobuf::IoBuf::new_from_size_align(4096).unwrap();
    let (first_block, res) =
        virtio_async::BlockDevice::post_read(block_device.clone(), 0, first_block)
            .await
            .await;
    res?;

    let mbr = mbr::Mbr::parse(&AsRef::<[u8]>::as_ref(&first_block)[..512]).map_err(|err| {
        log::error!("Mbr::parse() failed: {err:?}.");
        std::io::Error::from(ErrorKind::InvalidData)
    })?;

    // The boot-time MBR read has completed; all later I/O shares this owner.
    let (block_io, inbox) = moto_async::channel::channel(64);
    moto_async::LocalRuntime::spawn(block_io::run(block_device.clone(), inbox, fs_stats.clone()));
    let mut fs: Option<FS> = None;
    for pte in &mbr.entries {
        log::trace!("MBR PTE: {pte:?}");
        match pte.partition_type {
            mbr::PartitionType::FlatFs => {
                log::warn!("FlatFs is not (yet?) supported with async runtime");
            }
            mbr::PartitionType::SrFs => {
                log::warn!("SrFs is not (yet?) supported with async runtime");
            }
            mbr::PartitionType::MotorFs => {
                if fs.is_some() {
                    log::error!("Found more than one DATA partion.");
                    panic!();
                }

                let partition = Box::new(
                    virtio_partition::VirtioPartition::from_virtio_bd(
                        block_io.clone(),
                        block_device.flush_supported(),
                        pte.lba as u64,
                        pte.sectors as u64,
                    )
                    .await
                    .map_err(|err| {
                        log::error!("Mbr::parse() failed: {err:?}.");
                        std::io::Error::from(ErrorKind::InvalidData)
                    })?,
                );
                fs = Some(FS::MotorFs(
                    motor_fs::MotorFs::open_with_cache_size(partition, block_cache_blocks())
                        .await
                        .map_err(|err| {
                            log::error!("Mbr::parse() failed: {err:?}.");
                            std::io::Error::from(ErrorKind::InvalidData)
                        })?,
                ));
            }
            _ => continue,
        }
    }

    let Some(fs) = fs else {
        log::error!("Couldn't find a data partition.");
        return Err(std::io::Error::from(ErrorKind::InvalidData));
    };

    let mounts = Rc::new(RefCell::new(mounts::MountTable::new(fs)));
    let free_caches = Rc::new(admission::FreeCaches::default());
    config::load(&mounts, &free_caches)
        .await
        .unwrap_or_else(|err| {
            panic!("Cannot apply /system/cfg/sys-fs.toml: {err}");
        });

    let exec_locks: Rc<RefCell<spawn::ExecLocks>> = Default::default();
    let pager_notify = moto_sys::SysMem::pager_init()
        .map_err(|err| std::io::Error::from_raw_os_error(err as i32))?;
    let runtime = FsRuntime {
        mounts,
        free_caches,
        entry_ids: Rc::new(entry_ids::EntryIds::new()),
        fs_stats,
        locks: Default::default(),
        channel_budget,
        exec_locks: exec_locks.clone(),
        spawn_stats: Default::default(),
        pager: Rc::new(spawn::pager::Pager::new(exec_locks)),
    };
    moto_async::LocalRuntime::spawn(spawn::pager::run(runtime.clone(), pager_notify));

    spawn_fs_listeners(runtime.clone()).await;
    stats::spawn_stats_responder(runtime.clone());
    Ok(runtime)
}

async fn spawn_fs_listeners(runtime: FsRuntime) {
    const NUM_LISTENERS: usize = 8;
    for _ in 0..NUM_LISTENERS {
        spawn_new_listener(runtime.clone()).await;
    }
    // Note: we must not return until there is a started listener,
    //       otherwise the FS is not yet functional.
}

async fn spawn_new_listener(runtime: FsRuntime) {
    use std::sync::atomic::*;
    let (started_tx, started_rx) = moto_async::oneshot();

    moto_async::LocalRuntime::spawn(async move {
        if let Err(err) = fs_listener(runtime.clone(), started_tx).await {
            log::debug!("fs_listener() failed: {err:?}");
            spawn_new_listener(runtime).await;
        }
    });

    // Note: we must not return until there is a started listener,
    //       otherwise the FS is not yet functional.
    let _ = started_rx.await;
}

async fn fs_listener(
    runtime: FsRuntime,
    started_tx: moto_async::oneshot::Sender<()>,
) -> Result<()> {
    let mut listener = core::pin::pin!(moto_ipc::io_channel::listen(FS_URL));

    // Do a poll to ensure the listener has started listening.
    let (sender, mut receiver) = {
        let first_poll = core::future::poll_fn(|cx| match listener.as_mut().poll(cx) {
            std::task::Poll::Ready(res) => std::task::Poll::Ready(Some(res)),
            std::task::Poll::Pending => std::task::Poll::Ready(None),
        })
        .await;

        let _ = started_tx.send(());

        match first_poll {
            Some(res) => res,
            None => listener.await,
        }
        .map_err(|err| std::io::Error::from_raw_os_error(err as u16 as i32))?
    };

    // Note that if this function returns an error, it will be called again.
    // Thus to avoid spawning extra listeners, it must NOT return an error below,
    // after spawn_new_listener() is called.
    spawn_new_listener(runtime.clone()).await;

    // Under memory pressure a new client is refused.
    if runtime.free_caches.pressure() {
        runtime
            .fs_stats
            .pressure_refused_clients
            .set(runtime.fs_stats.pressure_refused_clients.get() + 1);
        log::debug!("FS: dropping new client under memory pressure.");
        return Ok(());
    }

    let (role, can_write, can_spawn) =
        match moto_sys::SysObj::get_capabilities(sender.remote_handle()) {
            Ok(capabilities) => (
                fs_role(capabilities),
                capabilities & moto_sys::caps::CAP_FS_WRITE != 0,
                capabilities & moto_sys::caps::CAP_SPAWN != 0,
            ),
            Err(err) => {
                log::warn!(
                    "FS: dropping client 0x{:x}: cannot query peer capabilities: {err:?}",
                    sender.remote_handle().as_u64()
                );
                return Ok(());
            }
        };

    // The wait-handle budget (see channel_budget): a channel past it would
    // eventually make the runtime thread's SysCpu::wait exceed the kernel's
    // handle cap, which is fatal. Dropped like the pressure refusal above;
    // the client's pending op fails with the channel error.
    let Ok(sender) = runtime.channel_budget.admit_fs(sender) else {
        log::debug!("FS: dropping new client: the channel budget is exhausted.");
        return Ok(());
    };

    // We want to process more than one message at at time (due to I/O waits), but
    // we don't want to have unlimited concurrency, we want backpressure.
    //
    // I tried to convert the receiver to a futures::Stream (via futures::stream::unfold()),
    // and then use futures::stream::for_each_concurrent, but this didn't work
    // with our runtime (maybe there is a bug in our runtime, maybe in for_each_concurrent).
    // (N.B.: futures::stream::for_each works).
    //
    // So we are using mpsc to implement "tickets".

    let (ticket_tx, mut ticket_rx) = moto_async::channel(MAX_IN_FLIGHT);
    // Pre-populate.
    for _ in 0..MAX_IN_FLIGHT {
        let _ = ticket_tx.send(()).await;
    }

    const IO_YIELD_BUDGET: u8 = 32;
    let mut requests_since_io = 0_u8;
    loop {
        let _ticket = ticket_rx.recv().await;

        // Now that we have a ticket, we can poll for msg.
        match receiver.recv().await {
            Ok(msg) => {
                moto_async::LocalRuntime::spawn(request_task(
                    msg,
                    sender.clone(),
                    runtime.clone(),
                    role,
                    can_write,
                    can_spawn,
                    ticket_tx.clone(),
                ));
                requests_since_io += 1;
                if requests_since_io == IO_YIELD_BUDGET {
                    requests_since_io = 0;
                    // Shared-memory replies can keep this client runnable forever.
                    // Poll kernel wakes so listeners and other clients also progress.
                    moto_async::yield_to_io().await;
                }
            }
            Err(_) => {
                let grants = runtime
                    .locks
                    .borrow_mut()
                    .disconnect(sender.remote_handle().as_u64());
                send_lock_grants(grants, &runtime).await;
                return Ok(());
            }
        }
    }
}

/// One request's task. frusa serves allocations up to 4 KiB from its slabs; a
/// larger task is mapped and unmapped for every request, so handler futures
/// must not hold big buffers across awaits (checked by a self-test).
async fn request_task(
    msg: moto_ipc::io_channel::Msg,
    sender: channel_budget::ClientSender,
    runtime: FsRuntime,
    role: Role,
    can_write: bool,
    can_spawn: bool,
    ticket_tx: moto_async::channel::Sender<()>,
) {
    on_msg(msg, sender, runtime, role, can_write, can_spawn).await;
    let _ = ticket_tx.send(()).await;
}

/// Freeing a held memfs ID is allowed under pressure. Resize's size-dependent
/// check happens under the very guard used to mutate, in its handler.
fn served_under_pressure(msg: &moto_ipc::io_channel::Msg, runtime: &FsRuntime) -> bool {
    // The decoder owns the operation-byte layout (it is infallible and
    // allocation-free); reading the byte directly here would be a second
    // copy of that layout.
    (msg.command == api_fs::CMD_FILE_LOCK
        && api_fs::file_lock_msg_decode(*msg)
            .is_ok_and(|(_, _, operation)| operation == moto_rt::fs::UNLOCK))
        || match msg.command {
            api_fs::CMD_DELETE_ENTRY => Some(api_fs::delete_entry_msg_decode(*msg)),
            api_fs::CMD_RESIZE => Some(api_fs::resize_msg_decode(*msg).0),
            _ => None,
        }
        .is_some_and(|entry_id| {
            runtime
                .decode(entry_id)
                .is_ok_and(|entry| entry.kind == api_fs::MountKind::MemFs)
        })
}

async fn on_msg(
    msg: moto_ipc::io_channel::Msg,
    sender: channel_budget::ClientSender,
    runtime: FsRuntime,
    role: Role,
    can_write: bool,
    can_spawn: bool,
) {
    // The capability gate, ahead of the pressure gate so that a forbidden
    // request is reported as such. It covers every lock operation and flush,
    // and frees donated pages for the same reason the pressure gate does.
    // Building a child takes the requester's spawn capability, which the
    // kernel would check only once the image is loaded.
    let forbidden =
        (!can_write && api_fs::known_cmd(msg.command) && !api_fs::is_read_command(msg.command))
            || (!can_spawn && msg.command == api_fs::CMD_SPAWN);
    if forbidden {
        api_fs::release_donated_pages(&msg, &sender);
        let resp = api_fs::empty_resp_encode(msg.id, Err(moto_rt::Error::NotAllowed));
        let _ = sender.send(resp).await;
        return;
    }

    // The memory-pressure gate. The gate itself does not allocate (a shared-
    // page load, a Cell bump, a POD response), though by this point the
    // message has already cost its spawned task in `fs_listener` -- bounded
    // transient work, MAX_IN_FLIGHT tickets per connection, the class the
    // floors absorb. Unrecognized commands fall through to the usual
    // InvalidData answer rather than inflating the refusal counter. Donated
    // pages must be freed here -- a handler releases them by decoding, which
    // never happens for a refused request, and the channel's page pool would
    // leak a slot per refusal.
    let pressured = api_fs::known_cmd(msg.command) && runtime.free_caches.pressure();
    if pressured && !served_under_pressure(&msg, &runtime) {
        api_fs::release_donated_pages(&msg, &sender);
        runtime
            .fs_stats
            .pressure_refused
            .set(runtime.fs_stats.pressure_refused.get() + 1);
        let resp = api_fs::empty_resp_encode(msg.id, Err(moto_rt::Error::OutOfMemory));
        let _ = sender.send(resp).await;
        return;
    }

    if let Err(err) = match msg.command {
        moto_sys_io::api_fs::CMD_STAT => on_cmd_stat(msg, &sender, runtime, role).await,
        moto_sys_io::api_fs::CMD_STAT_PATH => on_cmd_stat_path(msg, &sender, runtime, role).await,
        moto_sys_io::api_fs::CMD_CREATE_FILE => {
            on_cmd_create_file(msg, &sender, runtime, role).await
        }
        moto_sys_io::api_fs::CMD_CREATE_DIR => on_cmd_create_dir(msg, &sender, runtime, role).await,
        moto_sys_io::api_fs::CMD_CREATE_WITH_PERMISSIONS => {
            on_cmd_create_with_permissions(msg, &sender, runtime, role).await
        }
        moto_sys_io::api_fs::CMD_WRITE => on_cmd_write(msg, &sender, runtime, role).await,
        moto_sys_io::api_fs::CMD_READ => on_cmd_read(msg, &sender, runtime, role).await,
        moto_sys_io::api_fs::CMD_METADATA => on_cmd_metadata(msg, &sender, runtime, role).await,
        moto_sys_io::api_fs::CMD_SET_PERMISSIONS => {
            on_cmd_set_permissions(msg, &sender, runtime, role).await
        }
        moto_sys_io::api_fs::CMD_SET_ALL_PERMISSIONS => {
            on_cmd_set_all_permissions(msg, &sender, runtime, role).await
        }
        moto_sys_io::api_fs::CMD_RESIZE => {
            on_cmd_resize(msg, &sender, runtime, role, pressured).await
        }
        moto_sys_io::api_fs::CMD_DELETE_ENTRY => {
            on_cmd_delete_entry(msg, &sender, runtime, role, pressured).await
        }
        moto_sys_io::api_fs::CMD_FLUSH => on_cmd_flush(msg, &sender, runtime).await,
        moto_sys_io::api_fs::CMD_GET_FIRST_ENTRY => {
            on_cmd_get_first_entry(msg, &sender, runtime, role).await
        }
        moto_sys_io::api_fs::CMD_GET_NEXT_ENTRY => {
            on_cmd_get_next_entry(msg, &sender, runtime, role).await
        }
        moto_sys_io::api_fs::CMD_GET_NAME => on_cmd_get_name(msg, &sender, runtime, role).await,
        moto_sys_io::api_fs::CMD_MOVE_ENTRY => {
            on_cmd_move_entry(msg, &sender, runtime, role, true).await
        }
        moto_sys_io::api_fs::CMD_MOVE_NOREPLACE => {
            on_cmd_move_entry(msg, &sender, runtime, role, false).await
        }
        moto_sys_io::api_fs::CMD_COPY_FILE_RANGE => {
            on_cmd_copy_file_range(msg, &sender, runtime, role).await
        }
        moto_sys_io::api_fs::CMD_FILE_LOCK => on_cmd_file_lock(msg, &sender, runtime).await,
        moto_sys_io::api_fs::CMD_SPAWN => spawn::on_cmd_spawn(msg, &sender, runtime, role).await,
        api_fs::CMD_GET_MOUNTS => on_cmd_get_mounts(msg, &sender, runtime).await,

        cmd => {
            log::warn!("Unrecognized FS command: {cmd}.");
            Err(std::io::Error::from(ErrorKind::InvalidData))
        }
    } {
        let resp = api_fs::empty_resp_encode(msg.id, Err(map_err_into_native(err)));
        let _ = sender.send(resp).await;
    }
}

fn connection_is_disconnected(connection: u64) -> Result<bool> {
    match moto_sys::SysObj::is_connected(connection.into()) {
        Ok(connected) => Ok(!connected),
        Err(err) if err == moto_rt::E_BAD_HANDLE => Ok(true),
        Err(err) => Err(std::io::Error::from_raw_os_error(i32::from(err))),
    }
}

fn evict_disconnected_connections(
    entry: EntryId,
    mode: lock_manager::Mode,
    runtime: &FsRuntime,
) -> Result<()> {
    loop {
        let disconnected = runtime.locks.borrow().find_connection_if_contended(
            entry,
            mode,
            connection_is_disconnected,
        )?;
        let Some(connection) = disconnected else {
            return Ok(());
        };
        let grants = runtime.locks.borrow_mut().disconnect(connection);
        if !grants.is_empty() {
            // A try-lock request must not wait for another client to read its grant.
            let runtime = runtime.clone();
            moto_async::LocalRuntime::spawn(async move {
                send_lock_grants(grants, &runtime).await;
            });
        }
    }
}

async fn on_cmd_file_lock(
    msg: moto_ipc::io_channel::Msg,
    sender: &channel_budget::ClientSender,
    runtime: FsRuntime,
) -> Result<()> {
    use lock_manager::{Acquire, Mode};

    let request_id = msg.id;
    let (entry_id, open_id, operation) =
        api_fs::file_lock_msg_decode(msg).map_err(map_native_error)?;
    let connection_id = sender.remote_handle().as_u64();
    if operation == moto_rt::fs::UNLOCK {
        // Releasing touches only lock state, so it skips the quarantine gate:
        // a holder can still unlock, and queued waiters get the mount's error.
        let entry_id =
            mounts::canonical_unchecked(&runtime.mounts, runtime.entry_ids.decode(entry_id));
        let grants = runtime
            .locks
            .borrow_mut()
            .release(entry_id, connection_id, open_id)
            .map_err(|_| std::io::Error::from(ErrorKind::InvalidInput))?;
        // The waiters `release` just promoted must get their grants even if
        // the releaser's response cannot be sent (a client dying mid-`Drop`
        // is exactly that): dropping `grants` would leave the lock held by a
        // phantom owner and the waiters blocked forever.
        let responded = sender
            .send(api_fs::empty_resp_encode(request_id, Ok(())))
            .await;
        send_lock_grants(grants, &runtime).await;
        return responded.map_err(map_native_error);
    }
    let access = runtime.decode(entry_id)?;
    let entry_id = access.id;
    let (mode, blocking) = match operation {
        moto_rt::fs::LOCK_SHARED => (Mode::Shared, true),
        moto_rt::fs::LOCK_EXCLUSIVE => (Mode::Exclusive, true),
        moto_rt::fs::TRY_LOCK_SHARED => (Mode::Shared, false),
        moto_rt::fs::TRY_LOCK_EXCLUSIVE => (Mode::Exclusive, false),
        _ => return Err(ErrorKind::InvalidInput.into()),
    };
    evict_disconnected_connections(entry_id, mode, &runtime)?;
    // Do not yield between checking the peer and acquiring: a late request
    // must not recreate locks after its connection cleanup has run.
    if connection_is_disconnected(connection_id)? {
        return Err(ErrorKind::NotConnected.into());
    }
    let pending = PendingLockResponse {
        entry_id,
        access,
        connection_id,
        open_id,
        sender: sender.clone(),
        response: api_fs::empty_resp_encode(request_id, Ok(())),
    };
    let result = runtime.locks.borrow_mut().acquire(
        entry_id,
        connection_id,
        open_id,
        mode,
        blocking,
        pending,
    );
    match result {
        Acquire::Granted => {
            let response = sender
                .send(api_fs::empty_resp_encode(request_id, Ok(())))
                .await;
            if let Err(err) = response {
                let grants = runtime
                    .locks
                    .borrow_mut()
                    .release(entry_id, connection_id, open_id)
                    .expect("an immediate grant cannot have a pending acquisition");
                send_lock_grants(grants, &runtime).await;
                return Err(map_native_error(err));
            }
            Ok(())
        }
        Acquire::Queued => Ok(()),
        Acquire::WouldBlock => Err(ErrorKind::WouldBlock.into()),
        Acquire::AlreadyOwned(_) => Err(ErrorKind::InvalidInput.into()),
        Acquire::QueueFull(_) => Err(ErrorKind::OutOfMemory.into()),
    }
}

async fn send_lock_grants(mut grants: Vec<PendingLockResponse>, runtime: &FsRuntime) {
    while let Some(mut grant) = grants.pop() {
        let denied = if let Err(err) = grant.access.healthy() {
            grant.response =
                api_fs::empty_resp_encode(grant.response.id, Err(map_err_into_native(err)));
            true
        } else {
            false
        };
        if grant.sender.send(grant.response).await.is_err() || denied {
            grants.extend(
                runtime
                    .locks
                    .borrow_mut()
                    .release(grant.entry_id, grant.connection_id, grant.open_id)
                    .expect("granted lock cannot have a pending acquisition"),
            );
        }
    }
}

async fn on_cmd_stat(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let (parent_id, fname) = api_fs::stat_msg_decode(msg, sender).map_err(map_native_error)?;
    let parent = runtime.decode(parent_id)?;
    let parent_id = parent.local;
    let fs = parent.read().await?;
    let Some((entry_id, entry_kind)) =
        fs.stat(role, parent_id, fname.as_str())
            .await
            .map_err(|err| {
                log::warn!("fs.stat({role:?}, ) failed: {err:?}");
                err
            })?
    else {
        log::debug!("stat({parent_id}, {fname}): not found");
        return Err(std::io::Error::from(ErrorKind::NotFound));
    };
    let entry_id = parent.export(entry_id)?;
    core::mem::drop(fs);

    let resp = api_fs::stat_resp_encode(msg, runtime.entry_ids.encode(entry_id), entry_kind);
    sender.send(resp).await.map_err(map_native_error)
}

// The per-component permission checks are the same `fs.stat` calls the
// client would issue one round trip at a time.
async fn on_cmd_stat_path(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let path = api_fs::stat_path_msg_decode(msg, sender).map_err(map_native_error)?;
    let (entry_id, entry_kind) = mounts::stat_path(&runtime.mounts, role, &path).await?;

    let resp = api_fs::stat_resp_encode(msg, runtime.entry_ids.encode(entry_id), entry_kind);
    sender.send(resp).await.map_err(map_native_error)
}

async fn on_cmd_create_file(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let (parent_id, fname) =
        api_fs::create_entry_msg_decode(msg, sender).map_err(map_native_error)?;
    let parent = runtime.decode(parent_id)?;
    runtime.admit_allocation(msg.command, &parent)?;
    let parent_id = parent.local;
    let mut fs = parent.write().await?;
    let entry_id = fs
        .create_entry(
            role,
            parent_id,
            EntryKind::File,
            fname.as_str(),
            default_file_permissions(role),
        )
        .await
        .map_err(|err| {
            log::warn!("fs.create_entry({role:?}, ) failed: {err:?}");
            map_err_into_native(err)
        })
        .map_err(map_native_error)?;
    let entry_id = parent.export(entry_id)?;
    core::mem::drop(fs);
    log::debug!("created file {parent_id:x}:{fname} => {entry_id:x}");

    let resp = api_fs::stat_resp_encode(msg, runtime.entry_ids.encode(entry_id), EntryKind::File);
    sender.send(resp).await.map_err(map_native_error)
}

async fn on_cmd_create_with_permissions(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let (parent_id, kind, fname, raw_permissions) =
        api_fs::create_with_permissions_msg_decode(msg, sender).map_err(map_native_error)?;
    let parent = runtime.decode(parent_id)?;
    runtime.admit_allocation(msg.command, &parent)?;
    let parent_id = parent.local;
    let permissions = RolePermissions::new(
        raw_permissions[0].try_into()?,
        raw_permissions[1].try_into()?,
        raw_permissions[2].try_into()?,
    );

    let mut fs = parent.write().await?;
    let entry_id = fs
        .create_entry(role, parent_id, kind, fname.as_str(), permissions)
        .await
        .map_err(map_err_into_native)
        .map_err(map_native_error)?;
    let entry_id = parent.export(entry_id)?;
    core::mem::drop(fs);

    let resp = api_fs::stat_resp_encode(msg, runtime.entry_ids.encode(entry_id), kind);
    sender.send(resp).await.map_err(map_native_error)
}

async fn on_cmd_create_dir(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let (parent_id, fname) =
        api_fs::create_entry_msg_decode(msg, sender).map_err(map_native_error)?;
    let parent = runtime.decode(parent_id)?;
    runtime.admit_allocation(msg.command, &parent)?;
    let parent_id = parent.local;
    let mut fs = parent.write().await?;
    let entry_id = fs
        .create_entry(
            role,
            parent_id,
            EntryKind::Directory,
            fname.as_str(),
            default_directory_permissions(role),
        )
        .await
        .map_err(|err| {
            log::debug!("fs.create_entry({role:?}, ) failed: {err:?}");
            map_err_into_native(err)
        })
        .map_err(map_native_error)?;
    let entry_id = parent.export(entry_id)?;
    core::mem::drop(fs);
    log::debug!("created directory {parent_id:x}:{fname} => {entry_id:x}");

    let resp = api_fs::stat_resp_encode(
        msg,
        runtime.entry_ids.encode(entry_id),
        EntryKind::Directory,
    );
    sender.send(resp).await.map_err(map_native_error)
}

fn default_file_permissions(role: Role) -> RolePermissions {
    match role {
        Role::System => RolePermissions::new(
            AccessPermissions::Rw,
            AccessPermissions::R,
            AccessPermissions::R,
        ),
        Role::Interactive => RolePermissions::new(
            AccessPermissions::Rwx,
            AccessPermissions::Rw,
            AccessPermissions::R,
        ),
        Role::None => RolePermissions::new(
            AccessPermissions::Rwx,
            AccessPermissions::Rwx,
            AccessPermissions::Rw,
        ),
    }
}

fn default_directory_permissions(role: Role) -> RolePermissions {
    match role {
        Role::System => RolePermissions::new(
            AccessPermissions::Rwx,
            AccessPermissions::Rx,
            AccessPermissions::Rx,
        ),
        Role::Interactive => RolePermissions::new(
            AccessPermissions::Rwx,
            AccessPermissions::Rwx,
            AccessPermissions::Rx,
        ),
        Role::None => RolePermissions::all(AccessPermissions::Rwx),
    }
}

async fn on_cmd_write(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    // Multi-page write requests carry the total length in `flags`; classic
    // single-page requests never set it. See `api_fs::write_multi_msg_encode`.
    if msg.flags != 0 {
        return on_cmd_write_multi(msg, sender, runtime, role).await;
    }

    let (file_id, offset, len, io_page) =
        api_fs::write_msg_decode(msg, sender).map_err(map_native_error)?;
    let file = runtime.decode(file_id)?;

    // `len` comes from the (untrusted) client; reject anything that does not
    // fit into an io_page instead of panicking on the slice below.
    if len as usize > moto_ipc::io_channel::PAGE_SIZE {
        return Err(std::io::Error::from(ErrorKind::InvalidInput));
    }

    runtime.admit_allocation(msg.command, &file)?;
    let mut fs = file.write().await?;
    refuse_if_executing(&runtime, file.id)?;
    let written = fs
        .write(role, file.local, offset, &io_page.bytes()[..(len as usize)])
        .await?;
    assert_eq!(written, len as usize);
    core::mem::drop(fs);

    let resp = api_fs::empty_resp_encode(msg.id, Ok(()));
    let _ = sender.send(resp).await;
    runtime
        .fs_stats
        .write_msgs
        .set(runtime.fs_stats.write_msgs.get() + 1);
    Ok(())
}

/// A write request spanning several io_pages, decoded by
/// `api_fs::write_multi_msg_decode`: the fixed per-message cost (decode,
/// lock acquire, response send + wake) is paid once per up to 32K instead of
/// once per 4K. Page i holds chunk i of `api_fs::io_chunks(offset, len)`, so
/// no chunk crosses an FS block boundary. The response carries the number of
/// bytes actually written; a short count means a later chunk was cut short
/// or failed after earlier chunks were written.
async fn on_cmd_write_multi(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let (file_id, offset, len, pages) =
        api_fs::write_multi_msg_decode(msg, sender).map_err(map_native_error)?;
    let file = runtime.decode(file_id)?;
    runtime.admit_allocation(msg.command, &file)?;

    // One FS lock acquire for the whole message. The decode above recovered
    // every page, so all paths below free them on drop.
    let mut total = 0_u32;
    {
        let mut fs_guard = file.write().await?;
        refuse_if_executing(&runtime, file.id)?;
        let mut chunk_offset = offset;
        for (io_page, size) in pages.iter().zip(api_fs::io_chunks(offset, len)) {
            match fs_guard
                .write(role, file.local, chunk_offset, &io_page.bytes()[..size])
                .await
            {
                Ok(written) => {
                    total += written as u32;
                    chunk_offset += written as u64;
                    if written < size {
                        break;
                    }
                }
                Err(err) => {
                    if total == 0 {
                        return Err(err); // on_msg sends the error response.
                    }
                    // Chunks already written stay written: report the short
                    // count; the client stops there, and a retry of the rest
                    // hits the error with total == 0.
                    break;
                }
            }
        }
    }

    let resp = api_fs::write_multi_resp_encode(msg.id, total);
    let _ = sender.send(resp).await;
    runtime
        .fs_stats
        .write_msgs
        .set(runtime.fs_stats.write_msgs.get() + 1);
    Ok(())
}

async fn on_cmd_read(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let started = stats::now_ticks();
    let (file_id, offset, len) = api_fs::read_msg_decode(msg);
    let file = runtime.decode(file_id)?;

    // Requests spanning more than one io_page get a multi-page response;
    // see `api_fs::READ_MAX_PAGES`.
    if len as usize > moto_ipc::io_channel::PAGE_SIZE {
        return on_cmd_read_multi(msg, sender, runtime, role, file, offset, len).await;
    }

    let io_page = sender
        .alloc_page(u64::MAX)
        .await
        .map_err(map_native_error)?;

    let fs_guard = file.read().await?;
    let read = fs_guard
        .read(
            role,
            file.local,
            offset,
            &mut io_page.bytes_mut()[..(len as usize)],
        )
        .await?;
    core::mem::drop(fs_guard);

    let resp = api_fs::read_resp_encode(msg.id, read as u16, io_page);
    let _ = sender.send(resp).await;

    runtime
        .fs_stats
        .read_msgs
        .set(runtime.fs_stats.read_msgs.get() + 1);
    if stats::TIMINGS {
        let elapsed = stats::now_ticks().wrapping_sub(started);
        runtime
            .fs_stats
            .read_ticks
            .set(runtime.fs_stats.read_ticks.get() + elapsed);
    }

    maybe_readahead(runtime, file, offset, read);
    Ok(())
}

/// A read request spanning several io_pages, answered with one multi-page
/// response (see `api_fs::read_multi_resp_encode`): the fixed per-message
/// cost is paid once per up to 48K instead of once per 4K. Chunk sizes are
/// deterministic from (offset, len) — `api_fs::io_chunks` — so the client
/// reassembles without extra metadata. On early EOF the response carries
/// fewer pages than requested; `total_len` is authoritative.
async fn on_cmd_read_multi(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
    file: mounts::Resolved,
    offset: u64,
    len: u16,
) -> Result<()> {
    let started = stats::now_ticks();

    // `len`/`offset` come from the (untrusted) client: reject anything
    // spanning more chunks than a response can carry.
    if len as usize > api_fs::READ_MAX_BYTES {
        return Err(std::io::Error::from(ErrorKind::InvalidInput));
    }
    let mut chunk_sizes = [0_usize; api_fs::READ_MAX_PAGES];
    let mut num_chunks = 0_usize;
    for chunk in api_fs::io_chunks(offset, len as u32) {
        if num_chunks == api_fs::READ_MAX_PAGES {
            return Err(std::io::Error::from(ErrorKind::InvalidInput));
        }
        chunk_sizes[num_chunks] = chunk;
        num_chunks += 1;
    }

    // Reserve the whole response atomically: concurrent responses must not
    // each hold a partial allocation and exhaust the finite page pool.
    let mut pages = sender
        .alloc_pages(num_chunks, u64::MAX)
        .await
        .map_err(map_native_error)?;
    let mut total = 0_u32;
    {
        let fs_guard = file.read().await?;
        let mut chunk_offset = offset;
        for (&size, io_page) in chunk_sizes[..num_chunks].iter().zip(&pages) {
            file.healthy()?;
            let read = fs_guard
                .read(
                    role,
                    file.local,
                    chunk_offset,
                    &mut io_page.bytes_mut()[..size],
                )
                .await?; // On error: `pages` drops, freeing them; on_msg sends the error response.
            total += read as u32;
            chunk_offset += read as u64;
            if read < size {
                break; // EOF.
            }
        }
    }

    // Free the pages the data didn't reach (EOF), including a trailing
    // zero-byte one.
    let mut needed = 0_usize;
    let mut accounted = 0_u32;
    while accounted < total {
        accounted += (chunk_sizes[needed] as u32).min(total - accounted);
        needed += 1;
    }
    pages.truncate(needed);

    let resp = api_fs::read_multi_resp_encode(msg.id, total, pages);
    let _ = sender.send(resp).await;

    runtime
        .fs_stats
        .read_msgs
        .set(runtime.fs_stats.read_msgs.get() + 1);
    if stats::TIMINGS {
        let elapsed = stats::now_ticks().wrapping_sub(started);
        runtime
            .fs_stats
            .read_ticks
            .set(runtime.fs_stats.read_ticks.get() + elapsed);
    }

    // Fully-satisfied block-aligned reads are streaming: prefetch past the
    // end of this message's window (the cursor + cached-window probe make
    // the per-message trigger cheap).
    let end = offset + total as u64;
    if total == len as u32 && end.is_multiple_of(async_fs::BLOCK_SIZE as u64) {
        spawn_readahead(runtime, file, end / async_fs::BLOCK_SIZE as u64);
    }
    Ok(())
}

/// Sequential readahead: full-block reads are the signature of streaming
/// (e.g. the VDSO loading a binary; moto-io splits large reads into
/// block-sized chunks). On every 16th file block, prefetch the 32 blocks past
/// the current 16-block window into the block cache in the background.
/// Duplicate device reads with foreground requests are impossible: the block
/// cache deduplicates concurrent reads of the same block.
fn maybe_readahead(runtime: FsRuntime, file: mounts::Resolved, offset: u64, read: usize) {
    const TRIGGER_WINDOW: u64 = 16; // Matches the moto-io read batch size.

    if read != async_fs::BLOCK_SIZE || !offset.is_multiple_of(async_fs::BLOCK_SIZE as u64) {
        return;
    }
    let block_key = offset / (async_fs::BLOCK_SIZE as u64);
    if !block_key.is_multiple_of(TRIGGER_WINDOW) {
        return;
    }

    spawn_readahead(runtime, file, block_key + TRIGGER_WINDOW);
}

fn spawn_readahead(runtime: FsRuntime, file: mounts::Resolved, first: u64) {
    if file.kind != api_fs::MountKind::MotorFs {
        return;
    }
    runtime
        .fs_stats
        .readahead_spawns
        .set(runtime.fs_stats.readahead_spawns.get() + 1);
    moto_async::LocalRuntime::spawn(async move {
        let Ok(fs) = file.read().await else {
            return;
        };
        fs.prefetch(file.local, first, READAHEAD_BLOCKS).await;
    });
}

async fn on_cmd_metadata(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let entry_id = api_fs::metadata_msg_decode(msg);
    let entry = runtime.decode(entry_id)?;
    let fs = entry.read().await?;
    let metadata = fs.metadata(role, entry.local).await?;
    // A full response-page pool must not block filesystem writers.
    core::mem::drop(fs);

    let io_page = sender
        .alloc_page(u64::MAX)
        .await
        .map_err(map_native_error)?;
    let resp = api_fs::metadata_resp_encode(msg.id, metadata, io_page);
    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_set_permissions(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let (entry_id, raw_access) = api_fs::set_permissions_msg_decode(msg);
    let entry = runtime.decode(entry_id)?;
    let access = AccessPermissions::try_from(raw_access)?;

    let mut fs = entry.write().await?;
    refuse_if_executing(&runtime, entry.id)?;
    let resp = api_fs::empty_resp_encode(
        msg.id,
        fs.set_permissions(role, entry.local, role, access)
            .await
            .map_err(map_err_into_native),
    );
    core::mem::drop(fs);

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_set_all_permissions(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let (entry_id, raw_permissions) = api_fs::set_all_permissions_msg_decode(msg);
    let entry = runtime.decode(entry_id)?;
    let permissions = RolePermissions::new(
        raw_permissions[0].try_into()?,
        raw_permissions[1].try_into()?,
        raw_permissions[2].try_into()?,
    );

    let mut fs = entry.write().await?;
    refuse_if_executing(&runtime, entry.id)?;
    let resp = api_fs::empty_resp_encode(
        msg.id,
        fs.set_all_permissions(role, entry.local, permissions)
            .await
            .map_err(map_err_into_native),
    );
    core::mem::drop(fs);

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_resize(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
    pressured: bool,
) -> Result<()> {
    let (file_id, new_size) = api_fs::resize_msg_decode(msg);
    let file = runtime.decode(file_id)?;
    let mut fs = file.write().await?;
    refuse_if_executing(&runtime, file.id)?;
    if pressured
        && (file.kind != api_fs::MountKind::MemFs
            || new_size > fs.metadata(role, file.local).await?.size)
    {
        return Err(runtime.pressure_refused());
    }
    let resp = api_fs::empty_resp_encode(
        msg.id,
        fs.resize(role, file.local, new_size)
            .await
            .map_err(map_err_into_native),
    );
    core::mem::drop(fs);
    if pressured {
        runtime.free_caches.reclaim();
    }

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_delete_entry(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
    pressured: bool,
) -> Result<()> {
    let entry_id = api_fs::delete_entry_msg_decode(msg);
    let entry = runtime.decode(entry_id)?;
    entry.protect_root()?;
    let mut fs = entry.write().await?;
    refuse_if_executing(&runtime, entry.id)?;
    let resp = api_fs::empty_resp_encode(
        msg.id,
        fs.delete_entry(role, entry.local)
            .await
            .map_err(map_err_into_native),
    );
    core::mem::drop(fs);
    if pressured {
        runtime.free_caches.reclaim();
    }

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_flush(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    let resp = api_fs::empty_resp_encode(
        msg.id,
        mounts::flush(&runtime.mounts)
            .await
            .map_err(map_err_into_native),
    );

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_get_first_entry(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let parent_id = api_fs::get_first_entry_req_decode(msg);
    let parent = runtime.decode(parent_id)?;
    let fs = parent.read().await?;
    let entry_id = fs
        .get_first_entry(role, parent.local)
        .await?
        .map(|local| parent.export(local))
        .transpose()?;
    core::mem::drop(fs);
    let resp =
        api_fs::get_first_entry_resp_encode(msg, entry_id.map(|id| runtime.entry_ids.encode(id)));

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_get_next_entry(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let entry_id = api_fs::get_next_entry_req_decode(msg);
    let entry = runtime.decode(entry_id)?.namespace_entry()?;
    let fs = entry.read().await?;
    let next_entry_id = fs
        .get_next_entry(role, entry.local)
        .await?
        .map(|local| entry.export(local))
        .transpose()?;
    core::mem::drop(fs);
    let resp = api_fs::get_next_entry_resp_encode(
        msg,
        next_entry_id.map(|id| runtime.entry_ids.encode(id)),
    );

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_get_name(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let entry_id = api_fs::get_name_req_decode(msg);
    let entry = runtime.decode(entry_id)?.namespace_entry()?;
    let fs = entry.read().await?;
    let name = fs.name(role, entry.local).await?;
    core::mem::drop(fs);
    if name.len() > moto_rt::fs::MAX_FILENAME_LEN {
        return Err(std::io::ErrorKind::InvalidData.into());
    }

    let io_page = sender
        .alloc_page(u64::MAX)
        .await
        .map_err(map_native_error)?;

    let resp = api_fs::get_name_resp_encode(msg.id, name.as_str(), io_page);

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_move_entry(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
    replace: bool,
) -> Result<()> {
    let (entry_id, new_parent_id, fname) =
        api_fs::move_entry_req_decode(msg, sender).map_err(map_native_error)?;
    let entry_id = runtime.entry_ids.decode(entry_id);
    let new_parent_id = runtime.entry_ids.decode(new_parent_id);

    let result = move_entry(&runtime, role, entry_id, new_parent_id, &fname, replace).await;
    let resp = api_fs::empty_resp_encode(msg.id, result.map_err(map_err_into_native));

    let _ = sender.send(resp).await;
    Ok(())
}

async fn check_replacement(
    runtime: &FsRuntime,
    parent: &mounts::Resolved,
    fs: &FS,
    name: &str,
) -> Result<()> {
    // The backends replace with only `w` on the directory, so the protections
    // must not depend on traverse rights either.
    if let Some((local, _)) = fs.lookup_unchecked(parent.local, name).await? {
        let replaced = runtime.resolve(parent.export(local)?)?;
        replaced.protect_root()?;
        refuse_if_executing(runtime, replaced.id)?;
    }
    Ok(())
}

async fn move_entry(
    runtime: &FsRuntime,
    role: Role,
    entry: EntryId,
    parent: EntryId,
    name: &str,
    replace: bool,
) -> Result<()> {
    let entry = runtime.resolve(entry)?;
    let parent = runtime.resolve(parent)?;
    entry.protect_root()?;
    if entry.mount != parent.mount {
        // Root protection precedes CrossesDevices, including the destination.
        if replace {
            let fs = parent.read().await?;
            check_replacement(runtime, &parent, &fs, name).await?;
        }
        return Err(ErrorKind::CrossesDevices.into());
    }
    runtime.admit_allocation(
        if replace {
            api_fs::CMD_MOVE_ENTRY
        } else {
            api_fs::CMD_MOVE_NOREPLACE
        },
        &parent,
    )?;
    let mut fs = entry.write().await?;
    parent.healthy()?;
    refuse_if_executing(runtime, entry.id)?;
    if replace {
        check_replacement(runtime, &parent, &fs, name).await?;
        fs.move_entry(role, entry.local, parent.local, name).await
    } else {
        fs.move_noreplace(role, entry.local, parent.local, name)
            .await
    }
}

async fn on_cmd_copy_file_range(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
    role: Role,
) -> Result<()> {
    let (from, to, offset, size) = api_fs::copy_file_range_req_decode(msg);
    let from = runtime.entry_ids.decode(from);
    let to = runtime.entry_ids.decode(to);

    // In this implementation, from_offset == to_offset.
    let copied = copy_file_range(&runtime, role, from, offset, to, offset, size).await?;

    let resp = api_fs::copy_file_range_resp_encode(msg.id, copied);
    let _ = sender.send(resp).await;
    Ok(())
}

async fn copy_file_range(
    runtime: &FsRuntime,
    role: Role,
    from: EntryId,
    from_offset: u64,
    to: EntryId,
    to_offset: u64,
    size: u64,
) -> Result<u64> {
    let from = runtime.resolve(from)?;
    let to = runtime.resolve(to)?;
    runtime.admit_allocation(api_fs::CMD_COPY_FILE_RANGE, &to)?;
    let size = size.min(api_fs::WRITE_MAX_BYTES as u64);
    from_offset
        .checked_add(size)
        .ok_or(ErrorKind::InvalidInput)?;
    to_offset.checked_add(size).ok_or(ErrorKind::InvalidInput)?;
    if from.mount == to.mount {
        let mut fs = to.write().await?;
        from.healthy()?;
        refuse_if_executing(runtime, to.id)?;
        return fs
            .copy_file_range(role, from.local, from_offset, to.local, to_offset, size)
            .await;
    }
    // On the heap: a stack buffer would grow every request's task.
    let mut buffer = spawn::try_zeroed(async_fs::BLOCK_SIZE)?;
    let block = async_fs::BLOCK_SIZE as u64;
    let mut copied = 0;
    while copied < size {
        let src = from_offset + copied;
        let dst = to_offset + copied;
        let chunk = (size - copied)
            .min(block - src % block)
            .min(block - dst % block) as usize;
        let result = async {
            let read = {
                let fs = from.read().await?;
                fs.read(role, from.local, src, &mut buffer[..chunk]).await?
            };
            if read == 0 {
                // The source ended: an empty write could still grow or
                // allocate in the destination.
                return Ok(0);
            }
            let mut fs = to.write().await?;
            refuse_if_executing(runtime, to.id)?;
            fs.write(role, to.local, dst, &buffer[..read]).await
        }
        .await;
        match result {
            Ok(written) => {
                copied += written as u64;
                if written < chunk {
                    break;
                }
            }
            Err(err) => {
                if copied == 0 {
                    return Err(err);
                }
                break;
            }
        }
    }
    Ok(copied)
}

async fn on_cmd_get_mounts(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    let cursor = api_fs::get_mounts_req_decode(msg).map_err(map_native_error)?;
    let info = mounts::info(&runtime.mounts, cursor).await?;
    let next = if cursor as usize + 1 == runtime.mounts.borrow().iter().count() {
        api_fs::MOUNTS_END
    } else {
        cursor + 1
    };
    let page = sender
        .alloc_page(u64::MAX)
        .await
        .map_err(map_native_error)?;
    let response =
        api_fs::get_mounts_resp_encode(msg.id, &info, next, page).map_err(map_native_error)?;
    sender.send(response).await.map_err(map_native_error)
}
