use async_fs::AccessPermissions;
use async_fs::EntryId;
use async_fs::Role;
use async_fs::{EntryKind, FileSystem};
use async_trait::async_trait;
use moto_async::{AsFuture, LocalRwLock};
use moto_sys_io::api_fs;
use moto_sys_io::api_fs::FS_URL;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::io::Result;
use std::rc::Rc;

use crate::runtime::fs::virtio_partition::VirtioPartition;
use crate::util::map_err_into_native;
use crate::util::map_native_error;

mod lock_manager;
mod mbr;
pub mod stats;
mod virtio_partition;

/// The max number of "requests" in flight per connection.
const MAX_IN_FLIGHT: usize = 64;

/// How far sequential readahead prefetches past the current read (in 4K
/// blocks). See `maybe_readahead` and `on_cmd_read_multi`.
const READAHEAD_BLOCKS: u64 = 32;

// We allow(private_interfaces) to hide a warning that VirtioPartition
// has less visibility than enum FS, which is by design: the enum
// has crate visibility to allow internal/async FS access, but
// VirtioPartition is an internal detail of mod fs.
#[allow(private_interfaces)]
pub(crate) enum FS {
    MotorFs(motor_fs::MotorFs<VirtioPartition>),
}

impl FS {
    /// Best-effort readahead; see [`motor_fs::MotorFs::prefetch`].
    async fn prefetch(&self, file_id: EntryId, first_key: u64, count: u64) {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.prefetch(file_id, first_key, count).await,
        }
    }

    /// Block cache hit/miss/dedup counters. Diagnostics only.
    fn cache_stats(&self) -> async_fs::block_cache::BlockCacheStats {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.cache_stats(),
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
        }
    }

    /// Create a file or directory.
    async fn create_entry(
        &mut self,
        role: Role,
        parent_id: EntryId,
        kind: EntryKind,
        name: &str, // Leaf name.
        perms: [AccessPermissions; 3],
    ) -> Result<EntryId> {
        match self {
            FS::MotorFs(motor_fs) => {
                motor_fs
                    .create_entry(role, parent_id, kind, name, perms)
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
            FS::MotorFs(motor_fs) => {
                motor_fs
                    .set_permissions(caller, entry_id, target, access)
                    .await
            }
        }
    }

    /// Delete the file or directory.
    async fn delete_entry(&mut self, role: Role, entry_id: EntryId) -> Result<()> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.delete_entry(role, entry_id).await,
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
            FS::MotorFs(motor_fs) => {
                motor_fs
                    .move_entry(role, entry_id, new_parent_id, new_name)
                    .await
            }
        }
    }

    /// Get the first entry in a directory.
    async fn get_first_entry(&self, role: Role, parent_id: EntryId) -> Result<Option<EntryId>> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.get_first_entry(role, parent_id).await,
        }
    }

    /// Get the next entry in a directory.
    async fn get_next_entry(&self, role: Role, entry_id: EntryId) -> Result<Option<EntryId>> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.get_next_entry(role, entry_id).await,
        }
    }

    /// Get the parent of the entry.
    async fn get_parent(&self, role: Role, entry_id: EntryId) -> Result<Option<EntryId>> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.get_parent(role, entry_id).await,
        }
    }

    /// Filename of the entry, without parent directories.
    async fn name(&self, role: Role, entry_id: EntryId) -> Result<String> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.name(role, entry_id).await,
        }
    }

    /// The metadata of the directory entry.
    async fn metadata(&self, role: Role, entry_id: EntryId) -> Result<async_fs::Metadata> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.metadata(role, entry_id).await,
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
        }
    }

    /// Resize the file.
    async fn resize(&mut self, role: Role, file_id: EntryId, new_size: u64) -> Result<()> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.resize(role, file_id, new_size).await,
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
        }
    }

    async fn empty_blocks(&self) -> Result<u64> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.empty_blocks().await,
        }
    }

    async fn flush(&mut self) -> Result<()> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.flush().await,
        }
    }
}

/// The FS runtime handle passed around the message handlers: the filesystem
/// plus its data-path stats. Cheap to clone (two `Rc`s). Mirrors
/// `runtime::net::NetRuntime`.
#[derive(Clone)]
pub(crate) struct FsRuntime {
    fs: Rc<LocalRwLock<FS>>,
    fs_stats: Rc<stats::FsStats>,
    locks: Rc<RefCell<lock_manager::LockManager<PendingLockResponse>>>,
}

struct PendingLockResponse {
    entry_id: EntryId,
    connection_id: u64,
    open_id: u64,
    sender: moto_ipc::io_channel::Sender,
    response: moto_ipc::io_channel::Msg,
}

pub(super) async fn init(block_device: virtio_async::VirtioDevice) -> Result<Rc<LocalRwLock<FS>>> {
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

    let mut fs: Option<Rc<LocalRwLock<FS>>> = None;
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
                        block_device.clone(),
                        pte.lba as u64,
                        pte.sectors as u64,
                        fs_stats.clone(),
                    )
                    .await
                    .map_err(|err| {
                        log::error!("Mbr::parse() failed: {err:?}.");
                        std::io::Error::from(ErrorKind::InvalidData)
                    })?,
                );
                fs = Some(Rc::new(LocalRwLock::new(FS::MotorFs(
                    motor_fs::MotorFs::open(partition).await.map_err(|err| {
                        log::error!("Mbr::parse() failed: {err:?}.");
                        std::io::Error::from(ErrorKind::InvalidData)
                    })?,
                ))));
            }
            _ => continue,
        }
    }

    let Some(fs) = fs else {
        log::error!("Couldn't find a data partition.");
        return Err(std::io::Error::from(ErrorKind::InvalidData));
    };

    let runtime = FsRuntime {
        fs: fs.clone(),
        fs_stats,
        locks: Default::default(),
    };
    spawn_fs_listeners(runtime.clone()).await;
    stats::spawn_stats_responder(runtime);
    Ok(fs)
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

    loop {
        let _ticket = ticket_rx.recv().await;

        // Now that we have a ticket, we can poll for msg.
        match receiver.recv().await {
            Ok(msg) => {
                let sender = sender.clone();
                let runtime = runtime.clone();
                let ticket_tx = ticket_tx.clone();
                moto_async::LocalRuntime::spawn(async move {
                    on_msg(msg, sender, runtime).await;
                    let _ = ticket_tx.send(()).await;
                });
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

async fn on_msg(
    msg: moto_ipc::io_channel::Msg,
    sender: moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) {
    if let Err(err) = match msg.command {
        moto_sys_io::api_fs::CMD_STAT => on_cmd_stat(msg, &sender, runtime).await,
        moto_sys_io::api_fs::CMD_CREATE_FILE => on_cmd_create_file(msg, &sender, runtime).await,
        moto_sys_io::api_fs::CMD_CREATE_DIR => on_cmd_create_dir(msg, &sender, runtime).await,
        moto_sys_io::api_fs::CMD_WRITE => on_cmd_write(msg, &sender, runtime).await,
        moto_sys_io::api_fs::CMD_READ => on_cmd_read(msg, &sender, runtime).await,
        moto_sys_io::api_fs::CMD_METADATA => on_cmd_metadata(msg, &sender, runtime).await,
        moto_sys_io::api_fs::CMD_SET_PERMISSIONS => {
            on_cmd_set_permissions(msg, &sender, runtime).await
        }
        moto_sys_io::api_fs::CMD_RESIZE => on_cmd_resize(msg, &sender, runtime).await,
        moto_sys_io::api_fs::CMD_DELETE_ENTRY => on_cmd_delete_entry(msg, &sender, runtime).await,
        moto_sys_io::api_fs::CMD_FLUSH => on_cmd_flush(msg, &sender, runtime).await,
        moto_sys_io::api_fs::CMD_GET_FIRST_ENTRY => {
            on_cmd_get_first_entry(msg, &sender, runtime).await
        }
        moto_sys_io::api_fs::CMD_GET_NEXT_ENTRY => {
            on_cmd_get_next_entry(msg, &sender, runtime).await
        }
        moto_sys_io::api_fs::CMD_GET_NAME => on_cmd_get_name(msg, &sender, runtime).await,
        moto_sys_io::api_fs::CMD_MOVE_ENTRY => on_cmd_move_entry(msg, &sender, runtime).await,
        moto_sys_io::api_fs::CMD_COPY_FILE_RANGE => {
            on_cmd_copy_file_range(msg, &sender, runtime).await
        }
        moto_sys_io::api_fs::CMD_FILE_LOCK => on_cmd_file_lock(msg, &sender, runtime).await,

        cmd => {
            log::warn!("Unrecognized FS command: {cmd}.");
            Err(std::io::Error::from(ErrorKind::InvalidData))
        }
    } {
        let resp = api_fs::empty_resp_encode(msg.id, Err(map_err_into_native(err)));
        let _ = sender.send(resp).await;
    }
}

async fn on_cmd_file_lock(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    use lock_manager::{Acquire, Mode};

    let request_id = msg.id;
    let (entry_id, open_id, operation) =
        api_fs::file_lock_msg_decode(msg).map_err(map_native_error)?;
    let connection_id = sender.remote_handle().as_u64();
    if operation == moto_rt::fs::UNLOCK {
        let grants = runtime
            .locks
            .borrow_mut()
            .release(entry_id, connection_id, open_id)
            .map_err(|_| std::io::Error::from(ErrorKind::InvalidInput))?;
        sender
            .send(api_fs::empty_resp_encode(request_id, Ok(())))
            .await
            .map_err(map_native_error)?;
        send_lock_grants(grants, &runtime).await;
        return Ok(());
    }
    let (mode, blocking) = match operation {
        moto_rt::fs::LOCK_SHARED => (Mode::Shared, true),
        moto_rt::fs::LOCK_EXCLUSIVE => (Mode::Exclusive, true),
        moto_rt::fs::TRY_LOCK_SHARED => (Mode::Shared, false),
        moto_rt::fs::TRY_LOCK_EXCLUSIVE => (Mode::Exclusive, false),
        _ => return Err(ErrorKind::InvalidInput.into()),
    };
    let pending = PendingLockResponse {
        entry_id,
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
        Acquire::Granted => sender
            .send(api_fs::empty_resp_encode(request_id, Ok(())))
            .await
            .map_err(map_native_error),
        Acquire::Queued => Ok(()),
        Acquire::WouldBlock => Err(ErrorKind::WouldBlock.into()),
        Acquire::AlreadyOwned(_) => Err(ErrorKind::InvalidInput.into()),
        Acquire::QueueFull(_) => Err(ErrorKind::OutOfMemory.into()),
    }
}

async fn send_lock_grants(mut grants: Vec<PendingLockResponse>, runtime: &FsRuntime) {
    while let Some(grant) = grants.pop() {
        if grant.sender.send(grant.response).await.is_err() {
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
) -> Result<()> {
    let (parent_id, fname) = api_fs::stat_msg_decode(msg, sender).map_err(map_native_error)?;

    let fs = runtime.fs.read().await;
    let Some((entry_id, entry_kind)) = fs
        .stat(Role::System, parent_id, fname.as_str())
        .await
        .map_err(|err| {
            log::warn!("fs.stat(Role::System, ) failed: {err:?}");
            err
        })?
    else {
        log::debug!("stat({parent_id}, {fname}): not found");
        return Err(std::io::Error::from(ErrorKind::NotFound));
    };
    core::mem::drop(fs);

    let resp = api_fs::stat_resp_encode(msg, entry_id, entry_kind);
    sender.send(resp).await.map_err(map_native_error)
}

async fn on_cmd_create_file(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    let (parent_id, fname) =
        api_fs::create_entry_msg_decode(msg, sender).map_err(map_native_error)?;

    let mut fs = runtime.fs.write().await;
    let entry_id = fs
        .create_entry(
            Role::System,
            parent_id,
            EntryKind::File,
            fname.as_str(),
            [AccessPermissions::Rwx; 3],
        )
        .await
        .map_err(|err| {
            log::warn!("fs.create_entry(Role::System, ) failed: {err:?}");
            map_err_into_native(err)
        })
        .map_err(map_native_error)?;
    core::mem::drop(fs);
    log::debug!("created file {parent_id:x}:{fname} => {entry_id:x}");

    let resp = api_fs::stat_resp_encode(msg, entry_id, EntryKind::File);
    sender.send(resp).await.map_err(map_native_error)
}

async fn on_cmd_create_dir(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    let (parent_id, fname) =
        api_fs::create_entry_msg_decode(msg, sender).map_err(map_native_error)?;

    let mut fs = runtime.fs.write().await;
    let entry_id = fs
        .create_entry(
            Role::System,
            parent_id,
            EntryKind::Directory,
            fname.as_str(),
            [AccessPermissions::Rwx; 3],
        )
        .await
        .map_err(|err| {
            log::debug!("fs.create_entry(Role::System, ) failed: {err:?}");
            map_err_into_native(err)
        })
        .map_err(map_native_error)?;
    core::mem::drop(fs);
    log::debug!("created file {parent_id:x}:{fname} => {entry_id:x}");

    let resp = api_fs::stat_resp_encode(msg, entry_id, EntryKind::File);
    sender.send(resp).await.map_err(map_native_error)
}

async fn on_cmd_write(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    // Multi-page write requests carry the total length in `flags`; classic
    // single-page requests never set it. See `api_fs::write_multi_msg_encode`.
    if msg.flags != 0 {
        return on_cmd_write_multi(msg, sender, runtime).await;
    }

    let (file_id, offset, len, io_page) =
        api_fs::write_msg_decode(msg, sender).map_err(map_native_error)?;

    // `len` comes from the (untrusted) client; reject anything that does not
    // fit into an io_page instead of panicking on the slice below.
    if len as usize > moto_ipc::io_channel::PAGE_SIZE {
        return Err(std::io::Error::from(ErrorKind::InvalidInput));
    }

    let mut fs = runtime.fs.write().await;
    let written = fs
        .write(
            Role::System,
            file_id,
            offset,
            &io_page.bytes()[..(len as usize)],
        )
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
) -> Result<()> {
    let (file_id, offset, len, pages) =
        api_fs::write_multi_msg_decode(msg, sender).map_err(map_native_error)?;

    // One FS lock acquire for the whole message. The decode above recovered
    // every page, so all paths below free them on drop.
    let mut total = 0_u32;
    {
        let mut fs_guard = runtime.fs.write().await;
        let mut chunk_offset = offset;
        for (io_page, size) in pages.iter().zip(api_fs::io_chunks(offset, len)) {
            match fs_guard
                .write(
                    Role::System,
                    file_id,
                    chunk_offset,
                    &io_page.bytes()[..size],
                )
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
) -> Result<()> {
    let started = stats::now_ticks();
    let (file_id, offset, len) = api_fs::read_msg_decode(msg);

    // Requests spanning more than one io_page get a multi-page response;
    // see `api_fs::READ_MAX_PAGES`.
    if len as usize > moto_ipc::io_channel::PAGE_SIZE {
        return on_cmd_read_multi(msg, sender, runtime, file_id, offset, len).await;
    }

    let io_page = sender
        .alloc_page(u64::MAX)
        .await
        .map_err(map_native_error)?;

    let fs_guard = runtime.fs.read().await;
    let read = fs_guard
        .read(
            Role::System,
            file_id,
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

    maybe_readahead(runtime, file_id, offset, read);
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
    file_id: EntryId,
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

    // One page pool, one FS lock acquire, one tree-walk warmup for the whole
    // message. `alloc_page` may wait for the pool; pages recycle as soon as
    // the client consumes earlier responses, independent of the FS lock, so
    // waiting here (holding a read guard) cannot deadlock.
    let mut pages: Vec<moto_ipc::io_channel::IoPage> = Vec::with_capacity(num_chunks);
    let mut total = 0_u32;
    {
        let fs_guard = runtime.fs.read().await;
        let mut chunk_offset = offset;
        for &size in &chunk_sizes[..num_chunks] {
            let io_page = sender
                .alloc_page(u64::MAX)
                .await
                .map_err(map_native_error)?;
            let read = fs_guard
                .read(
                    Role::System,
                    file_id,
                    chunk_offset,
                    &mut io_page.bytes_mut()[..size],
                )
                .await?; // On error: `pages` drops, freeing them; on_msg sends the error response.
            pages.push(io_page);
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
        runtime
            .fs_stats
            .readahead_spawns
            .set(runtime.fs_stats.readahead_spawns.get() + 1);
        moto_async::LocalRuntime::spawn(async move {
            let fs = runtime.fs.read().await;
            fs.prefetch(
                file_id,
                end / (async_fs::BLOCK_SIZE as u64),
                READAHEAD_BLOCKS,
            )
            .await;
        });
    }
    Ok(())
}

/// Sequential readahead: full-block reads are the signature of streaming
/// (e.g. the VDSO loading a binary; moto-io splits large reads into
/// block-sized chunks). On every 16th file block, prefetch the 32 blocks past
/// the current 16-block window into the block cache in the background.
/// Duplicate device reads with foreground requests are impossible: the block
/// cache deduplicates concurrent reads of the same block.
fn maybe_readahead(runtime: FsRuntime, file_id: EntryId, offset: u64, read: usize) {
    const TRIGGER_WINDOW: u64 = 16; // Matches the moto-io read batch size.

    if read != async_fs::BLOCK_SIZE || !offset.is_multiple_of(async_fs::BLOCK_SIZE as u64) {
        return;
    }
    let block_key = offset / (async_fs::BLOCK_SIZE as u64);
    if !block_key.is_multiple_of(TRIGGER_WINDOW) {
        return;
    }

    runtime
        .fs_stats
        .readahead_spawns
        .set(runtime.fs_stats.readahead_spawns.get() + 1);
    moto_async::LocalRuntime::spawn(async move {
        let fs = runtime.fs.read().await;
        fs.prefetch(file_id, block_key + TRIGGER_WINDOW, READAHEAD_BLOCKS)
            .await;
    });
}

async fn on_cmd_metadata(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    let entry_id = api_fs::metadata_msg_decode(msg);

    let fs = runtime.fs.read().await;
    let metadata = fs.metadata(Role::System, entry_id).await?;

    let io_page = sender
        .alloc_page(u64::MAX)
        .await
        .map_err(map_native_error)?;
    core::mem::drop(fs);

    let resp = api_fs::metadata_resp_encode(msg.id, metadata, io_page);
    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_set_permissions(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    let (entry_id, raw_access) = api_fs::set_permissions_msg_decode(msg);
    let access = AccessPermissions::try_from(raw_access)?;

    let mut fs = runtime.fs.write().await;
    let resp = api_fs::empty_resp_encode(
        msg.id,
        fs.set_permissions(Role::System, entry_id, Role::System, access)
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
) -> Result<()> {
    let (file_id, new_size) = api_fs::resize_msg_decode(msg);

    let mut fs = runtime.fs.write().await;
    let resp = api_fs::empty_resp_encode(
        msg.id,
        fs.resize(Role::System, file_id, new_size)
            .await
            .map_err(map_err_into_native),
    );
    core::mem::drop(fs);

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_delete_entry(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    let entry_id = api_fs::delete_entry_msg_decode(msg);

    let mut fs = runtime.fs.write().await;
    let resp = api_fs::empty_resp_encode(
        msg.id,
        fs.delete_entry(Role::System, entry_id)
            .await
            .map_err(map_err_into_native),
    );
    core::mem::drop(fs);

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_flush(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    let mut fs = runtime.fs.write().await;
    let resp = api_fs::empty_resp_encode(msg.id, fs.flush().await.map_err(map_err_into_native));
    core::mem::drop(fs);

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_get_first_entry(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    let parent_id = api_fs::get_first_entry_req_decode(msg);
    let fs = runtime.fs.read().await;
    let resp = api_fs::get_first_entry_resp_encode(
        msg,
        fs.get_first_entry(Role::System, parent_id).await?,
    );
    core::mem::drop(fs);

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_get_next_entry(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    let entry_id = api_fs::get_next_entry_req_decode(msg);
    let fs = runtime.fs.read().await;
    let next_entry_id = fs.get_next_entry(Role::System, entry_id).await?;
    core::mem::drop(fs);
    let resp = api_fs::get_next_entry_resp_encode(msg, next_entry_id);

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_get_name(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    let entry_id = api_fs::get_name_req_decode(msg);
    let fs = runtime.fs.read().await;
    let name = fs.name(Role::System, entry_id).await?;
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
) -> Result<()> {
    let (entry_id, new_parent_id, fname) =
        api_fs::move_entry_req_decode(msg, sender).map_err(map_native_error)?;

    let mut fs = runtime.fs.write().await;
    let resp = api_fs::empty_resp_encode(
        msg.id,
        fs.move_entry(Role::System, entry_id, new_parent_id, fname.as_str())
            .await
            .map_err(map_err_into_native),
    );
    core::mem::drop(fs);

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_copy_file_range(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    runtime: FsRuntime,
) -> Result<()> {
    let (from, to, offset, size) = api_fs::copy_file_range_req_decode(msg);

    let mut fs = runtime.fs.write().await;

    // In this implementation, from_offset == to_offset.
    let copied = fs
        .copy_file_range(Role::System, from, offset, to, offset, size)
        .await?;
    core::mem::drop(fs);

    let resp = api_fs::copy_file_range_resp_encode(msg.id, copied);
    let _ = sender.send(resp).await;
    Ok(())
}
