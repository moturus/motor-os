use async_fs::EntryId;
use async_fs::{EntryKind, FileSystem};
use async_trait::async_trait;
use moto_async::{AsFuture, LocalMutex};
use moto_sys_io::api_fs;
use moto_sys_io::api_fs::FS_URL;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::io::Result;
use std::rc::Rc;

use crate::runtime::fs::virtio_partition::VirtioPartition;
use crate::util::map_err_into_native;
use crate::util::map_native_error;

mod mbr;
mod virtio_partition;

/// The max number of "requests" in flight per connection.
const MAX_IN_FLIGHT: usize = 32;

enum FS {
    MotorFs(motor_fs::MotorFs<VirtioPartition>),
}

#[async_trait(?Send)]
impl FileSystem for FS {
    type Completion<'a> = <VirtioPartition as async_fs::AsyncBlockDevice>::Completion<'a>;

    /// Find a file or directory by its full path.
    async fn stat(
        &mut self,
        parent_id: EntryId,
        filename: &str,
    ) -> Result<Option<(EntryId, EntryKind)>> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.stat(parent_id, filename).await,
        }
    }

    /// Create a file or directory.
    async fn create_entry(
        &mut self,
        parent_id: EntryId,
        kind: EntryKind,
        name: &str, // Leaf name.
    ) -> Result<EntryId> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.create_entry(parent_id, kind, name).await,
        }
    }

    /// Delete the file or directory.
    async fn delete_entry(&mut self, entry_id: EntryId) -> Result<()> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.delete_entry(entry_id).await,
        }
    }

    /// Rename and/or move the file or directory.
    async fn move_entry(
        &mut self,
        entry_id: EntryId,
        new_parent_id: EntryId,
        new_name: &str,
    ) -> Result<()> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.move_entry(entry_id, new_parent_id, new_name).await,
        }
    }

    /// Get the first entry in a directory.
    async fn get_first_entry(&mut self, parent_id: EntryId) -> Result<Option<EntryId>> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.get_first_entry(parent_id).await,
        }
    }

    /// Get the next entry in a directory.
    async fn get_next_entry(&mut self, entry_id: EntryId) -> Result<Option<EntryId>> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.get_next_entry(entry_id).await,
        }
    }

    /// Get the parent of the entry.
    async fn get_parent(&mut self, entry_id: EntryId) -> Result<Option<EntryId>> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.get_parent(entry_id).await,
        }
    }

    /// Filename of the entry, without parent directories.
    async fn name(&mut self, entry_id: EntryId) -> Result<String> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.name(entry_id).await,
        }
    }

    /// The metadata of the directory entry.
    async fn metadata(&mut self, entry_id: EntryId) -> Result<async_fs::Metadata> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.metadata(entry_id).await,
        }
    }

    /// Read bytes from a file.
    /// Note that cross-block reads may not be supported.
    async fn read(&mut self, file_id: EntryId, offset: u64, buf: &mut [u8]) -> Result<usize> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.read(file_id, offset, buf).await,
        }
    }

    /// Write bytes to a file.
    /// Note that cross-block writes may not be supported.
    async fn write(&mut self, file_id: EntryId, offset: u64, buf: &[u8]) -> Result<usize> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.write(file_id, offset, buf).await,
        }
    }

    /// Write bytes to a file.
    /// Note that cross-block writes may not be supported.
    #[allow(unused)]
    async fn write_2<'a>(
        &mut self,
        file_id: EntryId,
        offset: u64,
        buf: &'a [u8],
    ) -> Result<(usize, Self::Completion<'a>)> {
        todo!()
    }

    /// Resize the file.
    async fn resize(&mut self, file_id: EntryId, new_size: u64) -> Result<()> {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.resize(file_id, new_size).await,
        }
    }

    /// The total number of blocks in the FS.
    fn num_blocks(&self) -> u64 {
        match self {
            FS::MotorFs(motor_fs) => motor_fs.num_blocks(),
        }
    }

    async fn empty_blocks(&mut self) -> Result<u64> {
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

pub(super) async fn init(block_device: Rc<virtio_async::BlockDevice>) -> Result<()> {
    use zerocopy::FromZeros;

    let mut first_block = async_fs::Block::new_zeroed();
    let completion = virtio_async::BlockDevice::post_read(
        block_device.clone(),
        0,
        &mut first_block.as_bytes_mut()[..512],
    )
    .unwrap();
    completion.await;

    let mbr = mbr::Mbr::parse(&first_block.as_bytes()[..512]).map_err(|err| {
        log::error!("Mbr::parse() failed: {err:?}.");
        std::io::Error::from(ErrorKind::InvalidData)
    })?;

    let mut fs: Option<Rc<LocalMutex<FS>>> = None;
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
                    )
                    .await
                    .map_err(|err| {
                        log::error!("Mbr::parse() failed: {err:?}.");
                        std::io::Error::from(ErrorKind::InvalidData)
                    })?,
                );
                fs = Some(Rc::new(LocalMutex::new(FS::MotorFs(
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

    spawn_fs_listeners(fs).await;
    Ok(())
}

async fn spawn_fs_listeners(fs: Rc<LocalMutex<FS>>) {
    const NUM_LISTENERS: usize = 5;
    for _ in 0..NUM_LISTENERS {
        spawn_new_listener(fs.clone()).await;
    }
}

async fn spawn_new_listener(fs: Rc<LocalMutex<FS>>) {
    // Use oneshot to signal the start of listening, otherwise connects may fail.
    let (tx, rx) = moto_async::oneshot();

    moto_async::LocalRuntime::spawn(async move {
        fs_listener(fs.clone(), tx)
            .await
            .inspect_err(|err| log::debug!("fs_listener exited with error {err}"));

        // Spawn a new listener when another one completes.
        spawn_new_listener(fs);
    });

    let _ = rx.await;
}

async fn fs_listener(
    fs: Rc<LocalMutex<FS>>,
    started: moto_async::oneshot::Sender<()>,
) -> Result<()> {
    let mut listener = core::pin::pin!(moto_ipc::io_channel::listen(FS_URL));

    // Do a poll to ensure the listener has started listening.
    let (sender, mut receiver) =
        match core::future::poll_fn(|cx| match listener.as_mut().poll(cx) {
            std::task::Poll::Ready(res) => std::task::Poll::Ready(Some(res)),
            std::task::Poll::Pending => std::task::Poll::Ready(None),
        })
        .await
        {
            Some(res) => res,
            None => {
                let _ = started.send(());
                listener.await
            }
        }
        .map_err(|err| std::io::Error::from_raw_os_error(err as u16 as i32))?;

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
                let fs = fs.clone();
                let ticket_tx = ticket_tx.clone();
                moto_async::LocalRuntime::spawn(async move {
                    on_msg(msg, sender, fs).await;
                    let _ = ticket_tx.send(()).await;
                });
            }
            Err(err) => return Err(std::io::Error::from_raw_os_error(err as u16 as i32)),
        }
    }
}

async fn on_msg(
    msg: moto_ipc::io_channel::Msg,
    sender: moto_ipc::io_channel::Sender,
    fs: Rc<LocalMutex<FS>>,
) {
    if let Err(err) = match msg.command {
        moto_sys_io::api_fs::CMD_STAT => on_cmd_stat(msg, &sender, fs).await,
        moto_sys_io::api_fs::CMD_CREATE_FILE => on_cmd_create_file(msg, &sender, fs).await,
        moto_sys_io::api_fs::CMD_CREATE_DIR => todo!(),
        moto_sys_io::api_fs::CMD_WRITE => on_cmd_write(msg, &sender, fs).await,
        moto_sys_io::api_fs::CMD_READ => on_cmd_read(msg, &sender, fs).await,
        moto_sys_io::api_fs::CMD_METADATA => on_cmd_metadata(msg, &sender, fs).await,
        moto_sys_io::api_fs::CMD_RESIZE => on_cmd_resize(msg, &sender, fs).await,
        moto_sys_io::api_fs::CMD_DELETE_ENTRY => on_cmd_delete_entry(msg, &sender, fs).await,
        moto_sys_io::api_fs::CMD_FLUSH => on_cmd_flush(msg, &sender, fs).await,
        cmd => {
            log::warn!("Unrecognized FS command: {cmd}.");
            Err(std::io::Error::from(ErrorKind::InvalidData))
        }
    } {
        let resp = api_fs::empty_resp_encode(msg.id, Err(map_err_into_native(err)));
        let _ = sender.send(resp).await;
    }
}

async fn on_cmd_stat(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    fs: Rc<LocalMutex<FS>>,
) -> Result<()> {
    let (parent_id, fname) = api_fs::stat_msg_decode(msg, sender).map_err(map_native_error)?;

    let mut fs = fs.lock().await;
    let Some((entry_id, entry_kind)) = fs.stat(parent_id, fname.as_str()).await.map_err(|err| {
        log::warn!("fs.stat() failed: {err:?}");
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
    fs: Rc<LocalMutex<FS>>,
) -> Result<()> {
    let (parent_id, fname) =
        api_fs::create_entry_msg_decode(msg, sender).map_err(map_native_error)?;

    let mut fs = fs.lock().await;
    let entry_id = fs
        .create_entry(parent_id, EntryKind::File, fname.as_str())
        .await
        .map_err(|err| {
            log::warn!("fs.create_entry() failed: {err:?}");
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
    fs: Rc<LocalMutex<FS>>,
) -> Result<()> {
    let (file_id, offset, len, io_page) =
        api_fs::write_msg_decode(msg, sender).map_err(map_native_error)?;

    let mut fs = fs.lock().await;
    let written = fs
        .write(file_id, offset, &io_page.bytes()[..(len as usize)])
        .await?;
    assert_eq!(written, len as usize);

    let resp = api_fs::empty_resp_encode(msg.id, Ok(()));
    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_read(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    fs: Rc<LocalMutex<FS>>,
) -> Result<()> {
    let (file_id, offset, len) = api_fs::read_msg_decode(msg);

    let io_page = sender
        .alloc_page(u64::MAX)
        .await
        .map_err(map_native_error)?;

    let mut fs = fs.lock().await;
    let read = fs
        .read(file_id, offset, &mut io_page.bytes_mut()[..(len as usize)])
        .await?;

    let resp = api_fs::read_resp_encode(msg.id, read as u16, io_page);
    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_metadata(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    fs: Rc<LocalMutex<FS>>,
) -> Result<()> {
    let entry_id = api_fs::metadata_msg_decode(msg);

    let mut fs = fs.lock().await;
    let metadata = fs.metadata(entry_id).await?;

    let io_page = sender
        .alloc_page(u64::MAX)
        .await
        .map_err(map_native_error)?;

    let resp = api_fs::metadata_resp_encode(msg.id, metadata, io_page);
    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_resize(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    fs: Rc<LocalMutex<FS>>,
) -> Result<()> {
    let (file_id, new_size) = api_fs::resize_msg_decode(msg);

    let mut fs = fs.lock().await;
    let resp = api_fs::empty_resp_encode(
        msg.id,
        fs.resize(file_id, new_size)
            .await
            .map_err(map_err_into_native),
    );

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_delete_entry(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    fs: Rc<LocalMutex<FS>>,
) -> Result<()> {
    let entry_id = api_fs::delete_entry_msg_decode(msg);

    let mut fs = fs.lock().await;
    let resp = api_fs::empty_resp_encode(
        msg.id,
        fs.delete_entry(entry_id).await.map_err(map_err_into_native),
    );

    let _ = sender.send(resp).await;
    Ok(())
}

async fn on_cmd_flush(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    fs: Rc<LocalMutex<FS>>,
) -> Result<()> {
    let mut fs = fs.lock().await;
    let resp = api_fs::empty_resp_encode(msg.id, fs.flush().await.map_err(map_err_into_native));

    let _ = sender.send(resp).await;
    Ok(())
}

#[allow(unused)]
pub fn smoke_test() {
    assert_eq!(
        std::fs::metadata("/foo").err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        std::fs::metadata("/bar").err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );

    std::fs::write("/foo", "bar").expect("async write failed");
    let bytes = std::fs::read("/foo").expect("async read failed");
    assert_eq!(bytes.as_slice(), "bar".as_bytes());

    let mut bytes = vec![0_u8; 1024 * 1024 * 11 + 1001];
    // let mut bytes = vec![0_u8; 1024 * 1024 * 2 + 1001];
    for byte in &mut bytes {
        *byte = std::random::random(..);
    }

    let ts0 = std::time::Instant::now();
    std::fs::write("/bar", bytes.as_slice()).unwrap();
    let ts1 = std::time::Instant::now();
    let bytes_back = std::fs::read("/bar").unwrap();
    let dur_read = ts1.elapsed();
    let dur_write = ts1 - ts0;

    assert_eq!(
        moto_rt::fnv1a_hash_64(bytes.as_slice()),
        moto_rt::fnv1a_hash_64(bytes_back.as_slice())
    );

    let write_mbps = (bytes.len() as f64) / dur_write.as_secs_f64() / (1024.0 * 1024.0);
    let read_mbps = (bytes.len() as f64) / dur_write.as_secs_f64() / (1024.0 * 1024.0);
    log::info!(
        "async FS smoke test: write {:.3} mbps; read: {:.3} mbps",
        write_mbps,
        read_mbps
    );

    let metadata = std::fs::metadata("/bar").unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), bytes.len() as u64);

    std::fs::remove_file("/foo").unwrap();
    std::fs::remove_file("/bar").unwrap();

    assert_eq!(
        std::fs::metadata("/foo").err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        std::fs::metadata("/bar").err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );

    log::info!("async FS smoke test PASSED");
}
