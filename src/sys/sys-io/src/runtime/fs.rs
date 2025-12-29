use async_fs::{EntryKind, FileSystem};
use moto_async::{AsFuture, LocalMutex};
use moto_sys_io::api_fs;
use moto_sys_io::api_fs::FS_URL;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::io::Result;
use std::rc::Rc;

use crate::util::map_err_into_native;
use crate::util::map_native_error;

mod virtio_partition;

/// The max number of "requests" in flight per connection.
const MAX_IN_FLIGHT: usize = 32;

pub(super) async fn init(block_device: Rc<RefCell<virtio_async::BlockDevice>>) -> Result<()> {
    use zerocopy::FromZeros;

    let mut virtio_block = virtio_async::VirtioBlock::new_zeroed();
    let completion =
        virtio_async::BlockDevice::post_read(block_device.clone(), 0, virtio_block.as_mut())
            .unwrap();
    completion.await;

    let mbr = crate::fs::mbr::Mbr::parse(virtio_block.bytes.as_slice()).map_err(|err| {
        log::error!("Mbr::parse() failed: {err:?}.");
        std::io::Error::from(ErrorKind::InvalidData)
    })?;

    let mut fs: Option<Box<dyn FileSystem>> = None;
    for pte in &mbr.entries {
        log::trace!("MBR PTE: {pte:?}");
        match pte.partition_type {
            crate::fs::mbr::PartitionType::FlatFs => {
                log::warn!("FlatFs is not (yet?) supported with async runtime");
            }
            crate::fs::mbr::PartitionType::SrFs => {
                log::warn!("SrFs is not (yet?) supported with async runtime");
            }
            crate::fs::mbr::PartitionType::MotorFs => {
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
                    .map_err(|err| {
                        log::error!("Mbr::parse() failed: {err:?}.");
                        std::io::Error::from(ErrorKind::InvalidData)
                    })?,
                );
                fs = Some(Box::new(motor_fs::MotorFs::open(partition).await.map_err(
                    |err| {
                        log::error!("Mbr::parse() failed: {err:?}.");
                        std::io::Error::from(ErrorKind::InvalidData)
                    },
                )?));
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

async fn spawn_fs_listeners(fs: Box<dyn FileSystem>) {
    let fs = Rc::new(LocalMutex::new(fs));

    const NUM_LISTENERS: usize = 5;
    for _ in 0..NUM_LISTENERS {
        spawn_new_listener(fs.clone()).await;
    }
}

async fn spawn_new_listener(fs: Rc<LocalMutex<Box<dyn FileSystem>>>) {
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
    fs: Rc<LocalMutex<Box<dyn FileSystem>>>,
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
    fs: Rc<LocalMutex<Box<dyn FileSystem>>>,
) {
    if let Err(err) = match msg.command {
        moto_sys_io::api_fs::CMD_STAT => on_cmd_stat(msg, &sender, fs).await,
        moto_sys_io::api_fs::CMD_CREATE_FILE => on_cmd_create_file(msg, &sender, fs).await,
        moto_sys_io::api_fs::CMD_CREATE_DIR => todo!(),
        moto_sys_io::api_fs::CMD_WRITE => on_cmd_write(msg, &sender, fs).await,
        moto_sys_io::api_fs::CMD_READ => on_cmd_read(msg, &sender, fs).await,
        moto_sys_io::api_fs::CMD_METADATA => on_cmd_metadata(msg, &sender, fs).await,
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
    fs: Rc<LocalMutex<Box<dyn FileSystem>>>,
) -> Result<()> {
    let (parent_id, fname) = api_fs::stat_msg_decode(msg, &sender).map_err(map_native_error)?;

    let mut fs = fs.lock().await;
    let Some(entry_id) = fs.stat(parent_id, fname.as_str()).await.map_err(|err| {
        log::warn!("fs.stat() failed: {err:?}");
        err
    })?
    else {
        log::debug!("stat({parent_id}, {fname}): not found");
        return Err(std::io::Error::from(ErrorKind::NotFound));
    };
    core::mem::drop(fs);

    let resp = api_fs::stat_resp_encode(msg, entry_id);
    sender.send(resp).await.map_err(map_native_error)
}

async fn on_cmd_create_file(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    fs: Rc<LocalMutex<Box<dyn FileSystem>>>,
) -> Result<()> {
    let (parent_id, fname) =
        api_fs::create_entry_msg_decode(msg, &sender).map_err(map_native_error)?;

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

    let resp = api_fs::stat_resp_encode(msg, entry_id);
    sender.send(resp).await.map_err(map_native_error)
}

async fn on_cmd_write(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    fs: Rc<LocalMutex<Box<dyn FileSystem>>>,
) -> Result<()> {
    let (file_id, offset, len, io_page) =
        api_fs::write_msg_decode(msg, sender).map_err(map_native_error)?;
    log::debug!("write: {file_id:x}: offset: {offset:x}, len: {len}");

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
    fs: Rc<LocalMutex<Box<dyn FileSystem>>>,
) -> Result<()> {
    let (file_id, offset, len) = api_fs::read_msg_decode(msg);
    // log::debug!(
    //     "read: {file_id:x}: offset: {offset:x}, len: {len} msg id: {}",
    //     msg.id
    // );

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
    // log::debug!("read done: {file_id:x}: offset: {offset:x}, len: {len} ({read})");
    Ok(())
}

async fn on_cmd_metadata(
    msg: moto_ipc::io_channel::Msg,
    sender: &moto_ipc::io_channel::Sender,
    fs: Rc<LocalMutex<Box<dyn FileSystem>>>,
) -> Result<()> {
    let entry_id = api_fs::metadata_msg_decode(msg);
    log::debug!("metadata: {entry_id:x}");

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
