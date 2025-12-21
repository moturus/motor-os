use async_fs::FileSystem;
use moto_async::{AsFuture, LocalMutex};
use moto_rt::Result;
use moto_sys_io::api_fs;
use moto_sys_io::api_fs::FS_URL;
use std::cell::RefCell;
use std::io::ErrorKind;
use std::rc::Rc;

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
        moto_rt::Error::InvalidData
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
                        moto_rt::Error::InvalidData
                    })?,
                );
                fs = Some(Box::new(motor_fs::MotorFs::open(partition).await.map_err(
                    |err| {
                        log::error!("Mbr::parse() failed: {err:?}.");
                        moto_rt::Error::InvalidData
                    },
                )?));
            }
            _ => continue,
        }
    }

    let Some(fs) = fs else {
        log::error!("Couldn't find a data partition.");
        return Err(moto_rt::Error::InvalidData);
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
    let (sender, receiver) = match core::future::poll_fn(|cx| match listener.as_mut().poll(cx) {
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
    }?;

    let receiver_stream = futures::stream::unfold(&receiver, |rx| async move {
        match rx.recv().await {
            Ok(msg) => Some((msg, rx)),
            Err(_) => None,
        }
    });

    use futures::StreamExt;

    receiver_stream
        .for_each_concurrent(MAX_IN_FLIGHT, move |msg| {
            let sender = sender.clone();
            let fs = fs.clone();
            async move {
                let _ = on_msg(msg, sender, fs).await;
            }
        })
        .await;

    log::debug!("FS connection closed.");
    Ok(())
}

async fn on_msg(
    msg: moto_ipc::io_channel::Msg,
    sender: moto_ipc::io_channel::Sender,
    fs: Rc<LocalMutex<Box<dyn FileSystem>>>,
) -> Result<()> {
    match msg.command {
        moto_sys_io::api_fs::CMD_STAT => on_cmd_stat(msg, sender, fs).await,
        cmd => {
            log::warn!("Unrecognized FS command: {cmd}.");
            Err(moto_rt::Error::InvalidData)
        }
    }
}

async fn on_cmd_stat(
    msg: moto_ipc::io_channel::Msg,
    sender: moto_ipc::io_channel::Sender,
    fs: Rc<LocalMutex<Box<dyn FileSystem>>>,
) -> Result<()> {
    let (parent_id, fname) = api_fs::stat_msg_decode(msg, &sender)?;
    todo!("got {parent_id}, {fname}")
}
