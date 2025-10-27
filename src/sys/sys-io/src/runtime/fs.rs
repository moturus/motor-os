use async_fs::FileSystem;
use moto_async::{AsFuture, LocalMutex};
use std::cell::RefCell;
use std::io::{ErrorKind, Result};
use std::rc::Rc;

mod virtio_partition;

pub(super) async fn init(block_device: Rc<RefCell<virtio_async::BlockDevice>>) -> Result<()> {
    use zerocopy::FromZeros;

    let mut virtio_block = virtio_async::VirtioBlock::new_zeroed();
    let completion =
        virtio_async::BlockDevice::post_read(block_device.clone(), 0, virtio_block.as_mut())
            .unwrap();
    completion.await;

    let mbr = crate::fs::mbr::Mbr::parse(virtio_block.bytes.as_slice())?;

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

                let partition = Box::new(virtio_partition::VirtioPartition::from_virtio_bd(
                    block_device.clone(),
                    pte.lba as u64,
                    pte.sectors as u64,
                )?);
                fs = Some(Box::new(motor_fs::MotorFs::open(partition).await?));
            }
            _ => continue,
        }
    }

    let Some(fs) = fs else {
        log::error!("Couldn't find a data partition.");
        return Err(ErrorKind::NotFound.into());
    };

    spawn_fs_listeners(fs);
    Ok(())
}

fn spawn_fs_listeners(fs: Box<dyn FileSystem>) {
    let fs = Rc::new(LocalMutex::new(fs));

    const NUM_LISTENERS: usize = 5;
    for _ in 0..NUM_LISTENERS {
        spawn_new_listener(fs.clone());
    }
}

fn spawn_new_listener(fs: Rc<LocalMutex<Box<dyn FileSystem>>>) {
    let listener = moto_ipc::io_channel::ServerConnection::create("sys-io-fs")
        .expect("Failed to spawn a sys-io-fs listener: {err:?}");

    moto_async::LocalRuntime::spawn(async move {
        fs_listener(fs.clone(), listener)
            .await
            .inspect_err(|err| log::debug!("fs_listener exited with error {err}"));

        // Spawn a new listener when another one completes.
        spawn_new_listener(fs);
    });
}

async fn fs_listener(
    fs: Rc<LocalMutex<Box<dyn FileSystem>>>,
    mut listener: moto_ipc::io_channel::ServerConnection,
) -> Result<()> {
    listener
        .wait_handle()
        .as_future()
        .await
        .map_err(|code| std::io::Error::from_raw_os_error(code as i32))?;

    listener
        .accept()
        .map_err(|code| std::io::Error::from_raw_os_error(code as i32))?;
    todo!()
}
