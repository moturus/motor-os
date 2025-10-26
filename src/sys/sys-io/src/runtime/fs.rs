use async_fs::FileSystem;
use std::cell::RefCell;
use std::io::{ErrorKind, Result};
use std::rc::Rc;

mod virtio_partition;

pub(super) async fn init(
    block_device: Rc<RefCell<virtio_async::BlockDevice>>,
) -> Result<Box<dyn FileSystem>> {
    use zerocopy::FromZeros;

    let mut virtio_block = virtio_async::VirtioBlock::new_zeroed();
    let completion =
        virtio_async::BlockDevice::post_read(block_device.clone(), 0, virtio_block.as_mut())
            .unwrap();
    completion.await;

    let mbr = crate::fs::mbr::Mbr::parse(virtio_block.bytes.as_slice())?;
    log::info!("Got {mbr:#?}");

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

    fs.ok_or(ErrorKind::NotFound.into())
        .inspect_err(|_| log::error!("Couldn't find a data partition."))
}
