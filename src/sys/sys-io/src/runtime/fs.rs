use std::cell::RefCell;
use std::io::Result;
use std::rc::Rc;

pub(super) struct Filesystem {
    block_device: RefCell<virtio_async::BlockDevice>,
    fs: Box<dyn async_fs::FileSystem>,
}

pub(super) async fn init(
    block_device: Rc<RefCell<virtio_async::BlockDevice>>,
) -> Result<Filesystem> {
    use zerocopy::FromZeros;

    let mut virtio_block = virtio_async::VirtioBlock::new_zeroed();
    let completion =
        virtio_async::BlockDevice::post_read(block_device.clone(), 0, virtio_block.as_mut())
            .unwrap();
    completion.await;
    log::info!("FIRST ASYNC VIRTIO READ OK!!!");
    let mbr = crate::fs::mbr::Mbr::parse(virtio_block.bytes.as_slice())?;
    log::info!("Got {mbr:?}");
    todo!()
}

/*
pub fn init() {
    let mut drives = moto_virtio::lsblk();
    if drives.is_empty() {
        log::error!("No drives found");
        panic!("No drives found");
    }
    if drives.len() % 10 == 1 {
        log::debug!("Found {} virtio drive.", drives.len());
    } else {
        log::debug!("Found {} virtio drives.", drives.len());
    }

    const BLOCK_SIZE: usize = 512;
    let mut block = vec![0; BLOCK_SIZE];

    let mut fs: Option<Box<dyn FileSystem>> = None;
    for drive in &mut drives {
        if let Ok(()) = drive.read(block.as_mut_slice(), 0, 1) {
            match super::mbr::Mbr::parse(block.as_slice()) {
                Ok(mbr) => {
                    for pte in &mbr.entries {
                        log::trace!("MBR PTE: {pte:?}");
                        match pte.partition_type {
                            super::mbr::PartitionType::FlatFs => {
                                if fs.is_some() {
                                    log::error!("Found more than one DATA partion.");
                                    panic!();
                                }

                                fs = Some(super::fs_flatfs::init(
                                    drive.clone(),
                                    pte.lba as u64,
                                    pte.sectors as u64,
                                ));
                            }
                            super::mbr::PartitionType::SrFs => {
                                if fs.is_some() {
                                    log::error!("Found more than one DATA partion.");
                                    panic!();
                                }

                                fs = Some(super::fs_srfs::init(
                                    drive.clone(),
                                    pte.lba as u64,
                                    pte.sectors as u64,
                                ));
                            }
                            super::mbr::PartitionType::MotorFs => {
                                if fs.is_some() {
                                    log::error!("Found more than one DATA partion.");
                                    panic!();
                                }

                                todo!() /*
                                        fs = Some(super::fs_srfs::init(
                                            drive.clone(),
                                            pte.lba as u64,
                                            pte.sectors as u64,
                                        )); */
                            }
                            _ => continue,
                        }
                    }
                }
                Err(err) => {
                    crate::moto_log!("Failed to read MBR: {err}");
                    log::warn!("Failed to read MBR: {err}");
                }
            }
        } else {
            crate::moto_log!("Skipping a VirtIO drive due to I/O error.");
            log::warn!("Skipping a VirtIO drive due to I/O error.");
        }
    }

    if fs.is_none() {
        log::error!("Couldn't find a data partion.");
        panic!("Couldn't find a data partition.");
    }

    let holder = Box::leak(Box::new(FsHolder { ptr: fs.unwrap() }));

    assert!(FS
        .swap(holder, std::sync::atomic::Ordering::AcqRel)
        .is_null());
}
*/
