//! Boot-time source selection; each referenced device owns one bounded I/O inbox.
use super::{FS, block_io, mbr::Mbr, stats::FsStats, virtio_partition::VirtioPartition};
use moto_sdk::async_runtime::{LocalRuntime, channel};
use moto_sdk::iobuf::VirtioIoBuf;
use moto_sdk::sys_io::api_fs::MountBlockSource;
use std::io::{ErrorKind, Result};
use std::rc::Rc;

#[derive(Clone, Copy)]
pub(super) struct Source {
    pub identity: MountBlockSource,
    offset: u64,
    sectors: u64,
}

impl Source {
    fn new(identity: MountBlockSource, offset: u64, sectors: u64, capacity: u64) -> Result<Self> {
        if !sectors.is_multiple_of(8)
            || sectors / 8 < motor_fs::MIN_BLOCKS
            || offset.checked_add(sectors).is_none_or(|end| end > capacity)
        {
            return Err(ErrorKind::InvalidData.into());
        }
        Ok(Self {
            identity,
            offset,
            sectors,
        })
    }
}

struct Owner {
    inbox: channel::Sender<block_io::Message>,
    capacity: u64,
    flush_supported: bool,
    mbr: Option<Mbr>,
    root_header: Option<VirtioIoBuf>,
}

impl Owner {
    async fn first_block(&self) -> Result<VirtioIoBuf> {
        if self.capacity < 8 {
            return Err(ErrorKind::InvalidData.into());
        }
        let block = VirtioIoBuf::new_from_size_align(4096).ok_or(ErrorKind::OutOfMemory)?;
        let pages = vec![block.phys_addr() as u64];
        let reply = block_io::send(&self.inbox, block, |reply| block_io::Message::Read {
            first_sector: 0,
            pages,
            reply,
        })
        .await
        .map_err(|(_, error)| error)?;
        let (block, result) = reply.await;
        result?;
        Ok(block)
    }

    async fn mbr(&mut self) -> Result<&Mbr> {
        if self.mbr.is_none() {
            let block = self.first_block().await?;
            self.mbr = Some(Mbr::parse(
                &AsRef::<[u8]>::as_ref(&block)[..512],
                self.capacity,
            )?);
        }
        Ok(self.mbr.as_ref().unwrap())
    }
}

struct Device {
    parsed: Option<Result<virtio_async::VirtioDevice>>,
    owner: Option<Owner>,
}

pub(super) struct Devices {
    devices: Vec<Device>,
    stats: Rc<FsStats>,
}

impl Devices {
    pub fn new(devices: Vec<Result<virtio_async::VirtioDevice>>, stats: Rc<FsStats>) -> Self {
        Self {
            devices: devices
                .into_iter()
                .map(|device| Device {
                    parsed: Some(device),
                    owner: None,
                })
                .collect(),
            stats,
        }
    }

    fn owner(&mut self, index: u32) -> Result<&mut Owner> {
        let device = self
            .devices
            .get_mut(index as usize)
            .ok_or(ErrorKind::NotFound)?;
        if device.owner.is_none() {
            let parsed = device.parsed.take().ok_or(ErrorKind::NotConnected)??;
            let block = virtio_async::BlockDevice::from(parsed)?;
            let (sender, receiver) = channel::channel(64);
            device.owner = Some(Owner {
                inbox: sender,
                capacity: block.capacity(),
                flush_supported: block.flush_supported(),
                mbr: None,
                root_header: None,
            });
            LocalRuntime::spawn(block_io::run(block, receiver, self.stats.clone()));
        }
        Ok(device.owner.as_mut().unwrap())
    }

    pub async fn root(&mut self) -> Result<Source> {
        let owner = self.owner(0)?;
        let block = owner.first_block().await?;
        let partition = if motor_fs::has_superblock_magic(AsRef::<[u8]>::as_ref(&block)) {
            owner.root_header = Some(block);
            None
        } else {
            let mbr = Mbr::parse(&AsRef::<[u8]>::as_ref(&block)[..512], owner.capacity)?;
            let (slot, _) = mbr.first_motor_fs()?;
            owner.mbr = Some(mbr);
            Some(slot)
        };
        self.resolve(MountBlockSource {
            device: 0,
            partition,
        })
        .await
    }

    pub async fn resolve(&mut self, identity: MountBlockSource) -> Result<Source> {
        let owner = self.owner(identity.device)?;
        let (offset, sectors) = if let Some(slot) = identity.partition {
            let entry = owner.mbr().await?.motor_fs(slot)?;
            (u64::from(entry.lba), u64::from(entry.sectors))
        } else {
            (0, owner.capacity)
        };
        Source::new(identity, offset, sectors, owner.capacity)
    }

    pub async fn open(&mut self, source: Source, cache_blocks: usize) -> Result<FS> {
        let owner = self.owner(source.identity.device)?;
        let mut partition = VirtioPartition::from_virtio_bd(
            owner.inbox.clone(),
            owner.flush_supported,
            source.offset,
            source.sectors,
        )
        .await?;
        if let Some(header) = owner.root_header.take() {
            partition.seed_first_block(header);
        }
        let fs = motor_fs::MotorFs::open_with_cache_size(Box::new(partition), cache_blocks).await?;
        Ok(FS::MotorFs(fs))
    }
}

#[cfg(debug_assertions)]
pub(super) mod self_test {
    use super::*;
    use crate::self_test::{st_assert, st_assert_eq};

    pub(in crate::runtime::fs) const TESTS: &[crate::self_test::SelfTest] =
        &[("fs::block_sources", run)];

    fn run() -> std::result::Result<(), String> {
        let whole = MountBlockSource {
            device: 0,
            partition: None,
        };
        for sectors in [0, 8, 66 * 8, 67 * 8 + 1] {
            st_assert!(Source::new(whole, 0, sectors, sectors).is_err());
        }
        st_assert!(Source::new(whole, 0, 67 * 8, 67 * 8).is_ok());
        let partition = MountBlockSource {
            device: 1,
            partition: Some(4),
        };
        st_assert!(Source::new(partition, 1, 67 * 8, 67 * 8 + 1).is_ok());
        st_assert!(Source::new(partition, 1, 67 * 8, 67 * 8).is_err());
        st_assert!(Source::new(partition, u64::MAX - 7, 67 * 8, u64::MAX).is_err());
        // A failed earlier function must not renumber later devices.
        let mut devices = Devices::new(
            vec![
                Err(ErrorKind::InvalidData.into()),
                Err(ErrorKind::Unsupported.into()),
            ],
            Rc::new(FsStats::default()),
        );
        st_assert!(
            devices
                .owner(1)
                .is_err_and(|error| error.kind() == ErrorKind::Unsupported)
        );
        st_assert!(
            devices
                .owner(0)
                .is_err_and(|error| error.kind() == ErrorKind::InvalidData)
        );
        st_assert!(
            devices
                .owner(2)
                .is_err_and(|error| error.kind() == ErrorKind::NotFound)
        );
        st_assert_eq!(devices.devices.len(), 2);
        Ok(())
    }
}
