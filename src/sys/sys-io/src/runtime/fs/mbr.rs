// Master Boot Record.
//
// Inspired by https://github.com/ischeinkman/mbr-nostd (Apache 2.0).

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PartitionType {
    Unused,
    Unknown(u8),
    Fat12(u8),
    Fat16(u8),
    Fat32(u8),
    LinuxExt(u8),
    HfsPlus(u8),
    NtfsExfat(u8),
    FlatFs,
    SrFs,
    MotorFs,
}

impl PartitionType {
    pub fn from_mbr_tag_byte(tag: u8) -> PartitionType {
        match tag {
            0x0 => PartitionType::Unused,
            0x01 => PartitionType::Fat12(tag),
            0x04 | 0x06 | 0x0e => PartitionType::Fat16(tag),
            0x0b | 0x0c | 0x1b | 0x1c => PartitionType::Fat32(tag),
            0x83 => PartitionType::LinuxExt(tag),
            0x07 => PartitionType::NtfsExfat(tag),
            0xaf => PartitionType::HfsPlus(tag),
            motor_fs::PARTITION_ID => PartitionType::MotorFs, // 0x2e
            _ => PartitionType::Unknown(tag),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PartitionTableEntry {
    pub partition_type: PartitionType,
    pub lba: u32,
    pub sectors: u32,
}

impl PartitionTableEntry {
    pub fn new(partition_type: PartitionType, lba: u32, sectors: u32) -> PartitionTableEntry {
        PartitionTableEntry {
            partition_type,
            lba,
            sectors,
        }
    }

    pub fn empty() -> PartitionTableEntry {
        PartitionTableEntry::new(PartitionType::Unused, 0, 0)
    }
}

#[derive(Debug)]
pub struct Mbr {
    pub entries: [PartitionTableEntry; MAX_ENTRIES],
}

const MBR_SIZE: usize = 512;
const TABLE_OFFSET: usize = 446;
const ENTRY_SIZE: usize = 16;
const MBR_SUFFIX: [u8; 2] = [0x55, 0xaa];
const MAX_ENTRIES: usize = 4;

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut input = [0_u8; 4];

    for idx in 0..4 {
        if (idx + offset) >= bytes.len() {
            break;
        }
        input[idx] = bytes[idx + offset];
    }

    u32::from_le_bytes(input)
}

impl Mbr {
    pub fn parse(bytes: &[u8], capacity: u64) -> std::io::Result<Mbr> {
        if bytes.len() != MBR_SIZE || bytes[MBR_SIZE - MBR_SUFFIX.len()..] != MBR_SUFFIX {
            log::error!("MBR suffix wrong.");
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let mut entries = [PartitionTableEntry::empty(); MAX_ENTRIES];
        #[allow(clippy::needless_range_loop)]
        for idx in 0..MAX_ENTRIES {
            let offset = TABLE_OFFSET + idx * ENTRY_SIZE;
            let partition_type = PartitionType::from_mbr_tag_byte(bytes[offset + 4]);
            let lba = read_u32(bytes, offset + 8);
            let len = read_u32(bytes, offset + 12);
            if partition_type != PartitionType::Unused {
                let start = u64::from(lba);
                let end = start + u64::from(len);
                if lba == 0
                    || len == 0
                    || end > capacity
                    || entries[..idx].iter().any(|other| {
                        other.partition_type != PartitionType::Unused
                            && start < u64::from(other.lba) + u64::from(other.sectors)
                            && u64::from(other.lba) < end
                    })
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid or overlapping MBR extent in slot {}", idx + 1),
                    ));
                }
            }
            entries[idx] = PartitionTableEntry::new(partition_type, lba, len);
        }
        Ok(Mbr { entries })
    }

    pub fn motor_fs(&self, slot: u8) -> std::io::Result<PartitionTableEntry> {
        slot.checked_sub(1)
            .and_then(|index| self.entries.get(index as usize))
            .filter(|entry| {
                entry.partition_type == PartitionType::MotorFs && entry.sectors % 8 == 0
            })
            .copied()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid Motor FS partition in MBR slot {slot}"),
                )
            })
    }

    pub fn first_motor_fs(&self) -> std::io::Result<(u8, PartitionTableEntry)> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.partition_type == PartitionType::MotorFs)
            .ok_or(std::io::ErrorKind::NotFound)?;
        let slot = (index + 1) as u8;
        Ok((slot, self.motor_fs(slot)?))
    }
}

#[cfg(debug_assertions)]
pub(super) mod self_test {
    use super::*;
    use crate::self_test::{st_assert, st_assert_eq};

    pub(in crate::runtime::fs) const TESTS: &[crate::self_test::SelfTest] =
        &[("fs::mbr_extents", run)];

    fn disk(entries: &[(usize, u8, u32, u32)]) -> [u8; 512] {
        let mut bytes = [0; 512];
        bytes[510..].copy_from_slice(&MBR_SUFFIX);
        for &(slot, kind, start, length) in entries {
            let offset = TABLE_OFFSET + (slot - 1) * ENTRY_SIZE;
            bytes[offset + 4] = kind;
            bytes[offset + 8..offset + 12].copy_from_slice(&start.to_le_bytes());
            bytes[offset + 12..offset + 16].copy_from_slice(&length.to_le_bytes());
        }
        bytes
    }

    fn run() -> std::result::Result<(), String> {
        let motor = motor_fs::PARTITION_ID;
        let bytes = disk(&[(1, 0x83, 1, 4), (3, motor, 5, 16), (4, motor, 21, 8)]);
        let table = Mbr::parse(&bytes, 29).unwrap();
        st_assert_eq!(table.first_motor_fs().unwrap().0, 3);
        st_assert_eq!(table.motor_fs(3).unwrap().lba, 5);
        st_assert_eq!(table.motor_fs(4).unwrap().lba, 21);
        for slot in [0, 1, 2, 5, 255] {
            st_assert!(table.motor_fs(slot).is_err());
        }
        st_assert!(Mbr::parse(&bytes[..511], 29).is_err());
        st_assert!(Mbr::parse(&bytes, 28).is_err());
        st_assert!(Mbr::parse(&[0; 512], 29).is_err());
        for (start, length) in [(0, 8), (5, 0), (5, 25), (u32::MAX, 8)] {
            st_assert!(Mbr::parse(&disk(&[(3, motor, start, length)]), 29).is_err());
        }
        for other in [(1, 6), (6, 2), (20, 8)] {
            st_assert!(
                Mbr::parse(&disk(&[(3, motor, 5, 16), (4, 0x83, other.0, other.1)]), 29).is_err()
            );
        }
        // Do not renumber empty slots, or fall through an invalid lowest Motor FS slot.
        let table = Mbr::parse(&disk(&[(2, motor, 1, 7), (4, motor, 8, 8)]), 16).unwrap();
        st_assert!(
            table
                .first_motor_fs()
                .is_err_and(|error| error.to_string().contains("slot 2"))
        );
        st_assert!(table.motor_fs(4).is_ok());
        st_assert!(
            Mbr::parse(&disk(&[(1, 0x83, 1, 8)]), 9)
                .unwrap()
                .first_motor_fs()
                .is_err()
        );
        Ok(())
    }
}
