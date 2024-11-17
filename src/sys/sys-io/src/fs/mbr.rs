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
            flatfs::PARTITION_ID => PartitionType::FlatFs, // 0x2c
            srfs::PARTITION_ID => PartitionType::SrFs,     // 0x2d
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
    pub fn parse(bytes: &[u8]) -> Result<Mbr, &str> {
        assert_eq!(bytes.len(), MBR_SIZE);

        if bytes[MBR_SIZE - MBR_SUFFIX.len()..MBR_SIZE] != MBR_SUFFIX[..] {
            return Err("MBR suffix wrong.");
        }
        let mut entries = [PartitionTableEntry::empty(); MAX_ENTRIES];
        #[allow(clippy::needless_range_loop)]
        for idx in 0..MAX_ENTRIES {
            let offset = TABLE_OFFSET + idx * ENTRY_SIZE;
            let partition_type = PartitionType::from_mbr_tag_byte(bytes[offset + 4]);
            let lba = read_u32(bytes, offset + 8);
            let len = read_u32(bytes, offset + 12);
            entries[idx] = PartitionTableEntry::new(partition_type, lba, len);
        }
        Ok(Mbr { entries })
    }
}
