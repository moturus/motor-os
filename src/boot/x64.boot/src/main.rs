#![no_std]
#![no_main]

use crate::protected_mode::{enter_protected_mode_and_jump_to_stage_3, enter_unreal_mode};
use byteorder::{ByteOrder, LittleEndian};
use core::slice;
use disk::AlignedArrayBuffer;
use mbr_nostd::{PartitionTableEntry, PartitionType};

mod dap;
mod disk;
mod memory_map;
mod protected_mode;
mod serial;

#[derive(Debug)]
#[repr(C)]
pub struct PvhModlistEntry {
    pub paddr: u64,
    pub size: u64,
    cmdline_paddr: u64,
    _reserved: u64,
}

// Structures from xen/include/public/arch-x86/hvm/start_info.h
#[derive(Debug)]
#[repr(C)]
pub struct PvhStartInfo {
    magic: [u8; 4],
    version: u32,
    flags: u32,
    pub nr_modules: u32,
    pub modlist_paddr: u64,
    pub cmdline_paddr: u64,
    pub rsdp_paddr: u64,
    pub memmap_paddr: u64,
    pub memmap_entries: u32,
    _pad: u32,
}

impl PvhStartInfo {
    fn new(memmap: &'static [memory_map::E820MemoryRegion], initrd: &PvhModlistEntry) -> Self {
        Self {
            magic: [b'x', b'E' + 0x80, b'n', b'3'],
            version: 1,
            flags: 0,
            nr_modules: 1,
            modlist_paddr: initrd as *const _ as usize as u64,
            cmdline_paddr: 0,
            rsdp_paddr: 0,
            memmap_paddr: memmap.as_ptr() as usize as u64,
            memmap_entries: memmap.len() as u32,
            _pad: 0,
        }
    }
}

const INITRD_ADDR: u32 = 1024 * 1024;

// Reading in 4k blocks is _much_ faster than reading in 512 blocks.
const BLOCK_SIZE: usize = 4096;
static mut DISK_BUFFER: AlignedArrayBuffer<BLOCK_SIZE> = AlignedArrayBuffer {
    buffer: [0; BLOCK_SIZE],
};

#[no_mangle]
#[link_section = ".start"]
pub extern "C" fn _start(disk_number: u16, partition_table_start: *const u8) -> ! {
    start(disk_number, partition_table_start)
}

fn start(disk_number: u16, partition_table_start: *const u8) -> ! {
    // Enter unreal mode before doing anything else.
    enter_unreal_mode();

    // parse partition table
    let partitions = {
        const MAX_ENTRIES: usize = 4;
        const ENTRY_SIZE: usize = 16;

        let mut entries = [PartitionTableEntry::empty(); MAX_ENTRIES];
        let raw = unsafe { slice::from_raw_parts(partition_table_start, ENTRY_SIZE * MAX_ENTRIES) };
        for (idx, entry) in entries.iter_mut().enumerate() {
            let offset = idx * ENTRY_SIZE;
            let partition_type = PartitionType::from_mbr_tag_byte(raw[offset + 4]);
            let lba = LittleEndian::read_u32(&raw[offset + 8..]);
            let len = LittleEndian::read_u32(&raw[offset + 12..]);
            *entry = PartitionTableEntry::new(partition_type, lba, len);
        }
        entries
    };
    let initrd_partition = partitions.get(1).unwrap();

    // load initrd
    let mut disk = disk::DiskAccess {
        disk_number,
        base_offset: u64::from(initrd_partition.logical_block_address) * 512,
    };

    let initrd_start = INITRD_ADDR as usize;
    let initrd_len = (initrd_partition.sector_count * 512) as usize;

    #[allow(static_mut_refs)]
    let disk_buffer = unsafe { &mut DISK_BUFFER };

    let mut sector_pos = 0_usize;
    let mut dst: u32 = initrd_start as u32;

    while sector_pos < initrd_len {
        disk.read_exact_into(sector_pos, BLOCK_SIZE, disk_buffer);

        let slice_u8 = &disk_buffer.buffer[..BLOCK_SIZE];
        let slice_u32 = unsafe {
            core::slice::from_raw_parts(slice_u8.as_ptr() as *const u32, slice_u8.len() >> 2)
        };
        for val in slice_u32 {
            unsafe {
                core::arch::asm!("mov [{:e}], {:e}", in(reg) dst, in(reg) *val);
            }
            dst += 4;
        }

        sector_pos += BLOCK_SIZE;
    }
    // Load memory map after the initrd load because a file load corrupts memmap memory.
    // TODO: fix the corruption issue.
    let memory_map = unsafe { memory_map::query_memory_map() }.unwrap();

    let initrd_mod = PvhModlistEntry {
        paddr: initrd_start as u64,
        size: initrd_len as u64,
        cmdline_paddr: 0,
        _reserved: 0,
    };

    let pvh = PvhStartInfo::new(memory_map, &initrd_mod);

    enter_protected_mode_and_jump_to_stage_3(
        INITRD_ADDR + 512 as u32,
        &pvh as *const _ as usize as u32,
    );

    loop {}
}

#[cold]
#[inline(never)]
#[no_mangle]
pub extern "C" fn fail(code: u8) -> ! {
    panic!("fail: {}", code as char);
}

#[panic_handler]
#[cfg(not(test))]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    serial::write_serial!("PANIC: {info}\n");
    loop {}
}
