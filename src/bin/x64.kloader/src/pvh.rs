use core::mem::size_of;

use crate::util::vmm_exit;

// The PVH Boot Protocol starts at the 32-bit entrypoint to our firmware.
extern "C" {
    fn kloader_boot(); // defined in bootup_bsp.s
}

// The kind/name/desc of the PHV ELF Note are from xen/include/public/elfnote.h.
// This is the "Physical entry point into the kernel".
const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;
type Name = [u8; 4];
type Desc = unsafe extern "C" fn();

// We make sure our ELF Note has an alignment of 4 for maximum compatibility.
// Some software (QEMU) calculates padding incorectly if alignment != 4.
#[repr(C, packed(4))]
struct Note {
    name_size: u32,
    desc_size: u32,
    kind: u32,
    name: Name,
    desc: Desc,
}

// This is: ELFNOTE(Xen, XEN_ELFNOTE_PHYS32_ENTRY, .quad ram32_start)
#[link_section = ".note"]
#[used]
static PVH_NOTE: Note = Note {
    name_size: size_of::<Name>() as u32,
    desc_size: size_of::<Desc>() as u32,
    kind: XEN_ELFNOTE_PHYS32_ENTRY,
    name: *b"Xen\0",
    desc: kloader_boot,
};

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

#[derive(Debug)]
#[repr(C)]
pub struct PvhMemMapEntry {
    pub addr: u64,
    pub size: u64,
    pub entry_type: u32,
    reserved: u32,
}

impl PvhStartInfo {
    pub fn mem_map(&self) -> &[PvhMemMapEntry] {
        unsafe {
            core::slice::from_raw_parts(
                self.memmap_paddr as *mut PvhMemMapEntry,
                self.memmap_entries as usize,
            )
        }
    }

    pub fn initrd(&self) -> (usize, usize) {
        unsafe {
            if self.nr_modules != 1 {
                crate::raw_log!("ERROR: initrd not found in PvhStartInfo.\n");
                vmm_exit();
            }
            let md: &PvhModlistEntry = (self.modlist_paddr as usize as *const PvhModlistEntry)
                .as_ref()
                .unwrap();

            (md.paddr as usize, md.size as usize)
        }
    }

    pub fn initrd_bytes(&self) -> &'static [u8] {
        unsafe {
            let (start, len) = self.initrd();
            core::slice::from_raw_parts(
                ((crate::mm::PAGING_DIRECT_MAP_OFFSET as usize) + start) as *const u8,
                len,
            )
        }
    }

    pub fn init(pvh_addr: u64) -> &'static PvhStartInfo {
        let self_: &'static Self =
            unsafe { (pvh_addr as usize as *const PvhStartInfo).as_ref().unwrap() };

        if self_.magic != [b'x', b'E' + 0x80, b'n', b'3'] {
            crate::raw_log!("\nPVH magic bytes don't match.\n");
            panic!()
        }

        self_
    }
}
