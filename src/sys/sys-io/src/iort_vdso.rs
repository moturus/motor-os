use elfloader::*;

#[repr(C, align(64))]
struct AlignedBytes<B: ?Sized> {
    bytes: B,
}

static VDSO_BIN: &'static AlignedBytes<[u8]> = &AlignedBytes {
    bytes: *include_bytes!("../../lib/iort.vdso/iort.vdso"),
};

static VDSO_BYTES: &[u8] = &VDSO_BIN.bytes;

pub fn load() {
    let elf_binary = ElfBinary::new(VDSO_BYTES).expect("ELF parsing failed.");
    if elf_binary.get_arch() != Machine::X86_64 {
        panic!("iort.bin vdso not X86_64.");
    }

    if elf_binary.interpreter().is_some() {
        panic!("iort.bin has a dynamic interpreter.");
    }

    let mut loader = VsdoLoader {};
    elf_binary
        .load(&mut loader)
        .expect("Error loading iort.bin elf.");

    let vdso_entry_addr: u64 = elf_binary.entry_point() + moto_iort::IORT_VDSO_START;

    // Initialize IortVdsoVtable.
    let addr = moto_sys::SysMem::map(
        moto_sys::SysHandle::SELF,
        moto_sys::SysMem::F_CUSTOM_USER
            | moto_sys::SysMem::F_READABLE
            | moto_sys::SysMem::F_WRITABLE,
        u64::MAX,
        moto_iort::IortVdsoVtable::VADDR,
        moto_sys::sys_mem::PAGE_SIZE_SMALL,
        1,
    )
    .unwrap();
    assert_eq!(addr, moto_iort::IortVdsoVtable::VADDR);
    moto_iort::IortVdsoVtable::get()
        .vdso_entry
        .store(vdso_entry_addr, std::sync::atomic::Ordering::SeqCst);
    // This is a temporary test.
    let res = moto_iort::iort_entry(5);
    assert_eq!(res, 47);
}

struct VsdoLoader {}

impl ElfLoader for VsdoLoader {
    fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<(), ElfLoaderErr> {
        use moto_iort::IORT_VDSO_START;

        // We load VDSO at a fixed virtual address, as address randomization
        // is mostly security theader: https://grsecurity.net/kaslr_an_exercise_in_cargo_cult_security
        for header in load_headers {
            let vaddr_start =
                IORT_VDSO_START + header.virtual_addr() & !(moto_sys::sys_mem::PAGE_SIZE_SMALL - 1);
            let vaddr_end = moto_sys::align_up(
                IORT_VDSO_START + header.virtual_addr() + header.mem_size(),
                moto_sys::sys_mem::PAGE_SIZE_SMALL,
            );

            // Always readable; must be writable to actually load it in there.
            let flags = moto_sys::SysMem::F_CUSTOM_USER
                | moto_sys::SysMem::F_READABLE
                | moto_sys::SysMem::F_WRITABLE;

            let num_pages = (vaddr_end - vaddr_start) >> moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2;
            let addr = moto_sys::SysMem::map(
                moto_sys::SysHandle::SELF,
                flags,
                u64::MAX,
                vaddr_start,
                moto_sys::sys_mem::PAGE_SIZE_SMALL,
                num_pages,
            )
            .map_err(|_| ElfLoaderErr::OutOfMemory)?;
            assert_eq!(addr, vaddr_start);
        }
        Ok(())
    }

    fn load(&mut self, _flags: Flags, base: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
        unsafe {
            let addr = (moto_iort::IORT_VDSO_START + base) as usize as *mut u8;
            core::ptr::copy_nonoverlapping(region.as_ptr(), addr, region.len());
        }
        Ok(())
    }

    fn relocate(&mut self, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        use elfloader::arch::x86_64::RelocationTypes::*;
        use RelocationType::x86_64;

        let addr: u64 = moto_iort::IORT_VDSO_START + entry.offset;
        match entry.rtype {
            x86_64(R_AMD64_RELATIVE) => {
                // This type requires addend to be present.
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;

                // Need to write (addend + base) into addr.
                unsafe {
                    *(addr as usize as *mut u64) = moto_iort::IORT_VDSO_START + addend;
                }

                Ok(())
            }
            x86_64(R_AMD64_NONE) => Ok(()),
            _ => {
                panic!("unrecognized entry type: {:#?}", entry.rtype)
            }
        }
    }
}
