use elfloader::*;

#[repr(C, align(64))]
struct AlignedBytes<B: ?Sized> {
    bytes: B,
}

static VDSO_BIN: &'static AlignedBytes<[u8]> = &AlignedBytes {
    bytes: *include_bytes!("../../lib/rt.vdso/rt.vdso"),
};

static VDSO_BYTES: &[u8] = &VDSO_BIN.bytes;

pub fn load() {
    // Load the binary.
    let elf_binary = ElfBinary::new(VDSO_BYTES).expect("ELF parsing failed.");
    if elf_binary.get_arch() != Machine::X86_64 {
        panic!("rt.bin vdso not X86_64.");
    }

    if elf_binary.interpreter().is_some() {
        panic!("rt.bin has a dynamic interpreter.");
    }

    let mut loader = VsdoLoader {};
    elf_binary
        .load(&mut loader)
        .expect("Error loading rt.bin elf.");

    let vdso_entry_addr: u64 = elf_binary.entry_point() + moto_rt::RT_VDSO_START;

    // Copy VDSO_BYTES into their canonical place.
    let vdso_bytes_sz = VDSO_BYTES.len() as u64;
    let num_pages = (vdso_bytes_sz + moto_sys::sys_mem::PAGE_SIZE_SMALL - 1)
        >> moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2;
    let addr = moto_sys::SysMem::map(
        moto_sys::SysHandle::SELF,
        moto_sys::SysMem::F_CUSTOM_USER
            | moto_sys::SysMem::F_READABLE
            | moto_sys::SysMem::F_WRITABLE,
        u64::MAX,
        moto_rt::RT_VDSO_BYTES_ADDR,
        moto_sys::sys_mem::PAGE_SIZE_SMALL,
        num_pages,
    )
    .unwrap();
    assert_eq!(addr, moto_rt::RT_VDSO_BYTES_ADDR);
    unsafe {
        core::intrinsics::copy_nonoverlapping(
            VDSO_BYTES.as_ptr(),
            moto_rt::RT_VDSO_BYTES_ADDR as usize as *mut u8,
            vdso_bytes_sz as usize,
        );
    }

    // Store vdso_entry_vaddr and init rt vtable.
    let addr = moto_sys::SysMem::map(
        moto_sys::SysHandle::SELF,
        moto_sys::SysMem::F_CUSTOM_USER
            | moto_sys::SysMem::F_READABLE
            | moto_sys::SysMem::F_WRITABLE,
        u64::MAX,
        moto_rt::RT_VDSO_VTABLE_VADDR,
        moto_sys::sys_mem::PAGE_SIZE_SMALL,
        1,
    )
    .unwrap();
    assert_eq!(addr, moto_rt::RT_VDSO_VTABLE_VADDR);

    let vdso_vtable = unsafe {
        (moto_rt::RT_VDSO_VTABLE_VADDR as usize as *const moto_rt::RtVdsoVtableV1)
            .as_ref()
            .unwrap()
    };
    vdso_vtable
        .vdso_entry
        .store(vdso_entry_addr, std::sync::atomic::Ordering::Relaxed);
    vdso_vtable
        .vdso_bytes_sz
        .store(vdso_bytes_sz, std::sync::atomic::Ordering::Release);

    // ProcessData (zeroed).
    let addr = moto_sys::SysMem::map(
        moto_sys::SysHandle::SELF,
        moto_sys::SysMem::F_CUSTOM_USER
            | moto_sys::SysMem::F_READABLE
            | moto_sys::SysMem::F_WRITABLE,
        u64::MAX,
        moto_rt::MOTO_SYS_CUSTOM_USERSPACE_REGION_START,
        moto_sys::sys_mem::PAGE_SIZE_SMALL,
        1,
    )
    .unwrap();
    assert_eq!(addr, moto_rt::MOTO_SYS_CUSTOM_USERSPACE_REGION_START);

    moto_rt::init();
}

struct VsdoLoader {}

impl ElfLoader for VsdoLoader {
    fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<(), ElfLoaderErr> {
        use moto_rt::RT_VDSO_START;

        // We load VDSO at a fixed virtual address, as address randomization
        // is mostly security theader: https://grsecurity.net/kaslr_an_exercise_in_cargo_cult_security
        for header in load_headers {
            let vaddr_start =
                RT_VDSO_START + header.virtual_addr() & !(moto_sys::sys_mem::PAGE_SIZE_SMALL - 1);
            let vaddr_end = moto_sys::align_up(
                RT_VDSO_START + header.virtual_addr() + header.mem_size(),
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
            let addr = (moto_rt::RT_VDSO_START + base) as usize as *mut u8;
            core::ptr::copy_nonoverlapping(region.as_ptr(), addr, region.len());
        }
        Ok(())
    }

    fn relocate(&mut self, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        use elfloader::arch::x86_64::RelocationTypes::*;
        use RelocationType::x86_64;

        let addr: u64 = moto_rt::RT_VDSO_START + entry.offset;
        match entry.rtype {
            x86_64(R_AMD64_RELATIVE) => {
                // This type requires addend to be present.
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;

                // Need to write (addend + base) into addr.
                unsafe {
                    *(addr as usize as *mut u64) = moto_rt::RT_VDSO_START + addend;
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
