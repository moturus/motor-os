use elfloader::*;

#[repr(C, align(64))]
struct AlignedBytes<B: ?Sized> {
    bytes: B,
}

static VDSO_BIN: &AlignedBytes<[u8]> = &AlignedBytes {
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

    let mut loader = VsdoLoader {
        mapped_regions: [(0, 0, 0); VsdoLoader::MAX_REGIONS],
        num_regions: 0,
    };
    elf_binary
        .load(&mut loader)
        .expect("Error loading rt.bin elf.");
    core::mem::drop(loader); // Unmaps the RW aliases.

    let vdso_entry_addr: u64 = elf_binary.entry_point() + moto_rt::RT_VDSO_START;
    assert_ne!(0, vdso_entry_addr);

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
        (moto_rt::RT_VDSO_VTABLE_VADDR as usize as *const moto_rt::RtVdsoVtable)
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

    if moto_rt::RT_VERSION != std::os::motor::rt_version() {
        log::error!(
            "\n\n-- Rust std library expects moto-rt version {}; but we have {}.\n-- Something is not right.\n",
            std::os::motor::rt_version(),
            moto_rt::RT_VERSION
        );
        moto_sys::SysCpu::exit_process(0xbadc0de)
    }
}

struct VsdoLoader {
    // Segment regions: (unoffset vaddr, local RW alias, num_pages).
    // W^X: the vdso text is mapped R+X at its fixed address; all writes
    // (loading, relocation) go through the R+W alias side of a self-share.
    //
    // NO HEAP ALLOCATIONS here: the global allocator dispatches through
    // the vdso vtable, which is initialized only after this loader runs.
    mapped_regions: [(u64, u64, u64); Self::MAX_REGIONS],
    num_regions: usize,
}

impl VsdoLoader {
    const MAX_REGIONS: usize = 16;

    // `dst` is an unoffset vdso vaddr; writes through the RW alias.
    unsafe fn write_via_alias(&self, dst: u64, src: *const u8, sz: u64) {
        let mut region: Option<(u64, u64, u64)> = None;
        for entry in &self.mapped_regions[..self.num_regions] {
            let region_sz = entry.2 << moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2;
            if entry.0 <= dst && (dst + sz) <= (entry.0 + region_sz) {
                region = Some(*entry);
                break;
            }
        }
        let (region_start, alias_start, _) = region.unwrap();

        unsafe {
            core::ptr::copy_nonoverlapping(
                src,
                (alias_start + (dst - region_start)) as usize as *mut u8,
                sz as usize,
            )
        };
    }
}

impl Drop for VsdoLoader {
    fn drop(&mut self) {
        for (_, alias, _) in &self.mapped_regions[..self.num_regions] {
            moto_sys::SysMem::unmap(moto_sys::SysHandle::SELF, 0, u64::MAX, *alias).unwrap();
        }
    }
}

impl ElfLoader for VsdoLoader {
    fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<(), ElfLoaderErr> {
        use moto_rt::RT_VDSO_START;

        // We load VDSO at a fixed virtual address, as address randomization
        // is mostly security theader: https://grsecurity.net/kaslr_an_exercise_in_cargo_cult_security
        for header in load_headers {
            let vaddr_start =
                header.virtual_addr() & !(moto_sys::sys_mem::PAGE_SIZE_SMALL - 1);
            let vaddr_end = moto_sys::align_up(
                header.virtual_addr() + header.mem_size(),
                moto_sys::sys_mem::PAGE_SIZE_SMALL,
            );

            let mut flags = moto_sys::SysMem::F_SHARE_SELF;
            if header.flags().is_read() {
                flags |= moto_sys::SysMem::F_READABLE;
            }
            if header.flags().is_write() {
                flags |= moto_sys::SysMem::F_WRITABLE;
            }
            if header.flags().is_execute() && !header.flags().is_write() {
                flags |= moto_sys::SysMem::F_EXECUTABLE;
            }

            let num_pages = (vaddr_end - vaddr_start) >> moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2;
            let (addr, alias) = moto_sys::SysMem::map2(
                moto_sys::SysHandle::SELF,
                flags,
                u64::MAX,
                RT_VDSO_START + vaddr_start,
                moto_sys::sys_mem::PAGE_SIZE_SMALL,
                num_pages,
            )
            .map_err(|_| ElfLoaderErr::OutOfMemory)?;
            assert_eq!(addr, RT_VDSO_START + vaddr_start);
            assert!(self.num_regions < Self::MAX_REGIONS);
            self.mapped_regions[self.num_regions] = (vaddr_start, alias, num_pages);
            self.num_regions += 1;
        }
        Ok(())
    }

    fn load(&mut self, _flags: Flags, base: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
        unsafe {
            self.write_via_alias(base, region.as_ptr(), region.len() as u64);
        }
        Ok(())
    }

    fn relocate(&mut self, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        use RelocationType::x86_64;
        use elfloader::arch::x86_64::RelocationTypes::*;

        match entry.rtype {
            x86_64(R_AMD64_RELATIVE) => {
                // This type requires addend to be present.
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;

                // Need to write (addend + base) into addr.
                let value = moto_rt::RT_VDSO_START + addend;
                unsafe {
                    self.write_via_alias(
                        entry.offset,
                        &value as *const _ as *const u8,
                        core::mem::size_of::<u64>() as u64,
                    );
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
