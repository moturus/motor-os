use core::sync::atomic::Ordering;

use alloc::collections::btree_map::BTreeMap;
use elfloader::ElfBinary;
use moto_sys::{sys_mem, ErrorCode, SysHandle, SysMem};

pub fn load_vdso(address_space: u64) -> ErrorCode {
    let address_space = SysHandle::from_u64(address_space);

    let entry_point = match load_binary(address_space) {
        Ok(e) => e,
        Err(err) => return err,
    };

    match init_remote_vdso(address_space, entry_point) {
        Ok(()) => moto_rt::E_OK,
        Err(err) => err,
    }
}

fn init_remote_vdso(address_space: SysHandle, entry_point: u64) -> Result<(), ErrorCode> {
    // Map/copy VDSO bytes.
    // TODO: instead of copying VDSO bytes, map the pages.
    let flags = SysMem::F_SHARE_SELF | SysMem::F_READABLE;
    let vdso_bytes_sz = moto_rt::RtVdsoVtable::get()
        .vdso_bytes_sz
        .load(Ordering::Relaxed);
    let num_pages = (vdso_bytes_sz + sys_mem::PAGE_SIZE_SMALL - 1) >> sys_mem::PAGE_SIZE_SMALL_LOG2;

    let (remote, local) = SysMem::map2(
        address_space,
        flags,
        u64::MAX,
        moto_rt::RT_VDSO_BYTES_ADDR,
        sys_mem::PAGE_SIZE_SMALL,
        num_pages,
    )?;
    assert_eq!(remote, moto_rt::RT_VDSO_BYTES_ADDR);

    unsafe {
        core::ptr::copy_nonoverlapping(
            moto_rt::RT_VDSO_BYTES_ADDR as usize as *const u8,
            local as usize as *mut u8,
            vdso_bytes_sz as usize,
        );
    }
    SysMem::unmap(SysHandle::SELF, 0, u64::MAX, local).unwrap();

    // Write entry_point and vdso_bytes_sz.
    let flags = SysMem::F_SHARE_SELF | SysMem::F_READABLE | SysMem::F_WRITABLE;
    let (remote, local) = SysMem::map2(
        address_space,
        flags,
        u64::MAX,
        moto_rt::RT_VDSO_VTABLE_VADDR,
        sys_mem::PAGE_SIZE_SMALL,
        1,
    )?;
    assert_eq!(remote, moto_rt::RT_VDSO_VTABLE_VADDR);

    let remote_vdso_vtable = unsafe {
        (local as usize as *const moto_rt::RtVdsoVtable)
            .as_ref()
            .unwrap()
    };
    remote_vdso_vtable
        .vdso_entry
        .store(entry_point, Ordering::Relaxed);
    remote_vdso_vtable
        .vdso_bytes_sz
        .store(vdso_bytes_sz, Ordering::Release);

    SysMem::unmap(SysHandle::SELF, 0, u64::MAX, local).unwrap();
    Ok(())
}

// On success, return the _vdso_entry.
fn load_binary(address_space: SysHandle) -> Result<u64, ErrorCode> {
    let vdso_bytes = unsafe {
        core::slice::from_raw_parts(
            moto_rt::RT_VDSO_BYTES_ADDR as usize as *const u8,
            moto_rt::RtVdsoVtable::get()
                .vdso_bytes_sz
                .load(Ordering::Relaxed) as usize,
        )
    };
    let elf_binary = match ElfBinary::new(vdso_bytes) {
        Err(_) => {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        Ok(binary) => binary,
    };

    if elf_binary.get_arch() != elfloader::Machine::X86_64 {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    if elf_binary.interpreter().is_some() {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let mut elf_loader = RemoteLoader {
        address_space,
        relocated: false,
        offset: moto_rt::RT_VDSO_START,
        mapped_regions: BTreeMap::default(),
    };

    if elf_binary.load(&mut elf_loader).is_err() {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    };

    Ok(elf_binary.entry_point() + moto_rt::RT_VDSO_START)
}

struct RemoteLoader {
    address_space: SysHandle,
    relocated: bool,
    offset: u64,

    // Map of allocated pages: remote addr -> (local addr, num_pages).
    mapped_regions: BTreeMap<u64, (u64, u64)>,
}

impl RemoteLoader {
    unsafe fn write_remotely(&mut self, dst: u64, src: *const u8, sz: u64) {
        // There shouldn't be too many entries in the map, so we can just linearly iterate.
        let mut region: Option<(u64, u64, u64)> = None;
        for entry in &self.mapped_regions {
            if *entry.0 <= dst {
                region = Some((*entry.0, entry.1 .0, entry.1 .1));
            } else {
                break;
            }
        }

        let region = region.unwrap();

        let remote_region_start = region.0;
        let local_region_start = region.1;
        let region_sz = region.2 << sys_mem::PAGE_SIZE_SMALL_LOG2;

        assert!(remote_region_start <= dst);
        assert!((dst + sz) <= (region.0 + region_sz));

        let offset = dst - remote_region_start;

        core::ptr::copy_nonoverlapping(
            src,
            (local_region_start + offset) as usize as *mut u8,
            sz as usize,
        );
    }
}

impl Drop for RemoteLoader {
    fn drop(&mut self) {
        for (addr, _) in self.mapped_regions.values() {
            SysMem::unmap(SysHandle::SELF, 0, u64::MAX, *addr).unwrap();
        }
    }
}

impl elfloader::ElfLoader for RemoteLoader {
    fn allocate(
        &mut self,
        load_headers: elfloader::LoadableHeaders<'_, '_>,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        for header in load_headers {
            let vaddr_start = header.virtual_addr() & !(sys_mem::PAGE_SIZE_SMALL - 1);
            let vaddr_end = moto_sys::align_up(
                header.virtual_addr() + header.mem_size(),
                sys_mem::PAGE_SIZE_SMALL,
            );

            let mut flags = SysMem::F_SHARE_SELF;
            if header.flags().is_read() {
                flags |= SysMem::F_READABLE;
            }
            if header.flags().is_write() {
                flags |= SysMem::F_WRITABLE;
            }

            let num_pages = (vaddr_end - vaddr_start) >> sys_mem::PAGE_SIZE_SMALL_LOG2;

            let (remote, local) = SysMem::map2(
                self.address_space,
                flags,
                u64::MAX,
                vaddr_start + self.offset,
                sys_mem::PAGE_SIZE_SMALL,
                num_pages,
            )
            .map_err(|_| elfloader::ElfLoaderErr::OutOfMemory)?;

            assert_eq!(remote, vaddr_start + self.offset);
            self.mapped_regions.insert(vaddr_start, (local, num_pages));
        }
        Ok(())
    }

    fn load(
        &mut self,
        _flags: elfloader::Flags,
        base: elfloader::VAddr,
        region: &[u8],
    ) -> Result<(), elfloader::ElfLoaderErr> {
        unsafe {
            self.write_remotely(base, region.as_ptr(), region.len() as u64);
        }

        Ok(())
    }

    fn relocate(
        &mut self,
        entry: elfloader::RelocationEntry,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        use elfloader::arch::x86_64::RelocationTypes::*;
        use elfloader::RelocationType::x86_64;

        let remote_addr: u64 = entry.offset;

        match entry.rtype {
            x86_64(R_AMD64_RELATIVE) => {
                // This type requires addend to be present.
                let addend: u64 = self.offset
                    + entry
                        .addend
                        .ok_or(elfloader::ElfLoaderErr::UnsupportedRelocationEntry)?;

                // Need to write (addend + base) into addr.
                unsafe {
                    self.write_remotely(
                        remote_addr,
                        &addend as *const _ as *const u8,
                        core::mem::size_of::<u64>() as u64,
                    );
                }

                self.relocated = true;

                Ok(())
            }
            x86_64(R_AMD64_NONE) => Ok(()),
            _ => Err(elfloader::ElfLoaderErr::UnsupportedRelocationEntry),
        }
    }

    fn tls(
        &mut self,
        _tdata_start: elfloader::VAddr,
        _tdata_length: u64,
        _total_size: u64,
        _align: u64,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        Err(elfloader::ElfLoaderErr::UnsupportedAbi)
    }
}
