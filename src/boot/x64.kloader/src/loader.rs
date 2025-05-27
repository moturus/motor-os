// Same as in img-builder.
#[repr(C)]
#[derive(Debug)]
struct InitrdHeader {
    magic: u32,
    kloader_start: u32,
    kloader_end: u32,
    kernel_start: u32,
    kernel_end: u32,
}

impl InitrdHeader {
    const MAGIC: u32 = 0xf402_100f; // Whatever.

    fn from_addr(addr: usize) -> &'static Self {
        unsafe {
            let result = (addr as *const Self).as_ref().unwrap();
            if result.magic != Self::MAGIC {
                panic!("INITRD header magic bytes don't match.")
            }
            result
        }
    }
}

static KERNEL_ENTRY_POINT: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
#[derive(Debug)]
struct KernelBootupInfo {
    pvh_addr: u64, // *const PvhStartInfo
    start_tsc: u64,
    max_ram_offset: u64, // Max in use memory offset above 34M phys
    num_cpus: u32,
}

pub fn load_kernel_bsp(pvh: &'static crate::pvh::PvhStartInfo, num_cpus: u32, start_tsc: u64) -> ! {
    #[cfg(debug_assertions)]
    crate::raw_log!("load_kernel_bsp start\n");

    // We just load the kernel into its high address and jump there. The rest is
    // the kernel's responsibility.
    // crate::raw_log!("loading the kernel\n");
    let kernel_bytes = {
        let initrd_bytes = pvh.initrd_bytes();
        #[cfg(debug_assertions)]
        {
            let (start, len) = pvh.initrd();
            crate::raw_log!(
                "initrd: start: 0x{:x} == {}, len: 0x{:x} == {})\n",
                start,
                start,
                len,
                len
            );
        }
        let header = InitrdHeader::from_addr(initrd_bytes.as_ptr() as usize);
        &initrd_bytes[header.kernel_start as usize..header.kernel_end as usize]
    };

    #[cfg(debug_assertions)]
    crate::raw_log!("will load kernel\n");

    let (entry_point_raw, max_ram_offset) = load_kernel(kernel_bytes);

    #[cfg(debug_assertions)]
    crate::raw_log!("kernel loaded\n");

    let entry_point = entry_point_raw + crate::mm::kernel_offset();
    KERNEL_ENTRY_POINT.store(entry_point, Ordering::Release);

    let bootup_info = alloc::boxed::Box::new(KernelBootupInfo {
        pvh_addr: pvh as *const _ as usize as u64,
        start_tsc,
        max_ram_offset,
        num_cpus,
    });

    let bootup_info_addr = alloc::boxed::Box::leak(bootup_info) as *mut _ as usize as u64;
    crate::util::full_fence();

    #[cfg(debug_assertions)]
    crate::raw_log!(
        "jumping into the kernel at 0x{:x} (+ mapping offset)\n",
        entry_point_raw
    );

    unsafe { jump_to_kernel(bootup_info_addr, entry_point) }
}

#[unsafe(naked)]
unsafe extern "C" fn jump_to_kernel(arg0: u64, entry_point: u64) -> ! {
    // rdi, rsi, rdx
    core::arch::naked_asm!("call rsi")
}

pub fn jump_into_kernel_ap() -> ! {
    // This may be called before the kernel is loaded by bsp, so we must synchronize
    // with load_kernel_bsp().
    loop {
        let entry_point = KERNEL_ENTRY_POINT.load(Ordering::Relaxed);
        if entry_point == 0 {
            core::hint::spin_loop();
            continue;
        }
        unsafe { jump_to_kernel(0, entry_point) }
    }
}

use core::sync::atomic::{AtomicU64, Ordering};

use elfloader::*;

// Returns the entry point and the max ram offset.
fn load_kernel(bytes: &'static [u8]) -> (u64, u64) {
    // crate::raw_log!("parsing kernel: {} bytes\n", bytes.len());
    let elf_binary = ElfBinary::new(bytes).expect("ELF parsing failed.");

    if elf_binary.get_arch() != Machine::X86_64 {
        panic!("The ELF binary not X86_64.");
    }

    if elf_binary.interpreter().is_some() {
        panic!("The ELF binary has a dynamic interpreter.");
    }

    let mut kernel_loader = KernelLoader {
        relocated: false,
        max_offset: 0,
    };

    // crate::raw_log!("loading kernel\n");
    elf_binary
        .load(&mut kernel_loader)
        .expect("ELF loading failed.");

    (elf_binary.entry_point(), kernel_loader.max_offset)
}

struct KernelLoader {
    relocated: bool,
    max_offset: u64,
}

impl ElfLoader for KernelLoader {
    fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<(), ElfLoaderErr> {
        // We load the kernel at fixed physical/virtual addressess, as KASLR
        // is mostly security theader: https://grsecurity.net/kaslr_an_exercise_in_cargo_cult_security
        for header in load_headers {
            self.max_offset = self
                .max_offset
                .max(header.virtual_addr() + header.mem_size());
        }
        Ok(())
    }

    fn load(&mut self, _flags: Flags, base: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
        unsafe {
            core::ptr::copy_nonoverlapping(
                region.as_ptr(),
                (crate::mm::kernel_offset() + base) as usize as *mut u8,
                region.len(),
            );
        }
        Ok(())
    }

    fn relocate(&mut self, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        use elfloader::arch::x86_64::RelocationTypes::*;
        use RelocationType::x86_64;

        let addr: u64 = crate::mm::kernel_offset() + entry.offset;

        match entry.rtype {
            x86_64(R_AMD64_RELATIVE) => {
                // This type requires addend to be present
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;

                // Need to write (addend + base) into addr.
                unsafe {
                    *(addr as usize as *mut u64) = crate::mm::kernel_offset() + addend;
                }

                self.relocated = true;

                Ok(())
            }
            x86_64(R_AMD64_NONE) => Ok(()),
            _ => {
                panic!("unrecognized entry type: {:#?}", entry.rtype)
            }
        }
    }
}
