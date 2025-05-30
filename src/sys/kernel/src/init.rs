use crate::config::uCpus;
use crate::mm::{PAGE_SIZE_SMALL, PAGE_SIZE_SMALL_LOG2};
use core::sync::atomic::*;

#[repr(C)]
#[derive(Debug)]
struct InitrdHeader {
    magic: u32,
    kloader_start: u32,
    kloader_end: u32,
    kernel_start: u32,
    kernel_end: u32,
    sys_io_start: u32,
    sys_io_end: u32,
}

impl InitrdHeader {
    const MAGIC: u32 = 0xf402_100f; // Whatever.

    fn from_addr(addr: usize) -> &'static Self {
        unsafe { (addr as *const InitrdHeader).as_ref().unwrap() }
    }
}

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

impl PvhMemMapEntry {
    pub fn available(&self) -> bool {
        self.entry_type == 1
    }

    pub fn to_segment(&self) -> crate::mm::MemorySegment {
        crate::mm::MemorySegment {
            start: self.addr,
            size: self.size,
        }
    }
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

    fn initrd(&self) -> (u64, u64) {
        unsafe {
            if self.nr_modules != 1 {
                panic!("ERROR: initrd not found in PvhStartInfo.");
            }
            let md: &PvhModlistEntry = (self.modlist_paddr as usize as *const PvhModlistEntry)
                .as_ref()
                .unwrap();

            (md.paddr, md.size)
        }
    }

    fn initrd_bytes(&self) -> &'static [u8] {
        unsafe {
            let (start, len) = self.initrd();
            core::slice::from_raw_parts(
                ((crate::mm::PAGING_DIRECT_MAP_OFFSET as usize) + start as usize) as *const u8,
                len as usize,
            )
        }
    }

    fn sys_io_bytes(&self) -> &'static [u8] {
        let (start, len) = self.initrd();
        assert!(len > 4096);

        let header =
            InitrdHeader::from_addr((crate::mm::PAGING_DIRECT_MAP_OFFSET + start) as usize);
        assert_eq!(header.magic, InitrdHeader::MAGIC);
        assert!(header.sys_io_end <= len as u32);

        let initrd = self.initrd_bytes();
        &initrd[(header.sys_io_start as usize)..(header.sys_io_end as usize)]
    }

    fn init(pvh_addr: u64) -> &'static PvhStartInfo {
        let self_: &'static Self =
            unsafe { (pvh_addr as usize as *const PvhStartInfo).as_ref().unwrap() };

        if self_.magic != [b'x', b'E' + 0x80, b'n', b'3'] {
            crate::raw_log!("\nPVH magic bytes don't match.\n");
            panic!()
        }

        self_
    }
}

fn print_boot_logo() {
    crate::arch::arch_write_serial!("\nMOTOR OS ... ");

    // crate::raw_log!(" ███╗   ███╗ ██████╗ ████████╗ ██████╗ ██████╗      ██████╗  █████╗ ");
    // crate::raw_log!(" ████╗ ████║██╔═══██╗╚══██╔══╝██╔═══██╗██╔══██╗    ██╔═══██╗██╔═══╝ ");
    // crate::raw_log!(" ██╔████╔██║██║   ██║   ██║   ██║   ██║██████╔╝    ██║   ██║╚█████╗ ");
    // crate::raw_log!(" ██║╚██╔╝██║██║   ██║   ██║   ██║   ██║██╔══██╗    ██║   ██║╚════██║");
    // crate::raw_log!(" ██║ ╚═╝ ██║╚██████╔╝   ██║   ╚██████╔╝██║  ██║    ╚██████╔╝██████╔╝");
    // crate::raw_log!(" ╚═╝     ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝     ╚═════╝ ╚═════╝ ");
    // crate::raw_log!("\n");
}

pub fn init_exited(init: &crate::uspace::Process) -> ! {
    let status = init.status();

    match status {
        crate::uspace::process::ProcessStatus::Exited(exit_code) => {
            if exit_code == 0 {
                log::debug!("sys-io exited with status {exit_code}.");
            } else {
                log::warn!("sys-io exited with status {exit_code}.");
            }
            crate::arch::kernel_exit();
        }
        crate::uspace::process::ProcessStatus::Killed => {
            log::warn!("sys-io killed.");
            crate::arch::kernel_exit();
        }
        _ => {
            log::error!("sys-io: unexpected status: {status:?}.");
            panic!()
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KernelBootupInfo {
    pvh_addr: u64, // *const PvhStartInfo
    start_tsc: u64,
    max_ram_offset: u64, // Max in use memory offset above 34M phys
    num_cpus: u32,
}

impl KernelBootupInfo {
    pub fn validate(&self) {
        assert!(self.num_cpus <= (crate::config::MAX_CPUS as u32));
        assert!(self
            .kernel_bytes_phys()
            .intersect(&self.initrd_bytes_phys())
            .is_empty());
        let _ = PvhStartInfo::init(self.pvh_addr);

        #[cfg(debug_assertions)]
        {
            crate::raw_log!(
                "Boot info at 0x{:#x?}: {:?}",
                self as *const _ as usize,
                self
            );
            crate::raw_log!("PVH: 0x{:#x?}", self.pvh());
            crate::raw_log!("PVH MemMap: 0x{:#x?}", self.pvh().mem_map());
        }
    }

    pub fn kernel_bytes_phys(&self) -> crate::mm::MemorySegment {
        crate::mm::MemorySegment {
            start: crate::mm::KERNEL_PHYS_START,
            size: self.max_ram_offset,
        }
    }

    pub fn initrd_bytes_phys(&self) -> crate::mm::MemorySegment {
        let (start, size) = self.pvh().initrd();
        crate::mm::MemorySegment { start, size }
    }

    pub fn pvh(&self) -> &PvhStartInfo {
        PvhStartInfo::init(self.pvh_addr)
    }

    pub fn is_available(&self, segment: &crate::mm::MemorySegment) -> bool {
        if !self.kernel_bytes_phys().intersect(segment).is_empty()
            || !self.initrd_bytes_phys().intersect(segment).is_empty()
        {
            return false;
        }

        for entry in self.pvh().mem_map() {
            let e_seg = entry.to_segment();
            if e_seg.intersect(segment).is_empty() {
                continue;
            }

            if !entry.available() {
                return false;
            }

            if e_seg.contains_segment(segment) {
                return true;
            }

            return false;
        }

        false
    }
}

static AP_STARTED: AtomicU32 = AtomicU32::new(0);

fn start_bsp(arg: u64) -> ! {
    crate::arch::init_kvm_clock();

    let boot_info = unsafe { (arg as usize as *const KernelBootupInfo).as_ref().unwrap() };

    let boot_info = *boot_info;

    boot_info.validate();
    crate::config::set_num_cpus(boot_info.num_cpus as uCpus);

    while AP_STARTED.load(Ordering::Relaxed) != (boot_info.num_cpus - 1) {
        core::hint::spin_loop();
    }

    let new_stack = crate::mm::init_mm_bsp_stage1(&boot_info);
    copy_sys_io(boot_info.pvh().sys_io_bytes());
    let cpu_main_addr = cpu_main as *const fn(u64) as usize as u64;
    unsafe {
        core::arch::asm!("
        mov rsp, rax
        call r10
        ",
            in("rax") new_stack,
            in("rdi") 0_u64,
            in("r10") cpu_main_addr
        )
    };
    unreachable!()
}

fn start_ap(this_cpu: uCpus) -> ! {
    crate::arch::init_kvm_clock();

    AP_STARTED.fetch_add(1, Ordering::Relaxed);
    let new_stack = crate::mm::init_mm_ap_stage1();
    let cpu_main_addr = cpu_main as *const fn(u64) as usize as u64;
    unsafe {
        core::arch::asm!("
        mov rsp, rax
        call r10 
        ",
            in("rax") new_stack,
            in("rdi") (this_cpu as u64),
            in("r10") cpu_main_addr
        )
    };
    unreachable!()
}

static SYS_IO_ELF_START: AtomicUsize = AtomicUsize::new(0);
static SYS_IO_ELF_SIZE: AtomicUsize = AtomicUsize::new(0);

// sys_io_bytes are in initrd which we don't hold on to; so we copy the bytes
// to where we can have them.
fn copy_sys_io(sys_io_bytes: &[u8]) {
    let seg = crate::mm::virt::vmem_allocate_pages(
        crate::mm::virt::VmemKind::KernelStatic,
        crate::mm::align_up(sys_io_bytes.len() as u64, PAGE_SIZE_SMALL) >> PAGE_SIZE_SMALL_LOG2,
    )
    .unwrap();

    unsafe {
        core::intrinsics::copy_nonoverlapping(
            sys_io_bytes.as_ptr(),
            seg.start as usize as *mut u8,
            sys_io_bytes.len(),
        );
    }

    SYS_IO_ELF_START.store(seg.start as usize, Ordering::Relaxed);
    SYS_IO_ELF_SIZE.store(seg.size as usize, Ordering::Relaxed);
}

fn cpu_main(this_cpu: u64) -> ! {
    use crate::config::AtomicUCpus;

    static CPUS_INITIALIZED: AtomicUCpus = AtomicUCpus::new(0);
    if this_cpu == 0 {
        CPUS_INITIALIZED.fetch_add(1, Ordering::Release);
        while CPUS_INITIALIZED.load(Ordering::Relaxed) != crate::config::num_cpus() {
            core::hint::spin_loop();
        }

        crate::xray::logger::init_logging();

        crate::mm::init_mm_bsp_stage2();
        crate::xray::stats::init();
        crate::uspace::init();

        // If we print the boot logo before init_clock(), KVM in the host misbehaves and
        // often does not respond properly to the clock initialization dance.
        print_boot_logo();

        crate::sched::start()
    } else {
        CPUS_INITIALIZED.fetch_add(1, Ordering::Release);
        crate::mm::init_mm_ap_stage2();
        crate::sched::start()
    }
}

pub fn start_cpu(arg: u64) -> ! {
    let this_cpu = crate::arch::cpu_id();
    if this_cpu == 0 {
        start_bsp(arg)
    } else {
        start_ap(this_cpu)
    }
}

pub fn start_userspace_processes() {
    let mem_size = crate::mm::phys::PhysStats::get().total_size as f64 / (1024.0 * 1024.0);
    let tm = crate::arch::time::system_start_time().elapsed();

    let millis = tm.as_millis();
    crate::arch::arch_write_serial!(
        "kernel up at {:03}ms. {:.02} MiB RAM available, {} CPUs.\n",
        millis,
        mem_size,
        crate::config::num_cpus()
    );
    let address_space = crate::mm::user::UserAddressSpace::new().unwrap();
    let sys_io_bytes = unsafe {
        core::slice::from_raw_parts(
            SYS_IO_ELF_START.load(Ordering::Relaxed) as *const u8,
            SYS_IO_ELF_SIZE.load(Ordering::Relaxed),
        )
    };

    let result = crate::util::loader::load_elf(sys_io_bytes, address_space.as_ref());
    if result.is_err() {
        core::mem::drop(address_space);
        panic!("failed to load sys-io");
    }
    let entry_point = result.unwrap();

    let process = crate::uspace::Process::new(
        crate::xray::stats::kernel_stats(),
        address_space,
        entry_point,
        0xffff_ffff_ffff_ffff, // All possible caps.
        alloc::string::String::from("sys-io"),
    )
    .unwrap();

    assert_eq!(process.pid().as_u64(), moto_sys::stats::PID_SYS_IO);

    // crate::xray::tracing::start();
    // #[cfg(debug_assertions)]
    // log::set_max_level(log::LevelFilter::Debug);
    // #[cfg(not(debug_assertions))]
    log::set_max_level(log::LevelFilter::Info);

    log::debug!("starting sys-io");
    process.start();

    let _ = alloc::sync::Arc::into_raw(process);
}
