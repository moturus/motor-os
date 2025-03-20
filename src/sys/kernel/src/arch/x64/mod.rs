mod gdt;

pub mod irq;
pub mod paging;
pub mod serial;
pub mod syscall;
pub mod time;
pub mod tlb;

use crate::config::uCpus;

pub fn nop() {
    unsafe {
        core::arch::asm!("nop");
    }
}

pub fn init_cpu_postboot() {
    use core::sync::atomic::*;
    use x86_64::instructions::interrupts;

    static BSP_DONE: AtomicBool = AtomicBool::new(false);
    let this_cpu = apic_cpu_id_32();

    if this_cpu as uCpus == bsp() {
        GS::init(this_cpu as u64);
        assert_eq!(this_cpu as uCpus, current_cpu());

        irq::init();
        interrupts::enable();
        syscall::init();

        serial::init();
        tlb::setup();

        BSP_DONE.store(true, Ordering::Release);
    } else {
        GS::init(this_cpu as u64);
        assert_eq!(this_cpu as uCpus, current_cpu());

        while !BSP_DONE.load(Ordering::Acquire) {
            nop();
        }

        irq::init();
        interrupts::enable();
        syscall::init();
    }
}

#[inline(always)]
pub fn current_cpu() -> uCpus {
    GS::current_cpu()
}

pub fn bsp() -> uCpus {
    0
}

pub fn num_cpus() -> uCpus {
    crate::config::num_cpus()
}

pub fn wrmsr(msr: u32, value: u64) {
    let low = (value & 0xff_ff_ff_ff) as u32;
    let high = (value >> 32) as u32;

    unsafe { core::arch::asm!( "wrmsr", in("ecx") msr, in("eax") low, in("edx") high) }
}

pub fn rdmsr(msr: u32) -> u64 {
    let (high, low): (u32, u32);

    unsafe { core::arch::asm!( "rdmsr", in("ecx") msr, out("eax") low, out("edx") high) }

    ((high as u64) << 32) | (low as u64)
}

pub fn kernel_exit() -> ! {
    use x86_64::instructions::port::Port;

    crate::raw_log!("\n\r\n\rvm_exit: bye.\n\r");
    unsafe {
        // First, try acpi_shutdown, which works in cloud-hypervisor.

        // Initially it worked with port 0x3c0.
        let mut port = Port::new(0x3c0);
        port.write(0x34_u8);
        // Later port number became 0x600, for some reason.
        let mut port = Port::new(0x600);
        port.write(0x34_u8);

        // Then, try Qemu exit.
        let mut port = Port::new(0xf4);
        port.write(0x10_u32);
    }

    #[allow(clippy::empty_loop)]
    loop {} // The above did not work, so just loop
}

fn get_backtrace() -> [u64; 256] {
    let mut backtrace: [u64; 256] = [0; 256];

    let kernel_offset = crate::mm::kernel_offset_virt();

    let mut rbp: u64;
    unsafe {
        core::arch::asm!(
            "mov rdx, rbp", out("rdx") rbp, options(nomem, nostack)
        )
    };

    if rbp == 0 {
        // Use raw_log because log allocates.
        crate::write_serial!("Unable to collect backtrace: empty RBP.\n");
        return backtrace;
    }

    // Skip the first stack frame, which is one of the log_backtrace
    // functions below.
    rbp = unsafe { *(rbp as *mut u64) };

    for idx in 0..256 {
        if rbp == 0 {
            break;
        }
        if rbp & 7 != 0 {
            crate::write_serial!("get_backtrace(): unaligned rbp: 0x{:x}\n", rbp);
            return backtrace;
        }
        unsafe {
            backtrace[idx] = *((rbp + 8) as *mut u64);
            rbp = *(rbp as *mut u64);
        }

        if backtrace[idx] <= kernel_offset {
            break;
        }
        backtrace[idx] -= kernel_offset;
        if crate::mm::memory_initialized() && rbp < crate::mm::virt::VMEM_KERNEL_DATA_START {
            break;
        }
    }

    backtrace
}

pub fn log_backtrace(msg: &str) {
    let backtrace = get_backtrace();

    crate::raw_log!("backtrace ({msg}): run\n\naddr2line -e kernel \\");

    for addr in backtrace {
        if addr == 0 {
            break;
        }

        crate::raw_log!("\t0x{:x} \\", addr);
    }
    crate::raw_log!("\n");
}

pub fn apic_cpu_id_32() -> u32 {
    const IA32_X2APIC_APICID: u32 = 0x802;
    rdmsr(IA32_X2APIC_APICID) as u32
}

pub fn init_kvm_clock() {
    time::init_pvclock();
}

#[repr(C)]
#[derive(Debug)]
struct GS {
    _reserved: u64, // offset 0 - reading/writing here is flaky, for some reason
    gs_val: u64,    // offset 8 - self addr, as reading GS directly is flaky
    this_cpu: u64,  // offset 16
    kpt: u64,       // offset 24
    tcb: u64,       // offset 32
    rsp: u64,       // offset 40
    scratch_0: u64, // offset 48
    scratch_1: u64, // offset 56
}

impl GS {
    const MSR_IA32_GS_BASE: u32 = 0xc000_0101;
    const MSR_IA32_KERNEL_GSBASE: u32 = 0xc000_0102;

    fn init(this_cpu: u64) {
        assert!(this_cpu <= crate::config::MAX_CPUS as u64);
        assert_eq!(crate::arch::apic_cpu_id_32() as u64, this_cpu);

        // Enable WRGSBASE.
        unsafe {
            core::arch::asm!(
                "
                mov rax, cr4
                or  rax, 1 << 16
                mov cr4, rax
                ",
                out("rax") _
            )
        }

        let gs_val =
            crate::mm::virt::vmem_allocate_pages(crate::mm::virt::VmemKind::KernelStatic, 1)
                .unwrap()
                .start;

        let gs = Self::from_addr_mut(gs_val);
        gs.gs_val = gs_val;
        gs.this_cpu = this_cpu;
        gs.kpt = paging::kpt_phys_addr();

        wrmsr(Self::MSR_IA32_GS_BASE, gs_val); // Same as asm!("wrgsbase {gsval}").
        wrmsr(Self::MSR_IA32_KERNEL_GSBASE, gs_val);

        debug_assert_eq!(rdmsr(Self::MSR_IA32_GS_BASE), gs_val);
        debug_assert_eq!(rdmsr(Self::MSR_IA32_KERNEL_GSBASE), gs_val);

        // #[cfg(debug_assertions)]
        // crate::raw_log!("CPU {}: GS 0x{:x}", this_cpu, gs_val);

        core::sync::atomic::fence(core::sync::atomic::Ordering::AcqRel);
    }

    fn slow_swapgs() -> bool {
        let gsval1 = rdmsr(Self::MSR_IA32_GS_BASE);
        let gsval2 = rdmsr(Self::MSR_IA32_KERNEL_GSBASE);
        if gsval1 != gsval2 {
            unsafe { core::arch::asm!("swapgs", options(nomem, nostack)) }
            let gsval1 = rdmsr(Self::MSR_IA32_GS_BASE);
            assert_eq!(gsval1, gsval2);
            true
        } else {
            false
        }
    }

    fn current_cpu() -> uCpus {
        let result: u64;

        unsafe {
            core::arch::asm!("mov r15, gs:[16]", out("r15") result, options(nomem, nostack));
        }

        result as uCpus
    }

    fn current_tcb() -> u64 {
        let result: u64;

        unsafe {
            core::arch::asm!("mov r15, gs:[32]", out("r15") result, options(nomem, nostack));
        }

        result
    }

    #[allow(unused)]
    fn from_addr(addr: u64) -> &'static Self {
        unsafe { (addr as usize as *const Self).as_ref().unwrap_unchecked() }
    }

    fn from_addr_mut(addr: u64) -> &'static mut Self {
        unsafe { (addr as usize as *mut Self).as_mut().unwrap_unchecked() }
    }

    fn _get() -> &'static Self {
        let gs_val: u64;
        unsafe {
            core::arch::asm!("mov r12, gs:[8]", out("r12") gs_val, options(nostack));
        }

        Self::from_addr(gs_val)
    }

    fn _get_mut() -> &'static mut Self {
        let gs_val: u64;
        unsafe {
            core::arch::asm!("mov r12, gs:[8]", out("r12") gs_val, options(nostack));
        }

        Self::from_addr_mut(gs_val)
    }

    #[cfg(debug_assertions)]
    #[allow(unused)]
    fn print() {
        let gs_val = rdmsr(Self::MSR_IA32_GS_BASE);
        if gs_val == 0 {
            crate::raw_log!("GS: ZERO :(");
        } else {
            let gs = GS::from_addr(gs_val);
            crate::raw_log!("gs val: 0x{:x} GS: {:x?}", gs_val, gs);
        }
    }
}

pub fn slow_swapgs() -> bool {
    GS::slow_swapgs()
}

#[cfg(debug_assertions)]
#[allow(unused)]
pub fn print_gs() {
    GS::print()
}

#[cfg(debug_assertions)]
fn is_kernel_rsp() -> bool {
    let mut rsp: u64;
    unsafe {
        core::arch::asm!(
            "
            mov r14, rsp
            ",
            out("r14") rsp,
            options(nomem, nostack)
        )
    }

    crate::mm::virt::is_kernel_addr(rsp)
}
