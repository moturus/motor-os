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

// Installs `page_table` (a physical L4 address) as this CPU's CR3 unless it
// is already installed (per the gs:[64] shadow) — a CR3 write wipes all
// non-global TLB translations, so redundant loads are worth skipping (the
// same-process wait/resume lockstep case). Safe against the concurrent
// evict IPI (tlb::evict_user_page_table): eviction only targets page tables
// of fully-dead processes, which no caller can be installing.
pub fn install_page_table(page_table: u64) {
    let current: u64;
    unsafe {
        core::arch::asm!("mov {}, gs:[64]", out(reg) current, options(nostack));
    }
    if current == page_table {
        return;
    }
    unsafe {
        core::arch::asm!(
            "mov cr3, {0}",
            "mov gs:[64], {0}",
            in(reg) page_table,
            options(nostack)
        );
    }
}

pub fn install_kernel_page_table() {
    let kpt: u64;
    unsafe {
        core::arch::asm!("mov {}, gs:[24]", out(reg) kpt, options(nostack));
    }
    install_page_table(kpt);
}

// W7 direct switch: this CPU's "previous thread" slot (gs:[72], see the GS
// struct) — an Arc::into_raw pointer to the thread that direct-switched
// away and still needs its park bookkeeping run, 0 when none. Same-CPU
// set/take only; see the field comment for why plain accesses suffice.
pub fn set_direct_switch_prev(ptr: u64) {
    #[cfg(debug_assertions)]
    {
        let prev: u64;
        unsafe {
            core::arch::asm!("mov {}, gs:[72]", out(reg) prev, options(nostack));
        }
        debug_assert_eq!(prev, 0);
    }
    unsafe {
        core::arch::asm!("mov gs:[72], {}", in(reg) ptr, options(nostack));
    }
}

pub fn take_direct_switch_prev() -> u64 {
    let ptr: u64;
    unsafe {
        core::arch::asm!(
            "mov {p}, gs:[72]",
            "mov qword ptr gs:[72], 0",
            p = out(reg) ptr,
            options(nostack)
        );
    }
    ptr
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

    crate::write_serial!("\n\r\n\rvm_exit: bye.\n\r");
    unsafe {
        // First, try ACPI shutdown (works in Cloud Hypervisor).
        // SLEEP_CONTROL_REG: SLP_EN | (S5 << 2) == 0x34.
        let mut port = Port::new(0x3c0);
        port.write(0x34_u8);
        let mut port = Port::new(0x600);
        port.write(0x34_u8);

        // Then try Qemu isa-debug-exit.
        let mut port = Port::new(0xf4);
        port.write(0x10_u32);

        // Last resort: Firecracker i8042 reset.
        // NOTE: Cloud Hypervisor also implements this command, but as a
        // *reboot*, so it must come after the ACPI shutdown above.
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x64u16,
            in("al") 0xFEu8,
            options(nomem, nostack, preserves_flags)
        );
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
    // offset 64: shadow of this CPU's CR3 (W6b). Every CR3 write goes
    // through install_page_table()/install_kernel_page_table() or one of
    // the few asm paths that update gs:[64] alongside `mov cr3`, so the
    // shadow is always accurate. Lets kernel->user resume paths skip the
    // CR3 load (= a full non-global TLB wipe) when the right table is
    // already installed - the common lockstep case.
    current_cr3: u64,
    // offset 72: Arc::into_raw pointer to the thread that direct-switched
    // away on this CPU and still needs its park bookkeeping run (W7), 0
    // when none. Set just before syscall_switch_asm, taken at the wakee's
    // emergence (process::finish_direct_switch). Kernel code is never
    // preempted and no IRQ path touches this, so plain same-CPU
    // reads/writes are race-free.
    direct_switch_prev: u64,
}

impl GS {
    const MSR_IA32_GS_BASE: u32 = 0xc000_0101;
    const MSR_IA32_KERNEL_GSBASE: u32 = 0xc000_0102;

    fn init(this_cpu: u64) {
        assert!(this_cpu <= crate::config::MAX_CPUS as u64);
        assert_eq!(crate::arch::apic_cpu_id_32() as u64, this_cpu);

        // Enable WRGSBASE (bit 16) and global pages (PGE, bit 7 — see
        // PTE::GLOBAL in paging.rs).
        unsafe {
            core::arch::asm!(
                "
                mov rax, cr4
                or  rax, (1 << 16) | (1 << 7)
                mov cr4, rax
                ",
                out("rax") _
            )
        }

        // EFER.NXE (bit 11): PTE bit 63 becomes NX instead of reserved.
        // Must be set on every CPU before it can walk a user page table
        // (all user data leaves are NX — see PTE::NX in paging.rs); done
        // here because GS::init is the first per-CPU init step.
        const MSR_IA32_EFER: u32 = 0xc000_0080;
        const EFER_NXE: u64 = 1 << 11;
        wrmsr(MSR_IA32_EFER, rdmsr(MSR_IA32_EFER) | EFER_NXE);

        // SMEP (CR4 bit 20) / SMAP (CR4 bit 21): the kernel must never
        // execute user pages, and never read/write them through their user
        // mappings — every kernel access to user memory goes through the
        // direct map (kernel PTEs), so no stac/clac windows are needed
        // anywhere. Gated on CPUID.(7,0):EBX (bit 7 = SMEP, bit 20 = SMAP).
        let cpuid7 = core::arch::x86_64::__cpuid_count(7, 0);
        let mut cr4_security = 0_u64;
        if (cpuid7.ebx & (1 << 7)) != 0 {
            cr4_security |= 1 << 20; // SMEP
        }
        if (cpuid7.ebx & (1 << 20)) != 0 {
            cr4_security |= 1 << 21; // SMAP
        }
        if cr4_security != 0 {
            unsafe {
                core::arch::asm!(
                    "
                    mov rax, cr4
                    or  rax, {bits}
                    mov cr4, rax
                    ",
                    bits = in(reg) cr4_security,
                    out("rax") _
                )
            }
        }

        let gs_val =
            crate::mm::virt::vmem_allocate_pages(crate::mm::virt::VmemKind::KernelStatic, 1)
                .unwrap()
                .start;

        let gs = Self::from_addr_mut(gs_val);
        gs.gs_val = gs_val;
        gs.this_cpu = this_cpu;
        gs.kpt = paging::kpt_phys_addr();
        gs.current_cr3 = gs.kpt; // CR3 == KPT during init.
        gs.direct_switch_prev = 0;

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
            #[cfg(debug_assertions)]
            {
                let gsval1 = rdmsr(Self::MSR_IA32_GS_BASE);
                assert_eq!(gsval1, gsval2);
            }
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

// Asserts that the kernel GS is live: GS.gs_val (gs:[8]) is the GS base
// itself, so a self-referential read must match the MSR.
#[cfg(debug_assertions)]
pub fn validate_kernel_gs() {
    let gs_self: u64;
    unsafe {
        core::arch::asm!("mov {0}, gs:[8]", out(reg) gs_self, options(nostack));
    }
    assert_eq!(gs_self, rdmsr(GS::MSR_IA32_GS_BASE));
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
