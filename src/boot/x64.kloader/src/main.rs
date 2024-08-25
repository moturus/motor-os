#![no_std]
#![allow(internal_features)]
#![feature(alloc_error_handler)]
#![feature(stmt_expr_attributes)]
#![feature(const_mut_refs)]
#![feature(core_intrinsics)]
#![feature(maybe_uninit_uninit_array)]
#![feature(maybe_uninit_array_assume_init)]
#![feature(atomic_from_mut)]
#![feature(naked_functions)]
#![feature(asm_const)]
#![feature(assert_matches)]
#![no_main]

mod acpi;
mod cpuid;
mod gdt;
mod loader;
mod mm;
mod pvh;
mod serial;
mod util;

extern crate alloc;

use crate::serial::write_serial as raw_log;

#[allow(non_camel_case_types)]
pub type uCpus = u8;

#[panic_handler]
#[cfg(not(test))]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    serial::write_serial!("PANIC: {info}\n");
    util::vmm_exit()
}

// use core::arch::global_asm;
// global_asm!(include_str!("bootup_bsp.s"), options(att_syntax, raw));

use crate::util::vmm_exit;
use core::arch::asm;
use core::sync::atomic::*;

use crate::mm::PAGE_SIZE_SMALL;

const AP_BOOTUP_ADDR: u64 = 0xc000;
static AP_BOOTUP_CODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bootup_ap"));
static AP_READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn start_aps(num_cpus: uCpus) {
    assert!(AP_BOOTUP_CODE.len() as u64 <= PAGE_SIZE_SMALL);
    let ap_bootup_addr = AP_BOOTUP_ADDR;
    let ap_bootup_page: u64 = ap_bootup_addr >> PAGE_SIZE_SMALL.ilog2();
    assert_eq!(ap_bootup_page, ap_bootup_page & 0xff); // ipi_startup needs start_page to be in u8.

    // TODO: maybe make bootup_ap.s movable: now it is fixed at AP_BOOTUP_ADDR.
    assert_ne!(ap_bootup_addr, 0);
    unsafe {
        use core::slice;
        let dst: &mut [u8] =
            slice::from_raw_parts_mut(ap_bootup_addr as usize as *mut u8, AP_BOOTUP_CODE.len());
        dst.copy_from_slice(AP_BOOTUP_CODE);
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

    core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

    // Bring up processors.
    use x86::apic::ApicControl;
    let mut x2apic = x86::apic::x2apic::X2APIC::new();
    x2apic.attach();
    assert!(x2apic.bsp());

    let (l4, _) = x86_64::registers::control::Cr3::read();

    for ap in 1..num_cpus {
        let stack_start = allocate_kernel_stack();

        let ap_data_start = (ap_bootup_addr) as *mut u64;
        let ap_cpu_id = unsafe { ap_data_start.offset(1) };
        let ap_page_table = unsafe { ap_data_start.offset(2) };
        let ap_stack_start = unsafe { ap_data_start.offset(3) };
        let ap_stack_end = unsafe { ap_data_start.offset(4) };
        let ap_code = unsafe { ap_data_start.offset(5) };
        let ap_gdt = unsafe { ap_data_start.offset(6) };

        unsafe {
            *ap_cpu_id = ap as u64;
            *ap_page_table = l4.start_address().as_u64();
            *ap_stack_start = stack_start;
            *ap_stack_end = stack_start + 4096;
            *ap_code = ap_start as u64;
            *ap_gdt = &gdt::GDT64_PTR as *const gdt::Pointer as usize as u64;
        }

        AP_READY.store(false, Ordering::Release);

        let cpu = x86::apic::ApicId::X2Apic(ap as u32);
        unsafe {
            x2apic.ipi_init(cpu);
        }
        let mut iters: u64 = 0;
        const WAIT_ITERS: u64 = 10_000;
        while iters < WAIT_ITERS {
            core::hint::spin_loop();
            iters += 1;
        }

        unsafe {
            x2apic.ipi_startup(cpu, ap_bootup_page as u8);
        }

        while !AP_READY.load(Ordering::Relaxed) {
            unsafe {
                asm!("nop");
            } // without this the loop is optimized out
        }
    }
}

fn validate_bsp() {
    let this_cpu = cpuid::apic_id_32();
    if this_cpu != 0 {
        raw_log!("ERROR: BSP is not 0.\n");
        vmm_exit();
    }

    assert!(cpuid::has_msr());
    assert!(cpuid::has_tsc());
    assert!(cpuid::has_tsc_deadline());
    assert!(cpuid::has_rdtscp());
    assert!(cpuid::has_pdpe1gb());
    assert!(cpuid::has_kvm_clockshource2());
    assert!(cpuid::has_kvm_clockshource_stable_bit());
}

fn allocate_kernel_stack() -> u64 {
    const AP_STACK_SIZE: usize = 4096 * 4;
    (unsafe { crate::mm::alloc(core::alloc::Layout::from_size_align(AP_STACK_SIZE, 32).unwrap()) }
        + AP_STACK_SIZE) as u64
}

// Called from bootup_bsp.s.
#[no_mangle]
pub extern "C" fn bsp_start(rdi: u64) -> ! {
    let start = util::rdtsc();

    validate_bsp();

    let pvh = pvh::PvhStartInfo::init(rdi);
    mm::init(pvh);

    util::enable_sse();
    let num_cpus = acpi::application_processors(pvh.rsdp_paddr);
    if num_cpus > 1 {
        start_aps(num_cpus);
    } else {
        // raw_log!("A single CPU detected.");
    }
    util::full_fence(); // ap_start waits on cpus_initialized.

    // Assert kernel cpl.
    assert_eq!(x86::segmentation::cs().bits() & 0b11, 0);
    loader::load_kernel_bsp(pvh, num_cpus as u32, start)
}

pub extern "C" fn ap_start(this_cpu: u64) -> ! {
    AP_READY.store(true, core::sync::atomic::Ordering::Release);

    crate::util::enable_sse();
    assert_eq!(this_cpu, cpuid::apic_id_32() as u64);

    loader::jump_into_kernel_ap()
}
