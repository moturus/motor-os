use crate::arch::kernel_exit;
use crate::arch::syscall::ThreadControlBlock;
use crate::config::uCpus;
use crate::util::StaticPerCpu;
use crate::util::StaticRef;
use alloc::boxed::Box;
use core::arch::asm;
use core::arch::naked_asm;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

// Note: we use super::serial::write_serial_!() below instead of raw_log!()
// because raw_log!() grabs a mutex which is not allowed in IRQ context.
//
// We also don't use panic!(), because it uses raw_log!().

use super::syscall::kill_current_thread;

const LAPIC_BASE: u64 = 0xfee0_0000_u64; // The default Local APIC address.
const IOAPIC_BASE: u64 = 0xfec0_0000_u64; // The default IO APIC address.

const IOAPIC_REG_VER: u32 = 0x01;
const IOAPIC_REG_TABLE: u32 = 0x10;
const IOAPIC_INT_DISABLED: u32 = 0x00010000;

const IRQ_BASE: u8 = 32;
const IRQ_SERIAL: u8 = 36;

pub const IRQ_CUSTOM_START: u8 = 64; // config().custom_irqs in total.
const MAX_CUSTOM_IRQS: u8 = 128;

const IRQ_APIC_TIMER: u8 = IRQ_CUSTOM_START + MAX_CUSTOM_IRQS; // 192 = 0xc0.
const IRQ_WAKEUP: u8 = IRQ_APIC_TIMER + 1; // 193 = 0xc1.
const IRQ_TLB_SHOOTDOWN: u8 = IRQ_WAKEUP + 1; // 194 = 0xc2.

// const IRQ_ERROR : u8 = 19;
// const IRQ_SPURIOUS : u8 = 31;

static IDT: StaticRef<StaticPerCpu<InterruptDescriptorTable>> = StaticRef::default_const();
static X2APIC: StaticRef<StaticPerCpu<x86::apic::x2apic::X2APIC>> = StaticRef::default_const();

// Logs a byte to chv's log.
fn _log_to_cloud_hypervisor(c: u8) {
    unsafe {
        asm!(
            "out 0x80, al",
            in("al") c,
            options(nomem, nostack, preserves_flags)
        )
    };
}

// Matches struct pt_regs in Linux.
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
pub struct IrqStack {
    // Preserved registers.
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,

    // Scratch registers.
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,

    // On IRQ with error code, this is error code;
    // otherwise this is random garbage.
    pub error_code: u64,

    // Return frame for iretq.
    pub rip: u64,
    pub cs: u64,
    pub flags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// same as above, but already has "rax"
macro_rules! push_irq_registers {
    () => {
        "
        push rdi
        push rsi
        push rdx
        push rcx
        push rax
        push r8
        push r9
        push r10
        push r11

        push rbx
        push rbp
        push r12
        push r13
        push r14
        push r15
    "
    };
}

macro_rules! pop_irq_registers {
    () => {
        "
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbp
        pop rbx

        pop r11
        pop r10
        pop r9
        pop r8
        pop rax
        pop rcx
        pop rdx
        pop rsi
        pop rdi
    "
    };
}
pub(crate) use pop_irq_registers;

macro_rules! naked_irq_handler {
    ($handler_name: ident, $irqnum:literal) => {
        #[naked]
        unsafe extern "C" fn $handler_name() {
            naked_asm!(
                // Some IRQs have error code on stack, some don't. This handler
                // deals with those that don't. As we use the same struct IrqStack,
                // which has error code, we manually adjust rsp to accommodate
                // the 8 bytes error code would use on stack.
                "sub rsp, 8",
                // We can write #IRQ into the "error_code" field, like below.
                // concat!("mov qword ptr [rsp], ", stringify!($irqnum)),
                push_irq_registers!(),
                "mov rdi, rsp",
                concat!("mov rsi, ", stringify!($irqnum)),
                "call irq_handler_inner",
                pop_irq_registers!(),
                "add rsp, 8", // See "sub rsp, 8" above.
                "iretq",
            );
        }
    };
}

pub fn init() {
    // Disable the legacy 8259 PIC (enabled in qemu by default).
    // See https://wiki.osdev.org/PIC
    //
    // Note: this will produce warnings in cloud-hypervisor log.
    unsafe {
        asm!(
            "mov al, 0xff",
            "out 0xa1, al",
            "out 0x21, al",
            out("al") _,
            options(nomem, nostack, preserves_flags)
        );
    }

    let cpu = super::current_cpu();
    log::trace!("amd64::irq::init() for cpu {}", cpu);
    if cpu == super::bsp() {
        IDT.set(Box::leak(Box::new(
            StaticPerCpu::<InterruptDescriptorTable>::new(),
        )));
        X2APIC.set(Box::leak(Box::new(
            StaticPerCpu::<x86::apic::x2apic::X2APIC>::new(),
        )));

        // Check that APIC base is at the default address. VirtIO assumes so,
        // and qemu/cloud-hypervisor comply.
        const IA32_APIC_BASE: u32 = 0x1b;
        const DEFAULT_APIC_BASE: u64 = 0xfee0_0000;

        let apic_base = super::rdmsr(IA32_APIC_BASE) & 0xffff_f000;
        if apic_base != DEFAULT_APIC_BASE {
            log::error!("APIC BASE is not 0xfee0_0000: cannot proceed.");
            crate::arch::kernel_exit();
        }
    }
    super::gdt::gdt_init();

    let idt = IDT.set_per_cpu(Box::leak(Box::new(InterruptDescriptorTable::new())));
    unsafe {
        idt.divide_error
            .set_handler_addr(x86_64::VirtAddr::new(irq_handler_0 as usize as u64));
        idt.debug
            .set_handler_addr(x86_64::VirtAddr::new(irq_handler_1 as usize as u64));
        idt.non_maskable_interrupt
            .set_handler_addr(x86_64::VirtAddr::new(irq_handler_2 as usize as u64));
        idt.breakpoint
            .set_handler_addr(x86_64::VirtAddr::new(irq_handler_3 as usize as u64))
            .set_stack_index(super::gdt::BREAKPOINT_IST_INDEX)
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);

        idt.overflow
            .set_handler_addr(x86_64::VirtAddr::new(irq_handler_4 as usize as u64));
        idt.bound_range_exceeded
            .set_handler_addr(x86_64::VirtAddr::new(irq_handler_5 as usize as u64));
        idt.invalid_opcode.set_handler_fn(invalid_opcode_handler); // IRQ 6

        idt.device_not_available
            .set_handler_addr(x86_64::VirtAddr::new(irq_handler_7 as usize as u64));
        idt.double_fault
            .set_handler_fn(double_fault_handler)
            .set_stack_index(super::gdt::DOUBLE_FAULT_IST_INDEX); // IRQ 8

        idt.invalid_tss.set_handler_fn(generic_handler2); // 10

        idt.segment_not_present
            .set_handler_fn(segment_not_present)
            .set_stack_index(super::gdt::PAGE_FAULT_IST_INDEX); // IRQ 11
        idt.stack_segment_fault
            .set_handler_fn(stack_segment_fault)
            .set_stack_index(super::gdt::PAGE_FAULT_IST_INDEX); // IRQ 12
        idt.general_protection_fault
            .set_handler_fn(gpf_handler)
            .set_stack_index(super::gdt::PAGE_FAULT_IST_INDEX); // IRQ 13
        idt.page_fault
            .set_handler_addr(x86_64::VirtAddr::new(
                page_fault_handler_asm as usize as u64,
            ))
            .set_stack_index(super::gdt::PAGE_FAULT_IST_INDEX); // IRQ 14
    } // unsafe

    // 15 - reserved
    idt.x87_floating_point.set_handler_fn(fp_handler); // 16
    idt.alignment_check.set_handler_fn(generic_handler2); // 17
    idt.machine_check.set_handler_fn(generic_handler3); // 18
    idt.simd_floating_point.set_handler_fn(fp_handler); // 19
    idt.virtualization.set_handler_fn(generic_handler_2); // 20
                                                          // 21-28 - reserved
    idt.vmm_communication_exception
        .set_handler_fn(generic_handler2); // 29
    idt.security_exception.set_handler_fn(generic_handler2); // 30
                                                             // 31 - reserved
    if cpu == super::bsp() {
        // Init serial console.
        crate::uspace::serial_console::init();
        unsafe {
            idt[IRQ_SERIAL as usize]
                .set_handler_addr(x86_64::VirtAddr::new(irq_handler_36 as usize as u64))
                .set_stack_index(super::gdt::SERIAL_CONSOLE_IST_INDEX);
        }

        // Custom IRQs.
        unsafe {
            assert_eq!(IRQ_CUSTOM_START, 64);
            assert_eq!(16, crate::config::get().custom_irqs);

            idt[64].set_handler_addr(x86_64::VirtAddr::new(irq_handler_64 as usize as u64));
            idt[65].set_handler_addr(x86_64::VirtAddr::new(irq_handler_65 as usize as u64));
            idt[66].set_handler_addr(x86_64::VirtAddr::new(irq_handler_66 as usize as u64));
            idt[67].set_handler_addr(x86_64::VirtAddr::new(irq_handler_67 as usize as u64));
            idt[68].set_handler_addr(x86_64::VirtAddr::new(irq_handler_68 as usize as u64));
            idt[69].set_handler_addr(x86_64::VirtAddr::new(irq_handler_69 as usize as u64));
            idt[70].set_handler_addr(x86_64::VirtAddr::new(irq_handler_70 as usize as u64));
            idt[71].set_handler_addr(x86_64::VirtAddr::new(irq_handler_71 as usize as u64));
            idt[72].set_handler_addr(x86_64::VirtAddr::new(irq_handler_72 as usize as u64));
            idt[73].set_handler_addr(x86_64::VirtAddr::new(irq_handler_73 as usize as u64));
            idt[74].set_handler_addr(x86_64::VirtAddr::new(irq_handler_74 as usize as u64));
            idt[75].set_handler_addr(x86_64::VirtAddr::new(irq_handler_75 as usize as u64));
            idt[76].set_handler_addr(x86_64::VirtAddr::new(irq_handler_76 as usize as u64));
            idt[77].set_handler_addr(x86_64::VirtAddr::new(irq_handler_77 as usize as u64));
            idt[78].set_handler_addr(x86_64::VirtAddr::new(irq_handler_78 as usize as u64));
            idt[79].set_handler_addr(x86_64::VirtAddr::new(irq_handler_79 as usize as u64));

            for irq in 64..80 {
                let entry = &mut idt[irq];
                entry
                    .set_handler_addr(entry.handler_addr())
                    .set_stack_index(super::gdt::SERIAL_CONSOLE_IST_INDEX);
            }
        }
    } // if cpu == super::bsp()

    unsafe {
        // timer handler
        idt[IRQ_APIC_TIMER as usize]
            .set_handler_addr(x86_64::VirtAddr::new(irq_handler_192 as usize as u64))
            .set_stack_index(super::gdt::TIMER_IST_INDEX);
        idt[IRQ_WAKEUP as usize]
            .set_handler_addr(x86_64::VirtAddr::new(irq_handler_193 as usize as u64))
            .set_stack_index(super::gdt::TIMER_IST_INDEX);
        idt[IRQ_TLB_SHOOTDOWN as usize]
            .set_handler_addr(x86_64::VirtAddr::new(irq_handler_194 as usize as u64))
            .set_stack_index(super::gdt::TIMER_IST_INDEX);
    }
    idt.load();

    use x86::apic::ApicControl;
    let x2apic = X2APIC.set_per_cpu(Box::leak(Box::new(x86::apic::x2apic::X2APIC::new())));
    x2apic.attach();
    x2apic.tsc_enable(super::irq::IRQ_APIC_TIMER);

    unsafe {
        lapic_init();
        if cpu == super::bsp() {
            ioapic_init();
            ioapic_enable_irq(IRQ_SERIAL - IRQ_BASE, cpu);
        }
    }
    // crate::raw_log!("amd64::irq::init() for cpu {} done", cpu);
}

pub fn x2apic() -> &'static mut x86::apic::x2apic::X2APIC {
    X2APIC.get_per_cpu()
}

extern "x86-interrupt" fn generic_handler_2(stack_frame: InterruptStackFrame) {
    let ip = stack_frame.instruction_pointer.as_u64();
    let uspace = !crate::mm::virt::is_kernel_addr(ip);
    let swapgs = stack_frame.code_segment != 0x8;
    if swapgs {
        unsafe { asm!("swapgs") }
    }

    if uspace {
        super::serial::write_serial_!("\nGENERIC_2 exception in uspace.\n\n");
        kill_current_thread(super::syscall::TOCR_KILLED_GPF, 0);
    } else {
        super::serial::write_serial_!("\nGENERIC_2 exception in kernel : {:#?}\n\n", stack_frame);
        // #[cfg(debug_assertions)]
        // crate::arch::log_backtrace_pretty("#");
        crate::arch::kernel_exit();
    }
}

extern "x86-interrupt" fn fp_handler(stack_frame: InterruptStackFrame) {
    let ip = stack_frame.instruction_pointer.as_u64();
    let uspace = !crate::mm::virt::is_kernel_addr(ip);
    let swapgs = stack_frame.code_segment != 0x8;
    if swapgs {
        unsafe { asm!("swapgs") }
    }

    if uspace {
        super::serial::write_serial_!("\nFP exception in uspace.\n\n");
        kill_current_thread(super::syscall::TOCR_KILLED_GPF, 0);
    } else {
        crate::write_serial!("\nFP exception in kernel.\n\n");
        crate::arch::kernel_exit();
    }
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: InterruptStackFrame) {
    let ip = stack_frame.instruction_pointer.as_u64();
    let uspace = !crate::mm::virt::is_kernel_addr(ip);
    let swapgs = stack_frame.code_segment != 0x8;
    if swapgs {
        unsafe { asm!("swapgs") }
    }

    if uspace {
        crate::write_serial!("\nINVALID OPCODE in uspace.\n\n");
        kill_current_thread(super::syscall::TOCR_KILLED_GPF, 0);
    } else {
        crate::write_serial!(
            "\nINVALID OPCODE in kernel on cpu {}.\n\n",
            crate::arch::current_cpu()
        );
        #[cfg(debug_assertions)]
        crate::arch::log_backtrace("#");

        crate::xray::tracing::dump();
        kernel_exit();
    }
}

extern "x86-interrupt" fn generic_handler2(stack_frame: InterruptStackFrame, error_code: u64) {
    let ip = stack_frame.instruction_pointer.as_u64();
    let uspace = !crate::mm::virt::is_kernel_addr(ip);
    let swapgs = stack_frame.code_segment != 0x8;
    if swapgs {
        unsafe { asm!("swapgs") }
    }

    if uspace {
        crate::write_serial!(
            "USPACE EXCEPTION: GENERIC2 on cpu {}: 0x{:x}\n{:#?}",
            crate::arch::current_cpu(),
            error_code,
            stack_frame
        );
        kill_current_thread(super::syscall::TOCR_KILLED_GPF, 0);
    } else {
        crate::write_serial!(
            "KERNEL EXCEPTION: GENERIC2 on cpu {}: 0x{:x}\n{:#?}",
            crate::arch::current_cpu(),
            error_code,
            stack_frame
        );
        #[cfg(debug_assertions)]
        crate::arch::log_backtrace("#");

        crate::xray::tracing::dump();
        kernel_exit();
    }
}

extern "x86-interrupt" fn segment_not_present(stack_frame: InterruptStackFrame, error_code: u64) {
    crate::write_serial!(
        "EXCEPTION: SEGMENT NOT PRESENT: 0x{:x}\n{:#?}",
        error_code,
        stack_frame
    );
    kernel_exit();
}

extern "x86-interrupt" fn stack_segment_fault(stack_frame: InterruptStackFrame, error_code: u64) {
    crate::write_serial!(
        "EXCEPTION: STACK SEGMENT FAULT: 0x{:x}\n{:#?}",
        error_code,
        stack_frame
    );
    kernel_exit();
}

extern "x86-interrupt" fn generic_handler3(stack_frame: InterruptStackFrame) -> ! {
    crate::write_serial!("EXCEPTION: GENERIC3:\n{:#?}", stack_frame);
    kernel_exit();
}

extern "x86-interrupt" fn gpf_handler(stack_frame: InterruptStackFrame, error_code: u64) {
    let ip = stack_frame.instruction_pointer.as_u64();
    let uspace = !crate::mm::virt::is_kernel_addr(ip);
    let swapgs = stack_frame.code_segment != 0x8;
    if swapgs {
        unsafe { asm!("swapgs") }
    }

    if uspace {
        crate::write_serial!(
            "\n#GPF({}) on cpu {} in uspace: {:#?}.\n\n",
            error_code,
            crate::arch::current_cpu(),
            stack_frame
        );
        // crate::util::tracing::dump();
        kill_current_thread(super::syscall::TOCR_KILLED_GPF, 0);
    } else {
        crate::write_serial!("\n#GPF({}) in kernel.\n\n", error_code);
        crate::write_serial!(
            "\n#GPF({}) in kernel on cpu {}.\n\n",
            error_code,
            crate::arch::current_cpu()
        );
        #[cfg(debug_assertions)]
        crate::arch::log_backtrace("#GPF");

        crate::xray::tracing::dump();
        crate::arch::kernel_exit();
    }
}

#[no_mangle]
pub extern "C" fn irq_handler_inner(rsp: u64, irq_num: u64) {
    let irq_stack = unsafe { (rsp as usize as *const IrqStack).as_ref().unwrap() };

    let uspace = !crate::mm::virt::is_kernel_addr(irq_stack.rip);
    let swapgs = irq_stack.cs != 0x8;
    if swapgs {
        unsafe { asm!("swapgs") }
    }

    crate::xray::tracing::trace_irq(irq_num, irq_stack.rip, 0);

    if uspace && !swapgs {
        crate::write_serial!(
            "#IRQ {}:{}: uspace && !swapgs\n",
            crate::arch::current_cpu(),
            irq_num
        );
    }
    if swapgs && !uspace {
        crate::write_serial!(
            "IRQ {}:{}: swapgs && !uspace\n",
            crate::arch::current_cpu(),
            irq_num
        );
    }

    // Note: we don't change the page table; this is mostly OK, as user page tables
    // have kernel page table also in there.

    match irq_num as u8 {
        3 => {
            if uspace {
                ThreadControlBlock::preempt_current_thread_irq(irq_stack); // noreturn
            }
            eoi();
        }
        7 => {
            if uspace {
                crate::write_serial!("\nIRQ7 in uspace.\n\n");
                kill_current_thread(super::syscall::TOCR_KILLED_GPF, 0); // does not return.
            } else {
                crate::write_serial!("\n\nIRQ7 in kernel\n\n");
                crate::arch::kernel_exit();
            }
        }
        IRQ_SERIAL => {
            crate::sched::local_wake();
            crate::uspace::serial_console::on_irq(); // Console.
            eoi();
            if uspace {
                ThreadControlBlock::preempt_current_thread_irq(irq_stack); // noreturn
            }
        }
        64..=79 => {
            crate::sched::on_custom_irq(irq_num as u8);
            if uspace {
                // These are I/O IRQs, make sure the driver is running.
                //if !ThreadControlBlock::io_thread() {
                eoi();
                ThreadControlBlock::preempt_current_thread_irq(irq_stack); // noreturn
                                                                           //}
            }
            eoi();
        }
        IRQ_APIC_TIMER => {
            // Timer.
            crate::sched::local_wake();
            if uspace {
                eoi();
                ThreadControlBlock::preempt_current_thread_irq(irq_stack); // noreturn
            } else {
                // If the timer fires when the CPU is running a userspace thread,
                // it is preempted and ends up in super::syscall::thread_off_cpu_reason(),
                // which then calls on_timer_irq().
                crate::sched::on_timer_irq();
                eoi();
            }
        }
        IRQ_WAKEUP => {
            crate::sched::local_wake(); // Wakeup.
            eoi();
        }
        IRQ_TLB_SHOOTDOWN => {
            eoi();
            super::tlb::shoot_from_irq();
        }
        _ => {
            crate::write_serial!("\n\nUNKNOWN IRQ {}\n\n", irq_num);
        }
    }

    if swapgs {
        unsafe { asm!("swapgs") }
    }
}

naked_irq_handler!(irq_handler_0, 0);
naked_irq_handler!(irq_handler_1, 1);
naked_irq_handler!(irq_handler_2, 2);
naked_irq_handler!(irq_handler_3, 3);
naked_irq_handler!(irq_handler_4, 4);
naked_irq_handler!(irq_handler_5, 5);
naked_irq_handler!(irq_handler_7, 7);
naked_irq_handler!(irq_handler_36, 36); // IRQ_SERIAL.

naked_irq_handler!(irq_handler_64, 64); // IRQ_CUSTOM_START.
naked_irq_handler!(irq_handler_65, 65);
naked_irq_handler!(irq_handler_66, 66);
naked_irq_handler!(irq_handler_67, 67);
naked_irq_handler!(irq_handler_68, 68);
naked_irq_handler!(irq_handler_69, 69);
naked_irq_handler!(irq_handler_70, 70);
naked_irq_handler!(irq_handler_71, 71);
naked_irq_handler!(irq_handler_72, 71);
naked_irq_handler!(irq_handler_73, 73);
naked_irq_handler!(irq_handler_74, 74);
naked_irq_handler!(irq_handler_75, 75);
naked_irq_handler!(irq_handler_76, 76);
naked_irq_handler!(irq_handler_77, 77);
naked_irq_handler!(irq_handler_78, 78);
naked_irq_handler!(irq_handler_79, 79);

naked_irq_handler!(irq_handler_192, 192); // IRQ_APIC_TIMER.
naked_irq_handler!(irq_handler_193, 193); // IRQ_WAKEUP.
naked_irq_handler!(irq_handler_194, 194); // IRQ_TLB_SHOOTDOWN.

pub fn set_timer(when: super::time::Instant) {
    use x86_64::instructions::interrupts;

    interrupts::without_interrupts(|| {
        use x86::apic::ApicControl;
        x2apic().tsc_set(when.raw_tsc());
    });
}

/*
    from https://wiki.osdev.org/Exceptions:

    The Page Fault sets an error code:

    31              15                             4               0
    +---+--  --+---+-----+---+--  --+---+----+----+---+---+---+---+---+
    |   Reserved   | SGX |   Reserved   | SS | PK | I | R | U | W | P |
    +---+--  --+---+-----+---+--  --+---+----+----+---+---+---+---+---+

        Length 	Name 	            Description
    P 	1 bit 	Present	            When set, the page fault was caused by a page-protection violation. When not set, it was caused by a non-present page.
    W 	1 bit 	Write 	            When set, the page fault was caused by a write access. When not set, it was caused by a read access.
    U 	1 bit 	User 	            When set, the page fault was caused while CPL = 3. This does not necessarily mean that the page fault was a privilege violation.
    R 	1 bit 	Reserved write 	    When set, one or more page directory entries contain reserved bits which are set to 1. This only applies when the PSE or PAE flags in CR4 are set to 1.
    I 	1 bit 	Instruction Fetch 	When set, the page fault was caused by an instruction fetch. This only applies when the No-Execute bit is supported and enabled.
    PK 	1 bit 	Protection key 	    When set, the page fault was caused by a protection-key violation. The PKRU register (for user-mode accesses) or PKRS MSR (for supervisor-mode accesses) specifies the protection key rights.
    SS 	1 bit 	Shadow stack 	    When set, the page fault was caused by a shadow stack access.
    SGX	1 bit 	Software Guard Ext.	When set, the fault was due to an SGX violation. The fault is unrelated to ordinary paging.

    In addition, it sets the value of the CR2 register to the virtual address which caused the Page Fault.
*/
#[no_mangle]
pub extern "C" fn page_fault_handler_inner(rsp: u64) {
    let irq_stack = unsafe { (rsp as usize as *const IrqStack).as_ref().unwrap() };
    let uspace = (irq_stack.error_code & 4) != 0;
    let swapgs = irq_stack.cs != 0x8;
    if swapgs {
        unsafe { asm!("swapgs") }
    }
    if uspace && !swapgs {
        crate::write_serial!("#PF:{}: uspace && !swapgs\n", crate::arch::current_cpu(),);
    }
    if swapgs && !uspace {
        crate::write_serial!("#PF:{}: swapgs && !uspace\n", crate::arch::current_cpu(),);
    }

    use x86_64::registers::control::Cr2;
    let rip = irq_stack.rip;

    let pf_addr = Cr2::read().as_u64();

    if uspace {
        if (irq_stack.error_code & 4) == 0 {
            crate::write_serial!(
                "\n\n#PF with bad stack or flags:\n\tpf_addr: 0x{:x}\n\tRIP: 0x{:x}\n\tuspace: {} error code: 0x{:x}\n\n",
                pf_addr,
                rip,
                uspace,
                irq_stack.error_code
            );
            kernel_exit();
        }
        ThreadControlBlock::preempt_current_thread_pf(irq_stack, pf_addr); // noreturn
    } else {
        let cpu = super::apic_cpu_id_32();
        crate::write_serial!(
            "\n\n#PF (kernel):\n\tcpu: {}\n\tAccessed Address: 0x{:x}\n\tRIP: 0x{:x}\n\terror code: 0x{:x}\n\n",
            cpu,
            pf_addr,
            rip,
            irq_stack.error_code
        );

        #[cfg(debug_assertions)]
        crate::arch::log_backtrace("#PF");

        crate::xray::tracing::dump();

        kernel_exit();
    }
}

#[naked]
unsafe extern "C" fn page_fault_handler_asm() {
    naked_asm!(
        push_irq_registers!(),
        "
        mov rdi, rsp
        call page_fault_handler_inner
        ",
        pop_irq_registers!(),
        "iretq",
    );
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    crate::write_serial!(
        "EXCEPTION: DOUBLE FAULT: 0x{:x}\n{:#?}",
        error_code,
        stack_frame
    );
    kernel_exit();
}

static mut LAPIC_VIRT_ADDR: u64 = 0;

unsafe fn lapic_write(reg: u32, val: u32) {
    assert!(reg < 4092); // Only one page mapped.
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let addr = LAPIC_VIRT_ADDR as usize;
    core::ptr::write_volatile((addr + reg as usize) as *mut u32, val);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

unsafe fn lapic_init() {
    let cpu = super::current_cpu();
    log::trace!("lapic_init() for cpu {}", cpu);
    if cpu == super::bsp() {
        // Upon boot, we marked the first 32+M of phys memory as in use.
        // Now mark LAPIC_BASE as available, so that mmio_map() below succeeds.
        // crate::mm::phys::phys_deallocate_frameless(LAPIC_BASE, crate::mm::PageType::SmallPage);
        let mapping = crate::mm::mmio::mmio_map(LAPIC_BASE, 1).unwrap();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(LAPIC_VIRT_ADDR) as *mut u64,
            mapping.virt_addr,
        );
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    // See https://github.com/swetland/xv6/blob/master/kernel/lapic.c
    const SVR: u32 = 0xf0; // Spurious Interrupt Vector.
    const MASKED: u32 = 0x00010000;

    const TPR: u32 = 0x0080; // Task Priority.
    const EOI: u32 = 0x00B0; // End Of Interrupt.
    const ESR: u32 = 0x0280; // Error Status Register.
    const PCINT: u32 = 0x0340; // PC counter overflow.
    const LINT0: u32 = 0x0350;
    const LINT1: u32 = 0x0360;
    const ERROR: u32 = 0x0370;

    // Assume APIC timer disabled.

    // Disable local interrupt lines.
    lapic_write(LINT0, MASKED);
    lapic_write(LINT1, MASKED);
    lapic_write(PCINT, MASKED);
    lapic_write(ERROR, MASKED);

    // Clear ESR (requires two writes).
    lapic_write(ESR, 0);
    lapic_write(ESR, 0);

    // Ack any outstanding interrupts.
    lapic_write(EOI, 0);

    // Enable interrupts, but not on the cpu.
    lapic_write(TPR, 0);

    // Enable LAPIC; set SVR.
    lapic_write(LINT0, 0);
    lapic_write(SVR, 0x1ff); // (IRQ_BASE + IRQ_SPURIOUS) as u32 | 0x100);
    log::trace!("lapic_init() done");
}

unsafe fn ioapic_read(reg: u32) -> u32 {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let addr = IOAPIC_VIRT_ADDR as usize;
    core::ptr::write_volatile(addr as *mut u32, reg);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    core::ptr::read_volatile((addr + 0x10) as *const u32)
}

unsafe fn ioapic_write(reg: u32, data: u32) {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let addr = IOAPIC_VIRT_ADDR as usize;
    core::ptr::write_volatile(addr as *mut u32, reg);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    core::ptr::write_volatile((addr + 0x10) as *mut u32, data);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

static mut IOAPIC_VIRT_ADDR: u64 = 0;

unsafe fn ioapic_init() {
    let cpu = super::current_cpu();
    log::trace!("ioapic_init() for cpu {}", cpu);
    if cpu == super::bsp() {
        let mapping = crate::mm::mmio::mmio_map(IOAPIC_BASE, 1).unwrap();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(IOAPIC_VIRT_ADDR) as *mut u64,
            mapping.virt_addr,
        );
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

    let max_intr = ((ioapic_read(IOAPIC_REG_VER) >> 16) & 0xff) as u32;

    // Mark all interrupts edge-triggered, active high, disabled,
    // and not routed to any CPUs.
    // See https://github.com/swetland/xv6/blob/master/kernel/ioapic.c
    for idx in 0..max_intr {
        ioapic_write(
            IOAPIC_REG_TABLE + 2 * idx,
            IOAPIC_INT_DISABLED | (IRQ_BASE as u32 + idx),
        );
        ioapic_write(IOAPIC_REG_TABLE + 2 * idx + 1, 0);
    }
    log::trace!("ioapic_init() done");
}

unsafe fn ioapic_enable_irq(irq: u8, cpu: u8) {
    // See https://github.com/swetland/xv6/blob/master/kernel/ioapic.c.
    let irq = irq as u32;
    let cpu = cpu as u32;
    ioapic_write(IOAPIC_REG_TABLE + 2 * irq, IRQ_BASE as u32 + irq);
    ioapic_write(IOAPIC_REG_TABLE + 2 * irq + 1, cpu << 24);

    // See also https://ethv.net/workshops/osdev/notes/notes-3.html.
}

fn eoi() {
    const IA32_X2APIC_EOI: u32 = 0x80b;
    super::wrmsr(IA32_X2APIC_EOI, 0);
}

pub fn wake_remote_cpu(cpu: uCpus) {
    use x86::apic::*;

    let icr = x86::apic::Icr::for_x2apic(
        IRQ_WAKEUP,
        ApicId::X2Apic(cpu as u32),
        DestinationShorthand::NoShorthand,
        DeliveryMode::Fixed,
        DestinationMode::Physical,
        DeliveryStatus::Idle,
        Level::Assert,
        TriggerMode::Edge,
    );
    unsafe {
        x2apic().send_ipi(icr);
    }
}

pub fn shoot_remote_tlb(cpu: uCpus) {
    use x86::apic::*;

    let icr = x86::apic::Icr::for_x2apic(
        IRQ_TLB_SHOOTDOWN,
        ApicId::X2Apic(cpu as u32),
        DestinationShorthand::NoShorthand,
        DeliveryMode::Fixed,
        DestinationMode::Physical,
        DeliveryStatus::Idle,
        Level::Assert,
        TriggerMode::Edge,
    );
    unsafe {
        x2apic().send_ipi(icr);
    }
}
