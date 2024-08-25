// ----------------------------------------------------------------------------
// GDT + TSS
// ----------------------------------------------------------------------------

use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

use crate::mm;
use crate::mm::PAGE_SIZE_SMALL;
use crate::util::StaticPerCpu;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const PAGE_FAULT_IST_INDEX: u16 = 1;
pub const BREAKPOINT_IST_INDEX: u16 = 2;
pub const TIMER_IST_INDEX: u16 = 3;
pub const SERIAL_CONSOLE_IST_INDEX: u16 = 4;

fn new_tss() -> &'static TaskStateSegment {
    let new_stack = || -> VirtAddr {
        const STACK_PAGES: u64 = 5;
        let stack = mm::virt::vmem_allocate_pages(mm::virt::VmemKind::KernelStack, STACK_PAGES + 2)
            .unwrap();
        let stack_end = stack.end() - PAGE_SIZE_SMALL; // Remove guard page.
        VirtAddr::new(stack_end)
    };

    let mut tss = TaskStateSegment::new();
    tss.privilege_stack_table[0 as usize] = new_stack();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = new_stack();
    tss.interrupt_stack_table[PAGE_FAULT_IST_INDEX as usize] = new_stack();
    tss.interrupt_stack_table[BREAKPOINT_IST_INDEX as usize] = new_stack();
    tss.interrupt_stack_table[TIMER_IST_INDEX as usize] = new_stack();
    tss.interrupt_stack_table[SERIAL_CONSOLE_IST_INDEX as usize] = new_stack();

    use alloc::boxed::Box;
    Box::leak(Box::new(tss))
}

static GDT: crate::util::StaticRef<StaticPerCpu<(GlobalDescriptorTable, Selectors)>> =
    crate::util::StaticRef::default_const();

fn new_gdt() -> (GlobalDescriptorTable, Selectors) {
    let mut gdt = GlobalDescriptorTable::new();
    let kernel_code_selector = gdt.add_entry(Descriptor::kernel_code_segment());
    let kernel_data_selector = gdt.add_entry(Descriptor::kernel_data_segment());
    let tss_selector = gdt.add_entry(Descriptor::tss_segment(new_tss()));

    // The two selectors below must be in GDT; but they are never used explicitly.
    let _user_data_selector = gdt.add_entry(Descriptor::user_data_segment());
    let _user_code_selector = gdt.add_entry(Descriptor::user_code_segment());
    (
        gdt,
        Selectors {
            kernel_code_selector,
            kernel_data_selector,
            tss_selector,
        },
    )
}

struct Selectors {
    kernel_code_selector: SegmentSelector,
    kernel_data_selector: SegmentSelector,
    tss_selector: SegmentSelector,
}

pub fn gdt_init() {
    use alloc::boxed::Box;
    use x86_64::instructions::segmentation::{Segment, CS, DS};
    use x86_64::instructions::tables::load_tss;

    if crate::arch::current_cpu() == crate::arch::bsp() {
        GDT.set(Box::leak(Box::new(StaticPerCpu::<(
            GlobalDescriptorTable,
            Selectors,
        )>::new())));
    }

    let (gdt, selectors) = GDT.set_per_cpu(Box::leak(Box::new(new_gdt())));
    gdt.load();
    unsafe {
        CS::set_reg(selectors.kernel_code_selector);
        DS::set_reg(selectors.kernel_data_selector);
        load_tss(selectors.tss_selector);
    }
}
