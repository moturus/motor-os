use core::arch::asm;

static GDT: GdtProtectedMode = GdtProtectedMode::new();

#[repr(C)]
pub struct GdtProtectedMode {
    zero: u64,
    code: u64,
    data: u64,
}

const GDT_CODE: u64 = 0xcf_9a00_0000_ffff_u64;
const GDT_DATA: u64 = 0xcf_9200_0000_ffff_u64;

impl GdtProtectedMode {
    const fn new() -> Self {
        Self {
            zero: 0,
            code: GDT_CODE,
            data: GDT_DATA,
        }
    }

    fn clear_interrupts_and_load(&'static self) {
        let pointer = GdtPointer {
            base: self as *const _ as usize as u32,
            limit: 24,
        };

        unsafe {
            asm!("cli",
            "lgdt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
        }
    }
}

#[repr(C, packed(2))]
pub struct GdtPointer {
    // Size of the DT.
    pub limit: u16,
    // Pointer to the memory region containing the DT.
    pub base: u32, // *const GdtProtectedMode,
}

unsafe impl Send for GdtPointer {}
unsafe impl Sync for GdtPointer {}

pub fn enter_unreal_mode() {
    let ds: u16;
    let ss: u16;
    unsafe {
        asm!("mov {0:x}, ds", out(reg) ds, options(nomem, nostack, preserves_flags));
        asm!("mov {0:x}, ss", out(reg) ss, options(nomem, nostack, preserves_flags));
    }

    GDT.clear_interrupts_and_load();

    // set protected mode bit
    let cr0 = set_protected_mode_bit();

    // load GDT
    unsafe {
        asm!("mov {0}, 0x10", "mov ds, {0}", "mov ss, {0}", out(reg) _);
    }

    // unset protected mode bit again
    write_cr0(cr0);

    unsafe {
        asm!("mov ds, {0:x}", in(reg) ds, options(nostack, preserves_flags));
        asm!("mov ss, {0:x}", in(reg) ss, options(nostack, preserves_flags));
        asm!("sti");
    }
}

pub fn enter_protected_mode_and_jump_to_stage_3(entry_point: u32, ebx: u32) -> ! {
    // unsafe { asm!("cli") };
    assert_eq!(GDT.zero, 0);
    assert_eq!(GDT.code, GDT_CODE);
    assert_eq!(GDT.data, GDT_DATA);

    GDT.clear_interrupts_and_load();

    set_protected_mode_bit();
    unsafe {
        asm!("mov {0}, 0x10", "mov ds, {0}", "mov ss, {0}", out(reg) _);
    }
    unsafe {
        asm!(
            // align the stack
            "and esp, 0xffffff00",
            // push arguments
            "push {ebx:e}",
            // push entry point address
            "push {entry_point:e}",
            ebx = in(reg) ebx,
            entry_point = in(reg) entry_point,
        );
        asm!("ljmp $0x8, $2f", "2:", options(att_syntax));
        asm!(
            ".code32",

            // reload segment registers
            "mov {0}, 0x10",
            "mov ds, {0}",
            "mov es, {0}",
            "mov ss, {0}",

            // jump to third stage
            "pop {1}",
            "pop ebx",
            "call {1}",

            // enter endless loop in case third stage returns
            "2:",
            "jmp 2b",
            out(reg) _,
            out(reg) _,
        );
    }

    unreachable!()
}

fn set_protected_mode_bit() -> u32 {
    let mut cr0: u32;
    unsafe {
        asm!("mov {:e}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
    }
    let cr0_protected = cr0 | 1;
    write_cr0(cr0_protected);
    cr0
}

fn write_cr0(val: u32) {
    unsafe { asm!("mov cr0, {:e}", in(reg) val, options(nostack, preserves_flags)) };
}
