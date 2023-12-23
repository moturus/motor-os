#[allow(unused_imports)]
use crate::segmentation::SegmentSelector;
use crate::segmentation::{
    BuildDescriptor, Descriptor, DescriptorBuilder, DescriptorType, GateDescriptorBuilder,
    LdtDescriptorBuilder, SystemDescriptorTypes64,
};

#[cfg(target_arch = "x86_64")]
use core::arch::asm;

/// Entry for IDT, GDT or LDT.
///
/// See Intel 3a, Section 3.4.5 "Segment Descriptors", and Section 3.5.2
/// "Segment Descriptor Tables in IA-32e Mode", especially Figure 3-8.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct Descriptor64 {
    desc32: Descriptor,
    lower: u32,
    upper: u32,
}

impl Descriptor64 {
    pub const NULL: Descriptor64 = Descriptor64 {
        desc32: Descriptor::NULL,
        lower: 0,
        upper: 0,
    };

    pub(crate) fn apply_builder_settings(&mut self, builder: &DescriptorBuilder) {
        self.desc32.apply_builder_settings(builder);
        if let Some((base, limit)) = builder.base_limit {
            self.set_base_limit(base, limit)
        }
        if let Some((selector, offset)) = builder.selector_offset {
            self.set_selector_offset(selector, offset)
        }
    }

    /// Create a new segment, TSS or LDT descriptor
    /// by setting the three base and two limit fields.
    pub fn set_base_limit(&mut self, base: u64, limit: u64) {
        self.desc32.set_base_limit(base as u32, limit as u32);
        self.lower = (base >> 32) as u32;
    }

    /// Creates a new descriptor with selector and offset (for IDT Gate descriptors,
    /// e.g. Trap, Interrupts and Task gates)
    pub fn set_selector_offset(&mut self, selector: SegmentSelector, offset: u64) {
        self.desc32.set_selector_offset(selector, offset as u32);
        self.lower = (offset >> 32) as u32;
    }

    /// Sets the interrupt stack table index.
    /// The 3-bit IST index field that provides an offset into the IST section of the TSS.
    /// Using the IST mechanism, the processor loads the value pointed by an IST pointer into the RSP.
    pub fn set_ist(&mut self, index: u8) {
        assert!(index <= 0b111);
        self.desc32.upper |= index as u32;
    }
}

impl GateDescriptorBuilder<u64> for DescriptorBuilder {
    fn tss_descriptor(base: u64, limit: u64, available: bool) -> DescriptorBuilder {
        let typ = if available {
            DescriptorType::System64(SystemDescriptorTypes64::TssAvailable)
        } else {
            DescriptorType::System64(SystemDescriptorTypes64::TssBusy)
        };

        DescriptorBuilder::with_base_limit(base, limit).set_type(typ)
    }

    fn call_gate_descriptor(selector: SegmentSelector, offset: u64) -> DescriptorBuilder {
        DescriptorBuilder::with_selector_offset(selector, offset)
            .set_type(DescriptorType::System64(SystemDescriptorTypes64::CallGate))
    }

    fn interrupt_descriptor(selector: SegmentSelector, offset: u64) -> DescriptorBuilder {
        DescriptorBuilder::with_selector_offset(selector, offset).set_type(
            DescriptorType::System64(SystemDescriptorTypes64::InterruptGate),
        )
    }

    fn trap_gate_descriptor(selector: SegmentSelector, offset: u64) -> DescriptorBuilder {
        DescriptorBuilder::with_selector_offset(selector, offset)
            .set_type(DescriptorType::System64(SystemDescriptorTypes64::TrapGate))
    }
}

impl LdtDescriptorBuilder<u64> for DescriptorBuilder {
    fn ldt_descriptor(base: u64, limit: u64) -> DescriptorBuilder {
        DescriptorBuilder::with_base_limit(base, limit)
            .set_type(DescriptorType::System64(SystemDescriptorTypes64::LDT))
    }
}

impl BuildDescriptor<Descriptor64> for DescriptorBuilder {
    fn finish(&self) -> Descriptor64 {
        let mut desc: Descriptor64 = Default::default();
        desc.apply_builder_settings(self);

        let typ = match self.typ {
            Some(DescriptorType::System64(typ)) => {
                assert!(!self.l);
                if typ == SystemDescriptorTypes64::LDT
                    || typ == SystemDescriptorTypes64::TssAvailable
                    || typ == SystemDescriptorTypes64::TssBusy
                {
                    assert!(!self.db);
                }

                if typ == SystemDescriptorTypes64::InterruptGate {
                    desc.set_ist(self.ist);
                }

                typ as u8
            }
            Some(DescriptorType::System32(_typ)) => {
                panic!("Can't build a 64-bit version of this type.")
            }
            Some(DescriptorType::Data(_typ)) => {
                panic!("Can't build a 64-bit version of this type.")
            }
            Some(DescriptorType::Code(_typ)) => {
                panic!("Can't build a 64-bit version of this type.")
            }
            None => unreachable!("Type not set, this is a library bug in x86."),
        };

        desc.desc32.set_type(typ);
        desc
    }
}

/// Reload code segment register.
///
/// Note this is special since we can not directly move
/// to %cs. Instead we push the new segment selector
/// and return value on the stack and use lretq
/// to reload cs and continue at 1:.
///
/// # Safety
/// Can cause a GP-fault with a bad `sel` value.
#[cfg(target_arch = "x86_64")]
pub unsafe fn load_cs(sel: SegmentSelector) {
    asm!("pushq {0}; \
          leaq  1f(%rip), %rax; \
          pushq %rax; \
          lretq; \
          1:", in(reg) sel.bits() as usize, out("rax") _, options(att_syntax));
}

/// Write GS Segment Base
///
/// # Safety
/// Needs FSGSBASE-Enable Bit (bit 16 of CR4) set.
#[cfg(target_arch = "x86_64")]
pub unsafe fn wrgsbase(base: u64) {
    asm!("wrgsbase {0}", in(reg) base, options(att_syntax));
}

/// Write FS Segment Base
///
/// # Safety
/// Needs FSGSBASE-Enable Bit (bit 16 of CR4) set.
#[cfg(target_arch = "x86_64")]
pub unsafe fn wrfsbase(base: u64) {
    asm!("wrfsbase {0}", in(reg) base, options(att_syntax));
}

/// Read GS Segment Base
///
/// # Safety
/// Needs FSGSBASE-Enable Bit (bit 16 of CR4) set.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rdgsbase() -> u64 {
    let gs_base: u64;
    asm!("rdgsbase {0}", out(reg) gs_base, options(att_syntax));
    gs_base
}

/// Read FS Segment Base
///
/// # Safety
/// Needs FSGSBASE-Enable Bit (bit 16 of CR4) set.
#[cfg(target_arch = "x86_64")]
pub unsafe fn rdfsbase() -> u64 {
    let fs_base: u64;
    asm!("rdfsbase {0}", out(reg) fs_base, options(att_syntax));
    fs_base
}

/// "Dereferences" the fs register at offset 0.
///
/// # Safety
/// fs needs to point to valid address.
#[cfg(target_arch = "x86_64")]
pub unsafe fn fs_deref() -> u64 {
    let fs: u64;
    asm!("movq %fs:0x0, {0}", out(reg) fs, options(att_syntax));
    fs
}

/// "Dereferences" the gs register at offset 0.
///
/// # Safety
/// gs needs to point to valid address.
#[cfg(target_arch = "x86_64")]
pub unsafe fn gs_deref() -> u64 {
    let gs: u64;
    asm!("movq %gs:0x0, {0}", out(reg) gs, options(att_syntax));
    gs
}

/// Swap the GS register.
///
/// Exchanges the current GS base register value with the value contained
/// in MSR address IA32_KERNEL_GS_BASE.
///
/// The SWAPGS instruction is available only in 64-bit mode.
///
/// # Safety
/// The SWAPGS instruction is a privileged instruction intended for use by system software.
#[cfg(target_arch = "x86_64")]
pub unsafe fn swapgs() {
    asm!("swapgs");
}
