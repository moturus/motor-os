//! Functionality to manipulate segment registers, build segement
//! descriptors and selectors.
use bitflags::*;

use core::arch::asm;
use core::fmt;

use crate::Ring;

bitflags! {
    /// Specifies which element to load into a segment from
    /// descriptor tables (i.e., is a index to LDT or GDT table
    /// with some additional flags).
    ///
    /// See Intel 3a, Section 3.4.2 "Segment Selectors"
    pub struct SegmentSelector: u16 {
        /// Requestor Privilege Level
        const RPL_0 = 0b00;
        const RPL_1 = 0b01;
        const RPL_2 = 0b10;
        const RPL_3 = 0b11;

        /// Table Indicator (TI) 0 means GDT is used.
        const TI_GDT = 0 << 2;
        /// Table Indicator (TI) 1 means LDT is used.
        const TI_LDT = 1 << 2;
    }
}

impl SegmentSelector {
    /// Create a new SegmentSelector
    ///
    /// # Arguments
    ///  * `index` - index in GDT or LDT array.
    ///  * `rpl` - Requested privilege level of the selector
    pub const fn new(index: u16, rpl: Ring) -> SegmentSelector {
        SegmentSelector {
            bits: index << 3 | (rpl as u16),
        }
    }

    /// Returns segment selector's index in GDT or LDT.
    pub fn index(&self) -> u16 {
        self.bits >> 3
    }

    /// Make a new segment selector from a untyped u16 value.
    pub const fn from_raw(bits: u16) -> SegmentSelector {
        SegmentSelector { bits }
    }
}

impl fmt::Display for SegmentSelector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let r0 = match self.contains(SegmentSelector::RPL_0) {
            false => "",
            true => "Ring 0 segment selector.",
        };
        let r1 = match self.contains(SegmentSelector::RPL_1) {
            false => "",
            true => "Ring 1 segment selector.",
        };
        let r2 = match self.contains(SegmentSelector::RPL_2) {
            false => "",
            true => "Ring 2 segment selector.",
        };
        let r3 = match self.contains(SegmentSelector::RPL_3) {
            false => "",
            true => "Ring 3 segment selector.",
        };
        let tbl = match self.contains(SegmentSelector::TI_LDT) {
            false => "GDT Table",
            true => "LDT Table",
        };

        write!(
            f,
            "Index {} in {}, {}{}{}{}",
            self.bits >> 3,
            tbl,
            r0,
            r1,
            r2,
            r3
        )
    }
}

/// System-Segment and Gate-Descriptor Types 64-bit mode
/// See also Intel 3a, Table 3-2 System Segment and Gate-Descriptor Types.
#[allow(clippy::upper_case_acronyms)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SystemDescriptorTypes64 {
    //Reserved0 = 0b0000,
    //Reserved1 = 0b0001,
    LDT = 0b0010,
    //Reserved = 0b0011,
    //Reserved = 0b0100,
    //Reserved = 0b0101,
    //Reserved = 0b0110,
    //Reserved = 0b0111,
    //Reserved = 0b1000,
    TssAvailable = 0b1001,
    //Reserved = 0b1010,
    TssBusy = 0b1011,
    CallGate = 0b1100,
    //Reserved = 0b1101,
    InterruptGate = 0b1110,
    TrapGate = 0b1111,
}

/// System-Segment and Gate-Descriptor Types 32-bit mode.
/// See also Intel 3a, Table 3-2 System Segment and Gate-Descriptor Types.
#[allow(clippy::upper_case_acronyms)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SystemDescriptorTypes32 {
    //Reserved0 = 0b0000,
    TSSAvailable16 = 0b0001,
    LDT = 0b0010,
    TSSBusy16 = 0b0011,
    CallGate16 = 0b0100,
    TaskGate = 0b0101,
    InterruptGate16 = 0b0110,
    TrapGate16 = 0b0111,
    //Reserved1 = 0b1000,
    TssAvailable32 = 0b1001,
    //Reserved2 = 0b1010,
    TssBusy32 = 0b1011,
    CallGate32 = 0b1100,
    //Reserved3 = 0b1101,
    InterruptGate32 = 0b1110,
    TrapGate32 = 0b1111,
}

/// Data Segment types for descriptors.
/// See also Intel 3a, Table 3-1 Code- and Data-Segment Types.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DataSegmentType {
    /// Data Read-Only
    ReadOnly = 0b0000,
    /// Data Read-Only, accessed
    ReadOnlyAccessed = 0b0001,
    /// Data Read/Write
    ReadWrite = 0b0010,
    /// Data Read/Write, accessed
    ReadWriteAccessed = 0b0011,
    /// Data Read-Only, expand-down
    ReadExpand = 0b0100,
    /// Data Read-Only, expand-down, accessed
    ReadExpandAccessed = 0b0101,
    /// Data Read/Write, expand-down
    ReadWriteExpand = 0b0110,
    /// Data Read/Write, expand-down, accessed
    ReadWriteExpandAccessed = 0b0111,
}

/// Code Segment types for descriptors.
/// See also Intel 3a, Table 3-1 Code- and Data-Segment Types.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CodeSegmentType {
    /// Code Execute-Only
    Execute = 0b1000,
    /// Code Execute-Only, accessed
    ExecuteAccessed = 0b1001,
    /// Code Execute/Read
    ExecuteRead = 0b1010,
    /// Code Execute/Read, accessed
    ExecuteReadAccessed = 0b1011,
    /// Code Execute-Only, conforming
    ExecuteConforming = 0b1100,
    /// Code Execute-Only, conforming, accessed
    ExecuteConformingAccessed = 0b1101,
    /// Code Execute/Read, conforming
    ExecuteReadConforming = 0b1110,
    /// Code Execute/Read, conforming, accessed
    ExecuteReadConformingAccessed = 0b1111,
}

/// Helper enum type to differentiate between the different descriptor types that all end up written in the same field.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum DescriptorType {
    System64(SystemDescriptorTypes64),
    System32(SystemDescriptorTypes32),
    Data(DataSegmentType),
    Code(CodeSegmentType),
}

/// Trait that defines the architecture specific functions for building various system segment descriptors
/// which are available on all 16, 32, and 64 bits.
pub trait GateDescriptorBuilder<Size> {
    fn tss_descriptor(base: u64, limit: u64, available: bool) -> Self;
    fn call_gate_descriptor(selector: SegmentSelector, offset: Size) -> Self;
    fn interrupt_descriptor(selector: SegmentSelector, offset: Size) -> Self;
    fn trap_gate_descriptor(selector: SegmentSelector, offset: Size) -> Self;
}

/// Trait to implement for building a task-gate (this descriptor is not implemented for 64-bit systems since
/// Hardware task switches are not supported in IA-32e mode.).
pub trait TaskGateDescriptorBuilder {
    fn task_gate_descriptor(selector: SegmentSelector) -> Self;
}

/// Trait to define functions that build architecture specific code and data descriptors.
pub trait SegmentDescriptorBuilder<Size> {
    fn code_descriptor(base: Size, limit: Size, cst: CodeSegmentType) -> Self;
    fn data_descriptor(base: Size, limit: Size, dst: DataSegmentType) -> Self;
}

/// Trait to define functions that build an architecture specific ldt descriptor.
/// There is no corresponding ldt descriptor type for 16 bit.
pub trait LdtDescriptorBuilder<Size> {
    fn ldt_descriptor(base: Size, limit: Size) -> Self;
}

pub trait BuildDescriptor<Descriptor> {
    fn finish(&self) -> Descriptor;
}

/// Makes building descriptors easier (hopefully).
#[derive(Debug)]
pub struct DescriptorBuilder {
    /// The base defines the location of byte 0 of the segment within the 4-GByte linear address space.
    /// The limit is the size of the range covered by the segment. Really a 20bit value.
    pub(crate) base_limit: Option<(u64, u64)>,
    /// Alternative to base_limit we use a selector that points to a segment and an an offset for certain descriptors.
    pub(crate) selector_offset: Option<(SegmentSelector, u64)>,
    /// Descriptor type
    pub(crate) typ: Option<DescriptorType>,
    /// Specifies the privilege level of the segment. The privilege level can range from 0 to 3, with 0 being the most privileged level.
    pub(crate) dpl: Option<Ring>,
    /// Indicates whether the segment is present in memory (set) or not present (clear).
    pub(crate) present: bool,
    /// Available for use by system software
    pub(crate) avl: bool,
    /// Default operation size
    pub(crate) db: bool,
    /// Determines the scaling of the segment limit field. When the granularity flag is clear, the segment limit is interpreted in byte units; when flag is set, the segment limit is interpreted in 4-KByte units.
    pub(crate) limit_granularity_4k: bool,
    /// 64-bit code segment (IA-32e mode only)
    pub(crate) l: bool,
    /// Interrupt stack table (IST) selector (IA-32e mode only)
    pub(crate) ist: u8,
}

impl DescriptorBuilder {
    /// Start building a new descriptor with a base and limit.
    pub(crate) fn with_base_limit(base: u64, limit: u64) -> DescriptorBuilder {
        DescriptorBuilder {
            base_limit: Some((base, limit)),
            selector_offset: None,
            typ: None,
            dpl: None,
            present: false,
            avl: false,
            db: false,
            limit_granularity_4k: false,
            l: false,
            ist: 0,
        }
    }

    /// Start building a new descriptor with a segment selector and offset.
    pub(crate) fn with_selector_offset(
        selector: SegmentSelector,
        offset: u64,
    ) -> DescriptorBuilder {
        DescriptorBuilder {
            base_limit: None,
            selector_offset: Some((selector, offset)),
            typ: None,
            dpl: None,
            present: false,
            avl: false,
            db: false,
            limit_granularity_4k: false,
            l: false,
            ist: 0,
        }
    }

    pub(crate) fn set_type(mut self, typ: DescriptorType) -> DescriptorBuilder {
        self.typ = Some(typ);
        self
    }

    /// The segment limit is interpreted in 4-KByte units if this is set.
    pub fn limit_granularity_4kb(mut self) -> DescriptorBuilder {
        self.limit_granularity_4k = true;
        self
    }

    /// Indicates whether the segment is present in memory (set) or not present (clear).
    pub fn present(mut self) -> DescriptorBuilder {
        self.present = true;
        self
    }

    /// Specifies the privilege level of the segment.
    pub fn dpl(mut self, dpl: Ring) -> DescriptorBuilder {
        self.dpl = Some(dpl);
        self
    }

    /// Toggle the AVL bit.
    pub fn avl(mut self) -> DescriptorBuilder {
        self.avl = true;
        self
    }

    /// Set default operation size (false for 16bit segment, true for 32bit segments).
    pub fn db(mut self) -> DescriptorBuilder {
        self.db = true;
        self
    }

    /// Set L bit if this descriptor is a 64-bit code segment.
    /// In IA-32e mode, bit 21 of the second doubleword of the segment descriptor indicates whether a code segment
    /// contains native 64-bit code. A value of 1 indicates instructions in this code segment are executed in 64-bit mode.
    pub fn l(mut self) -> DescriptorBuilder {
        self.l = true;
        self
    }

    /// Set a the interrupt stack table index (only if this ends up being a 64-bit interrupt descriptor).
    pub fn ist(mut self, index: u8) -> DescriptorBuilder {
        debug_assert!(index <= 7);
        self.ist = index;
        self
    }
}

impl GateDescriptorBuilder<u32> for DescriptorBuilder {
    fn tss_descriptor(base: u64, limit: u64, available: bool) -> DescriptorBuilder {
        let typ = match available {
            true => DescriptorType::System32(SystemDescriptorTypes32::TssAvailable32),
            false => DescriptorType::System32(SystemDescriptorTypes32::TssBusy32),
        };

        DescriptorBuilder::with_base_limit(base, limit).set_type(typ)
    }

    fn call_gate_descriptor(selector: SegmentSelector, offset: u32) -> DescriptorBuilder {
        DescriptorBuilder::with_selector_offset(selector, offset.into()).set_type(
            DescriptorType::System32(SystemDescriptorTypes32::CallGate32),
        )
    }

    fn interrupt_descriptor(selector: SegmentSelector, offset: u32) -> DescriptorBuilder {
        DescriptorBuilder::with_selector_offset(selector, offset.into()).set_type(
            DescriptorType::System32(SystemDescriptorTypes32::InterruptGate32),
        )
    }

    fn trap_gate_descriptor(selector: SegmentSelector, offset: u32) -> DescriptorBuilder {
        DescriptorBuilder::with_selector_offset(selector, offset.into()).set_type(
            DescriptorType::System32(SystemDescriptorTypes32::TrapGate32),
        )
    }
}

impl TaskGateDescriptorBuilder for DescriptorBuilder {
    fn task_gate_descriptor(selector: SegmentSelector) -> DescriptorBuilder {
        DescriptorBuilder::with_selector_offset(selector, 0)
            .set_type(DescriptorType::System32(SystemDescriptorTypes32::TaskGate))
    }
}

impl SegmentDescriptorBuilder<u32> for DescriptorBuilder {
    fn code_descriptor(base: u32, limit: u32, cst: CodeSegmentType) -> DescriptorBuilder {
        DescriptorBuilder::with_base_limit(base.into(), limit.into())
            .set_type(DescriptorType::Code(cst))
    }

    fn data_descriptor(base: u32, limit: u32, dst: DataSegmentType) -> DescriptorBuilder {
        DescriptorBuilder::with_base_limit(base.into(), limit.into())
            .set_type(DescriptorType::Data(dst))
    }
}

impl LdtDescriptorBuilder<u32> for DescriptorBuilder {
    fn ldt_descriptor(base: u32, limit: u32) -> DescriptorBuilder {
        DescriptorBuilder::with_base_limit(base.into(), limit.into())
            .set_type(DescriptorType::System32(SystemDescriptorTypes32::LDT))
    }
}

impl BuildDescriptor<Descriptor> for DescriptorBuilder {
    fn finish(&self) -> Descriptor {
        let mut desc: Descriptor = Default::default();
        desc.apply_builder_settings(self);

        let typ = match self.typ {
            Some(DescriptorType::System64(_)) => {
                panic!("You shall not use 64-bit types on 32-bit descriptor.")
            }
            Some(DescriptorType::System32(typ)) => typ as u8,
            Some(DescriptorType::Data(typ)) => {
                desc.set_s();
                typ as u8
            }
            Some(DescriptorType::Code(typ)) => {
                desc.set_s();
                typ as u8
            }
            None => unreachable!("Type not set, this is a library bug in x86."),
        };
        desc.set_type(typ);

        desc
    }
}

/// Entry for IDT, GDT or LDT. Provides size and location of a segment.
///
/// See Intel 3a, Section 3.4.5 "Segment Descriptors", and Section 3.5.2
#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
pub struct Descriptor {
    pub lower: u32,
    pub upper: u32,
}

impl fmt::Display for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Descriptor(0x{:x})", self.as_u64())
    }
}

impl Descriptor {
    pub const NULL: Descriptor = Descriptor { lower: 0, upper: 0 };

    pub fn as_u64(&self) -> u64 {
        (self.upper as u64) << 32 | self.lower as u64
    }

    pub(crate) fn apply_builder_settings(&mut self, builder: &DescriptorBuilder) {
        if let Some(ring) = builder.dpl {
            self.set_dpl(ring)
        }
        if let Some((base, limit)) = builder.base_limit {
            self.set_base_limit(base as u32, limit as u32)
        }
        if let Some((selector, offset)) = builder.selector_offset {
            self.set_selector_offset(selector, offset as u32)
        }

        if builder.present {
            self.set_p();
        }
        if builder.avl {
            self.set_avl();
        }
        if builder.db {
            self.set_db();
        }
        if builder.limit_granularity_4k {
            self.set_g();
        }
        if builder.l {
            self.set_l();
        }
    }

    /// Create a new segment, TSS or LDT descriptor
    /// by setting the three base and two limit fields.
    pub fn set_base_limit(&mut self, base: u32, limit: u32) {
        // Clear the base and limit fields in Descriptor
        self.lower = 0;
        self.upper &= 0x00F0FF00;

        // Set the new base
        self.lower |= base << 16;
        self.upper |= (base >> 16) & 0xff;
        self.upper |= (base >> 24) << 24;

        // Set the new limit
        self.lower |= limit & 0xffff;
        let limit_last_four_bits = (limit >> 16) & 0x0f;
        self.upper |= limit_last_four_bits << 16;
    }

    /// Creates a new descriptor with selector and offset (for IDT Gate descriptors,
    /// e.g. Trap, Interrupts and Task gates)
    pub fn set_selector_offset(&mut self, selector: SegmentSelector, offset: u32) {
        // Clear the selector and offset
        self.lower = 0;
        self.upper &= 0x0000ffff;

        // Set selector
        self.lower |= (selector.bits() as u32) << 16;

        // Set offset
        self.lower |= offset & 0x0000ffff;
        self.upper |= offset & 0xffff0000;
    }

    /// Set the type of the descriptor (bits 8-11).
    /// Indicates the segment or gate type and specifies the kinds of access that can be made to the
    /// segment and the direction of growth. The interpretation of this field depends on whether the descriptor
    /// type flag specifies an application (code or data) descriptor or a system descriptor.
    pub fn set_type(&mut self, typ: u8) {
        self.upper &= !(0x0f << 8); // clear
        self.upper |= (typ as u32 & 0x0f) << 8;
    }

    /// Specifies whether the segment descriptor is for a system segment (S flag is clear) or a code or data segment (S flag is set).
    pub fn set_s(&mut self) {
        self.upper |= bit!(12);
    }

    /// Specifies the privilege level of the segment. The DPL is used to control access to the segment.
    pub fn set_dpl(&mut self, ring: Ring) {
        assert!(ring as u32 <= 0b11);
        self.upper &= !(0b11 << 13);
        self.upper |= (ring as u32) << 13;
    }

    /// Set Present bit.
    /// Indicates whether the segment is present in memory (set) or not present (clear).
    /// If this flag is clear, the processor generates a segment-not-present exception (#NP) when a segment selector
    /// that points to the segment descriptor is loaded into a segment register.
    pub fn set_p(&mut self) {
        self.upper |= bit!(15);
    }

    /// Set AVL bit. System software can use this bit to store information.
    pub fn set_avl(&mut self) {
        self.upper |= bit!(20);
    }

    /// Set L
    /// In IA-32e mode, bit 21 of the second doubleword of the segment descriptor indicates whether a
    /// code segment contains native 64-bit code. A value of 1 indicates instructions in this code
    /// segment are executed in 64-bit mode. A value of 0 indicates the instructions in this code segment
    /// are executed in compatibility mode. If L-bit is set, then D-bit must be cleared.
    pub fn set_l(&mut self) {
        self.upper |= bit!(21);
    }

    /// Set D/B.
    /// Performs different functions depending on whether the segment descriptor is an executable code segment,
    /// an expand-down data segment, or a stack segment.
    pub fn set_db(&mut self) {
        self.upper |= bit!(22);
    }

    /// Set G bit
    /// Determines the scaling of the segment limit field.
    /// When the granularity flag is clear, the segment limit is interpreted in byte units;
    /// when flag is set, the segment limit is interpreted in 4-KByte units.
    pub fn set_g(&mut self) {
        self.upper |= bit!(23);
    }
}

/// Reload stack segment register.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn load_ss(sel: SegmentSelector) {
    asm!("movw {0:x}, %ss", in(reg) sel.bits(), options(att_syntax));
}

/// Reload data segment register.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn load_ds(sel: SegmentSelector) {
    asm!("movw {0:x}, %ds", in(reg) sel.bits(), options(att_syntax));
}

/// Reload es segment register.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn load_es(sel: SegmentSelector) {
    asm!("movw {0:x}, %es", in(reg) sel.bits(), options(att_syntax));
}

/// Reload fs segment register.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn load_fs(sel: SegmentSelector) {
    asm!("movw {0:x}, %fs", in(reg) sel.bits(), options(att_syntax));
}

/// Reload gs segment register.
///
/// # Safety
/// Needs CPL 0.
pub unsafe fn load_gs(sel: SegmentSelector) {
    asm!("movw {0:x}, %gs", in(reg) sel.bits(), options(att_syntax));
}

pub use crate::current::segmentation::load_cs;

/// Returns the current value of the code segment register.
pub fn cs() -> SegmentSelector {
    let segment: u16;
    unsafe { asm!("mov %cs, {0:x}", out(reg) segment, options(att_syntax)) };
    SegmentSelector::from_raw(segment)
}

/// Returns the current value of the extra segment register.
pub fn es() -> SegmentSelector {
    let segment: u16;
    unsafe { asm!("mov %es, {0:x}", out(reg) segment, options(att_syntax)) };
    SegmentSelector::from_raw(segment)
}

/// Returns the current value of the stack segment register.
pub fn ss() -> SegmentSelector {
    let segment: u16;
    unsafe { asm!("mov %ss, {0:x}", out(reg) segment, options(att_syntax)) };
    SegmentSelector::from_raw(segment)
}

/// Returns the current value of the data segment register.
pub fn ds() -> SegmentSelector {
    let segment: u16;
    unsafe { asm!("mov %ds, {0:x}", out(reg) segment, options(att_syntax)) };
    SegmentSelector::from_raw(segment)
}

/// Returns the current value of the FS segment register.
pub fn fs() -> SegmentSelector {
    let segment: u16;
    unsafe { asm!("mov %fs, {0:x}", out(reg) segment, options(att_syntax)) };
    SegmentSelector::from_raw(segment)
}

/// Returns the current value of the GS segment register.
pub fn gs() -> SegmentSelector {
    let segment: u16;
    unsafe { asm!("mov %gs, {0:x}", out(reg) segment, options(att_syntax)) };
    SegmentSelector::from_raw(segment)
}

#[cfg(all(test, feature = "utest"))]
mod test {
    use super::*;
    use crate::Ring;

    #[test]
    fn test_x86_64_default_gdt() {
        let null: Descriptor = Default::default();
        let code_kernel: Descriptor =
            DescriptorBuilder::code_descriptor(0, 0xFFFFF, CodeSegmentType::ExecuteRead)
                .present()
                .dpl(Ring::Ring0)
                .limit_granularity_4kb()
                .db()
                .finish();
        let stack_kernel: Descriptor =
            DescriptorBuilder::data_descriptor(0, 0xFFFFF, DataSegmentType::ReadWrite)
                .present()
                .dpl(Ring::Ring0)
                .limit_granularity_4kb()
                .db()
                .finish();
        let code_user: Descriptor =
            DescriptorBuilder::code_descriptor(0, 0xFFFFF, CodeSegmentType::ExecuteRead)
                .present()
                .limit_granularity_4kb()
                .db()
                .dpl(Ring::Ring3)
                .finish();
        let stack_user: Descriptor =
            DescriptorBuilder::data_descriptor(0, 0xFFFFF, DataSegmentType::ReadWrite)
                .present()
                .limit_granularity_4kb()
                .db()
                .dpl(Ring::Ring3)
                .finish();

        assert_eq!(0x0000000000000000u64, null.as_u64());
        assert_eq!(
            0x00CF9A000000FFFFu64,
            code_kernel.as_u64(),
            "code_kernel: {:#b} first bit to differ is {}",
            (code_kernel.as_u64() ^ 0x00CF9A000000FFFFu64),
            (code_kernel.as_u64() ^ 0x00CF9A000000FFFFu64).trailing_zeros()
        );
        assert_eq!(
            0x00CF92000000FFFFu64,
            stack_kernel.as_u64(),
            "stack_kernel: {:#b} first bit to differ is {}",
            (stack_kernel.as_u64() ^ 0x00CF92000000FFFFu64),
            (stack_kernel.as_u64() ^ 0x00CF92000000FFFFu64).trailing_zeros()
        );
        assert_eq!(
            0x00CFFA000000FFFFu64,
            code_user.as_u64(),
            "code_user: {:#b} first bit to differ is {}",
            (code_user.as_u64() ^ 0x00CFFA000000FFFFu64),
            (code_user.as_u64() ^ 0x00CFFA000000FFFFu64).trailing_zeros()
        );
        assert_eq!(
            0x00CFF2000000FFFFu64,
            stack_user.as_u64(),
            "stack_user: {:#b} first bit to differ is {}",
            (stack_user.as_u64() ^ 0x00CFF2000000FFFFu64),
            (stack_user.as_u64() ^ 0x00CFF2000000FFFFu64).trailing_zeros()
        );
    }
}
