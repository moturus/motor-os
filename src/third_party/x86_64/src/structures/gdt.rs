//! Types for the Global Descriptor Table and segment selectors.

pub use crate::registers::segmentation::SegmentSelector;
use crate::structures::tss::TaskStateSegment;
use crate::PrivilegeLevel;
use bit_field::BitField;
use bitflags::bitflags;
// imports for intra-doc links
#[cfg(doc)]
use crate::registers::segmentation::{Segment, CS, SS};

/// A 64-bit mode global descriptor table (GDT).
///
/// In 64-bit mode, segmentation is not supported. The GDT is used nonetheless, for example for
/// switching between user and kernel mode or for loading a TSS.
///
/// The GDT has a fixed size of 8 entries, trying to add more entries will panic.
///
/// You do **not** need to add a null segment descriptor yourself - this is already done
/// internally.
///
/// Data segment registers in ring 0 can be loaded with the null segment selector. When running in
/// ring 3, the `ss` register must point to a valid data segment which can be obtained through the
/// [`Descriptor::user_data_segment()`](Descriptor::user_data_segment) function. Code segments must
/// be valid and non-null at all times and can be obtained through the
/// [`Descriptor::kernel_code_segment()`](Descriptor::kernel_code_segment) and
/// [`Descriptor::user_code_segment()`](Descriptor::user_code_segment) in rings 0 and 3
/// respectively.
///
/// For more info, see:
/// [x86 Instruction Reference for `mov`](https://www.felixcloutier.com/x86/mov#64-bit-mode-exceptions),
/// [Intel Manual](https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf),
/// [AMD Manual](https://www.amd.com/system/files/TechDocs/24593.pdf)
///
/// # Example
/// ```
/// use x86_64::structures::gdt::{GlobalDescriptorTable, Descriptor};
///
/// let mut gdt = GlobalDescriptorTable::new();
/// gdt.add_entry(Descriptor::kernel_code_segment());
/// gdt.add_entry(Descriptor::user_code_segment());
/// gdt.add_entry(Descriptor::user_data_segment());
///
/// // Add entry for TSS, call gdt.load() then update segment registers
/// ```

#[derive(Debug, Clone)]
pub struct GlobalDescriptorTable {
    table: [u64; 8],
    len: usize,
}

impl GlobalDescriptorTable {
    /// Creates an empty GDT.
    #[inline]
    pub const fn new() -> GlobalDescriptorTable {
        GlobalDescriptorTable {
            table: [0; 8],
            len: 1,
        }
    }

    /// Forms a GDT from a slice of `u64`.
    ///
    /// # Safety
    ///
    /// * The user must make sure that the entries are well formed
    /// * The provided slice **must not be larger than 8 items** (only up to the first 8 will be observed.)
    #[inline]
    pub const unsafe fn from_raw_slice(slice: &[u64]) -> GlobalDescriptorTable {
        let len = slice.len();
        let mut table = [0; 8];
        let mut idx = 0;

        assert!(
            len <= 8,
            "initializing a GDT from a slice requires it to be **at most** 8 elements."
        );

        while idx < len {
            table[idx] = slice[idx];
            idx += 1;
        }

        GlobalDescriptorTable { table, len }
    }

    /// Get a reference to the internal table.
    ///
    /// The resulting slice may contain system descriptors, which span two `u64`s.
    #[inline]
    pub fn as_raw_slice(&self) -> &[u64] {
        &self.table[..self.len]
    }

    /// Adds the given segment descriptor to the GDT, returning the segment selector.
    ///
    /// Panics if the GDT doesn't have enough free entries to hold the Descriptor.
    #[inline]
    #[cfg_attr(feature = "const_fn", rustversion::attr(all(), const))]
    pub fn add_entry(&mut self, entry: Descriptor) -> SegmentSelector {
        let index = match entry {
            Descriptor::UserSegment(value) => {
                if self.len > self.table.len().saturating_sub(1) {
                    panic!("GDT full")
                }
                self.push(value)
            }
            Descriptor::SystemSegment(value_low, value_high) => {
                if self.len > self.table.len().saturating_sub(2) {
                    panic!("GDT requires two free spaces to hold a SystemSegment")
                }
                let index = self.push(value_low);
                self.push(value_high);
                index
            }
        };

        let rpl = match entry {
            Descriptor::UserSegment(value) => {
                if DescriptorFlags::from_bits_truncate(value).contains(DescriptorFlags::DPL_RING_3)
                {
                    PrivilegeLevel::Ring3
                } else {
                    PrivilegeLevel::Ring0
                }
            }
            Descriptor::SystemSegment(_, _) => PrivilegeLevel::Ring0,
        };

        SegmentSelector::new(index as u16, rpl)
    }

    /// Loads the GDT in the CPU using the `lgdt` instruction. This does **not** alter any of the
    /// segment registers; you **must** (re)load them yourself using [the appropriate
    /// functions](crate::instructions::segmentation):
    /// [`SS::set_reg()`] and [`CS::set_reg()`].
    #[cfg(feature = "instructions")]
    #[inline]
    pub fn load(&'static self) {
        // SAFETY: static lifetime ensures no modification after loading.
        unsafe { self.load_unsafe() };
    }

    /// Loads the GDT in the CPU using the `lgdt` instruction. This does **not** alter any of the
    /// segment registers; you **must** (re)load them yourself using [the appropriate
    /// functions](crate::instructions::segmentation):
    /// [`SS::set_reg()`] and [`CS::set_reg()`].
    ///
    /// # Safety
    ///
    /// Unlike `load` this function will not impose a static lifetime constraint
    /// this means its up to the user to ensure that there will be no modifications
    /// after loading and that the GDT will live for as long as it's loaded.
    ///
    #[cfg(feature = "instructions")]
    #[inline]
    pub unsafe fn load_unsafe(&self) {
        use crate::instructions::tables::lgdt;
        unsafe {
            lgdt(&self.pointer());
        }
    }

    #[inline]
    #[cfg_attr(feature = "const_fn", rustversion::attr(all(), const))]
    fn push(&mut self, value: u64) -> usize {
        let index = self.len;
        self.table[index] = value;
        self.len += 1;
        index
    }

    /// Creates the descriptor pointer for this table. This pointer can only be
    /// safely used if the table is never modified or destroyed while in use.
    #[cfg(feature = "instructions")]
    fn pointer(&self) -> super::DescriptorTablePointer {
        use core::mem::size_of;
        super::DescriptorTablePointer {
            base: crate::VirtAddr::new(self.table.as_ptr() as u64),
            limit: (self.len * size_of::<u64>() - 1) as u16,
        }
    }
}

/// A 64-bit mode segment descriptor.
///
/// Segmentation is no longer supported in 64-bit mode, so most of the descriptor
/// contents are ignored.
#[derive(Debug, Clone)]
pub enum Descriptor {
    /// Descriptor for a code or data segment.
    ///
    /// Since segmentation is no longer supported in 64-bit mode, almost all of
    /// code and data descriptors is ignored. Only some flags are still used.
    UserSegment(u64),
    /// A system segment descriptor such as a LDT or TSS descriptor.
    SystemSegment(u64, u64),
}

bitflags! {
    /// Flags for a GDT descriptor. Not all flags are valid for all descriptor types.
    pub struct DescriptorFlags: u64 {
        /// Set by the processor if this segment has been accessed. Only cleared by software.
        /// _Setting_ this bit in software prevents GDT writes on first use.
        const ACCESSED          = 1 << 40;
        /// For 32-bit data segments, sets the segment as writable. For 32-bit code segments,
        /// sets the segment as _readable_. In 64-bit mode, ignored for all segments.
        const WRITABLE          = 1 << 41;
        /// For code segments, sets the segment as “conforming”, influencing the
        /// privilege checks that occur on control transfers. For 32-bit data segments,
        /// sets the segment as "expand down". In 64-bit mode, ignored for data segments.
        const CONFORMING        = 1 << 42;
        /// This flag must be set for code segments and unset for data segments.
        const EXECUTABLE        = 1 << 43;
        /// This flag must be set for user segments (in contrast to system segments).
        const USER_SEGMENT      = 1 << 44;
        /// The DPL for this descriptor is Ring 3. In 64-bit mode, ignored for data segments.
        const DPL_RING_3        = 3 << 45;
        /// Must be set for any segment, causes a segment not present exception if not set.
        const PRESENT           = 1 << 47;
        /// Available for use by the Operating System
        const AVAILABLE         = 1 << 52;
        /// Must be set for 64-bit code segments, unset otherwise.
        const LONG_MODE         = 1 << 53;
        /// Use 32-bit (as opposed to 16-bit) operands. If [`LONG_MODE`][Self::LONG_MODE] is set,
        /// this must be unset. In 64-bit mode, ignored for data segments.
        const DEFAULT_SIZE      = 1 << 54;
        /// Limit field is scaled by 4096 bytes. In 64-bit mode, ignored for all segments.
        const GRANULARITY       = 1 << 55;

        /// Bits `0..=15` of the limit field (ignored in 64-bit mode)
        const LIMIT_0_15        = 0xFFFF;
        /// Bits `16..=19` of the limit field (ignored in 64-bit mode)
        const LIMIT_16_19       = 0xF << 48;
        /// Bits `0..=23` of the base field (ignored in 64-bit mode, except for fs and gs)
        const BASE_0_23         = 0xFF_FFFF << 16;
        /// Bits `24..=31` of the base field (ignored in 64-bit mode, except for fs and gs)
        const BASE_24_31        = 0xFF << 56;
    }
}

/// The following constants define default values for common GDT entries. They
/// are all "flat" segments, meaning they can access the entire address space.
/// These values all set [`WRITABLE`][DescriptorFlags::WRITABLE] and
/// [`ACCESSED`][DescriptorFlags::ACCESSED]. They also match the values loaded
/// by the `syscall`/`sysret` and `sysenter`/`sysexit` instructions.
///
/// In short, these values disable segmentation, permission checks, and access
/// tracking at the GDT level. Kernels using these values should use paging to
/// implement this functionality.
impl DescriptorFlags {
    // Flags that we set for all our default segments
    const COMMON: Self = Self::from_bits_truncate(
        Self::USER_SEGMENT.bits()
            | Self::PRESENT.bits()
            | Self::WRITABLE.bits()
            | Self::ACCESSED.bits()
            | Self::LIMIT_0_15.bits()
            | Self::LIMIT_16_19.bits()
            | Self::GRANULARITY.bits(),
    );
    /// A kernel data segment (64-bit or flat 32-bit)
    pub const KERNEL_DATA: Self =
        Self::from_bits_truncate(Self::COMMON.bits() | Self::DEFAULT_SIZE.bits());
    /// A flat 32-bit kernel code segment
    pub const KERNEL_CODE32: Self = Self::from_bits_truncate(
        Self::COMMON.bits() | Self::EXECUTABLE.bits() | Self::DEFAULT_SIZE.bits(),
    );
    /// A 64-bit kernel code segment
    pub const KERNEL_CODE64: Self = Self::from_bits_truncate(
        Self::COMMON.bits() | Self::EXECUTABLE.bits() | Self::LONG_MODE.bits(),
    );
    /// A user data segment (64-bit or flat 32-bit)
    pub const USER_DATA: Self =
        Self::from_bits_truncate(Self::KERNEL_DATA.bits() | Self::DPL_RING_3.bits());
    /// A flat 32-bit user code segment
    pub const USER_CODE32: Self =
        Self::from_bits_truncate(Self::KERNEL_CODE32.bits() | Self::DPL_RING_3.bits());
    /// A 64-bit user code segment
    pub const USER_CODE64: Self =
        Self::from_bits_truncate(Self::KERNEL_CODE64.bits() | Self::DPL_RING_3.bits());
}

impl Descriptor {
    /// Creates a segment descriptor for a 64-bit kernel code segment. Suitable
    /// for use with `syscall` or 64-bit `sysenter`.
    #[inline]
    pub const fn kernel_code_segment() -> Descriptor {
        Descriptor::UserSegment(DescriptorFlags::KERNEL_CODE64.bits())
    }

    /// Creates a segment descriptor for a kernel data segment (32-bit or
    /// 64-bit). Suitable for use with `syscall` or `sysenter`.
    #[inline]
    pub const fn kernel_data_segment() -> Descriptor {
        Descriptor::UserSegment(DescriptorFlags::KERNEL_DATA.bits())
    }

    /// Creates a segment descriptor for a ring 3 data segment (32-bit or
    /// 64-bit). Suitable for use with `sysret` or `sysexit`.
    #[inline]
    pub const fn user_data_segment() -> Descriptor {
        Descriptor::UserSegment(DescriptorFlags::USER_DATA.bits())
    }

    /// Creates a segment descriptor for a 64-bit ring 3 code segment. Suitable
    /// for use with `sysret` or `sysexit`.
    #[inline]
    pub const fn user_code_segment() -> Descriptor {
        Descriptor::UserSegment(DescriptorFlags::USER_CODE64.bits())
    }

    /// Creates a TSS system descriptor for the given TSS.
    ///
    /// While it is possible to create multiple Descriptors that point to the
    /// same TSS, this generally isn't recommended, as the TSS usually contains
    /// per-CPU information such as the RSP and IST pointers. Instead, there
    /// should be exactly one TSS and one corresponding TSS Descriptor per CPU.
    /// Then, each of these descriptors should be placed in a GDT (which can
    /// either be global or per-CPU).
    #[inline]
    pub fn tss_segment(tss: &'static TaskStateSegment) -> Descriptor {
        use self::DescriptorFlags as Flags;
        use core::mem::size_of;

        let ptr = tss as *const _ as u64;

        let mut low = Flags::PRESENT.bits();
        // base
        low.set_bits(16..40, ptr.get_bits(0..24));
        low.set_bits(56..64, ptr.get_bits(24..32));
        // limit (the `-1` in needed since the bound is inclusive)
        low.set_bits(0..16, (size_of::<TaskStateSegment>() - 1) as u64);
        // type (0b1001 = available 64-bit tss)
        low.set_bits(40..44, 0b1001);

        let mut high = 0;
        high.set_bits(0..32, ptr.get_bits(32..64));

        Descriptor::SystemSegment(low, high)
    }
}

#[cfg(test)]
mod tests {
    use super::DescriptorFlags as Flags;
    use super::*;

    #[test]
    #[rustfmt::skip]
    pub fn linux_kernel_defaults() {
        // Make sure our defaults match the ones used by the Linux kernel.
        // Constants pulled from an old version of arch/x86/kernel/cpu/common.c
        assert_eq!(Flags::KERNEL_CODE64.bits(), 0x00af9b000000ffff);
        assert_eq!(Flags::KERNEL_CODE32.bits(), 0x00cf9b000000ffff);
        assert_eq!(Flags::KERNEL_DATA.bits(),   0x00cf93000000ffff);
        assert_eq!(Flags::USER_CODE64.bits(),   0x00affb000000ffff);
        assert_eq!(Flags::USER_CODE32.bits(),   0x00cffb000000ffff);
        assert_eq!(Flags::USER_DATA.bits(),     0x00cff3000000ffff);
    }

    // Makes a GDT that has two free slots
    fn make_six_entry_gdt() -> GlobalDescriptorTable {
        let mut gdt = GlobalDescriptorTable::new();
        gdt.add_entry(Descriptor::kernel_code_segment());
        gdt.add_entry(Descriptor::kernel_data_segment());
        gdt.add_entry(Descriptor::UserSegment(DescriptorFlags::USER_CODE32.bits()));
        gdt.add_entry(Descriptor::user_data_segment());
        gdt.add_entry(Descriptor::user_code_segment());
        assert_eq!(gdt.len, 6);
        gdt
    }

    static TSS: TaskStateSegment = TaskStateSegment::new();

    fn make_full_gdt() -> GlobalDescriptorTable {
        let mut gdt = make_six_entry_gdt();
        gdt.add_entry(Descriptor::tss_segment(&TSS));
        assert_eq!(gdt.len, 8);
        gdt
    }

    #[test]
    pub fn push_max_segments() {
        // Make sure we don't panic with user segments
        let mut gdt = make_six_entry_gdt();
        gdt.add_entry(Descriptor::user_data_segment());
        assert_eq!(gdt.len, 7);
        gdt.add_entry(Descriptor::user_data_segment());
        assert_eq!(gdt.len, 8);
        // Make sure we don't panic with system segments
        let _ = make_full_gdt();
    }

    #[test]
    #[should_panic]
    pub fn panic_user_segment() {
        let mut gdt = make_full_gdt();
        gdt.add_entry(Descriptor::user_data_segment());
    }

    #[test]
    #[should_panic]
    pub fn panic_system_segment() {
        let mut gdt = make_six_entry_gdt();
        gdt.add_entry(Descriptor::user_data_segment());
        // We have one free slot, but the GDT requires two
        gdt.add_entry(Descriptor::tss_segment(&TSS));
    }
}
