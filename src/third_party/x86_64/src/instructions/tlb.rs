//! Functions to flush the translation lookaside buffer (TLB).

use crate::VirtAddr;
use core::arch::asm;

/// Invalidate the given address in the TLB using the `invlpg` instruction.
#[inline]
pub fn flush(addr: VirtAddr) {
    unsafe {
        asm!("invlpg [{}]", in(reg) addr.as_u64(), options(nostack, preserves_flags));
    }
}

/// Invalidate the TLB completely by reloading the CR3 register.
#[inline]
pub fn flush_all() {
    use crate::registers::control::Cr3;
    let (frame, flags) = Cr3::read();
    unsafe { Cr3::write(frame, flags) }
}

/// The Invalidate PCID Command to execute.
#[derive(Debug)]
pub enum InvPicdCommand {
    /// The logical processor invalidates mappings—except global translations—for the linear address and PCID specified.
    Address(VirtAddr, Pcid),

    /// The logical processor invalidates all mappings—except global translations—associated with the PCID.
    Single(Pcid),

    /// The logical processor invalidates all mappings—including global translations—associated with any PCID.
    All,

    /// The logical processor invalidates all mappings—except global translations—associated with any PCID.
    AllExceptGlobal,
}

/// The INVPCID descriptor comprises 128 bits and consists of a PCID and a linear address.
/// For INVPCID type 0, the processor uses the full 64 bits of the linear address even outside 64-bit mode; the linear address is not used for other INVPCID types.
#[repr(C)]
#[derive(Debug)]
struct InvpcidDescriptor {
    address: u64,
    pcid: u64,
}

/// Structure of a PCID. A PCID has to be <= 4096 for x86_64.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pcid(u16);

impl Pcid {
    /// Create a new PCID. Will result in a failure if the value of
    /// PCID is out of expected bounds.
    pub const fn new(pcid: u16) -> Result<Pcid, &'static str> {
        if pcid >= 4096 {
            Err("PCID should be < 4096.")
        } else {
            Ok(Pcid(pcid))
        }
    }

    /// Get the value of the current PCID.
    pub const fn value(&self) -> u16 {
        self.0
    }
}

/// Invalidate the given address in the TLB using the `invpcid` instruction.
///
/// ## Safety
///
/// This function is unsafe as it requires CPUID.(EAX=07H, ECX=0H):EBX.INVPCID to be 1.
#[inline]
pub unsafe fn flush_pcid(command: InvPicdCommand) {
    let mut desc = InvpcidDescriptor {
        address: 0,
        pcid: 0,
    };

    let kind: u64;
    match command {
        InvPicdCommand::Address(addr, pcid) => {
            kind = 0;
            desc.pcid = pcid.value().into();
            desc.address = addr.as_u64()
        }
        InvPicdCommand::Single(pcid) => {
            kind = 1;
            desc.pcid = pcid.0.into()
        }
        InvPicdCommand::All => kind = 2,
        InvPicdCommand::AllExceptGlobal => kind = 3,
    }

    unsafe {
        asm!("invpcid {0}, [{1}]", in(reg) kind, in(reg) &desc, options(nostack, preserves_flags));
    }
}
