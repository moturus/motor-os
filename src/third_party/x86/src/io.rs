//! I/O port functionality.

use core::arch::asm;

/// Write 8 bits to port
///
/// # Safety
/// Needs IO privileges.
#[inline]
pub unsafe fn outb(port: u16, val: u8) {
    asm!("outb %al, %dx", in("al") val, in("dx") port, options(att_syntax));
}

/// Read 8 bits from port
///
/// # Safety
/// Needs IO privileges.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let ret: u8;
    asm!("inb %dx, %al", in("dx") port, out("al") ret, options(att_syntax));
    ret
}

/// Write 16 bits to port
///
/// # Safety
/// Needs IO privileges.
#[inline]
pub unsafe fn outw(port: u16, val: u16) {
    asm!("outw %ax, %dx", in("ax") val, in("dx") port, options(att_syntax));
}

/// Read 16 bits from port
///
/// # Safety
/// Needs IO privileges.
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    let ret: u16;
    asm!("inw %dx, %ax", in("dx") port, out("ax") ret, options(att_syntax));
    ret
}

/// Write 32 bits to port
///
/// # Safety
/// Needs IO privileges.
#[inline]
pub unsafe fn outl(port: u16, val: u32) {
    asm!("outl %eax, %dx", in("eax") val, in("dx") port, options(att_syntax));
}

/// Read 32 bits from port
///
/// # Safety
/// Needs IO privileges.
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    let ret: u32;
    asm!("inl %dx, %eax", out("eax") ret, in("dx") port, options(att_syntax));
    ret
}

#[cfg(all(test, feature = "vmtest"))]
mod x86testing {
    use super::*;
    use x86test::*;

    #[x86test(ioport(0x0, 0xaf))]
    fn check_outb() {
        unsafe {
            outb(0x0, 0xaf);
            // hypervisor will fail here if port 0x0 doesn't see 0xaf
        }
    }

    #[x86test(ioport(0x0, 0xaf))]
    #[should_panic]
    fn check_outb_wrong_value() {
        unsafe {
            outb(0x0, 0xff);
        }
    }

    #[x86test(ioport(0x1, 0xad))]
    fn check_inb() {
        unsafe {
            kassert!(
                inb(0x1) == 0xad,
                "`inb` instruction didn't read the correct value"
            );
        }
    }

    #[x86test(ioport(0x2, 0xad))]
    #[should_panic]
    fn check_inb_wrong_port() {
        unsafe {
            kassert!(
                inb(0x1) == 0xad,
                "`inb` instruction didn't read the correct value"
            );
        }
    }

    #[x86test(ioport(0x2, 0x99))]
    fn check_outw() {
        unsafe {
            super::outw(0x2, 0x99);
            // hypervisor will fail here if port 0x2 doesn't see 0x99
        }
    }

    #[x86test(ioport(0x3, 0xfefe))]
    fn check_inw() {
        unsafe {
            kassert!(
                inw(0x3) == 0xfefe,
                "`inw` instruction didn't read the correct value"
            );
        }
    }

    #[x86test(ioport(0x5, 0xbeefaaaa))]
    fn check_outl() {
        unsafe {
            outl(0x5, 0xbeefaaaa);
            // hypervisor will fail here if port 0x5 doesn't see 0xbeefaaaa
        }
    }

    #[x86test(ioport(0x4, 0xdeadbeef))]
    fn check_inl() {
        unsafe {
            kassert!(
                inl(0x4) == 0xdeadbeef,
                "`inl` instruction didn't read the correct value"
            );
        }
    }
}
