//! Access to I/O ports

use core::arch::asm;
use core::fmt;
use core::marker::PhantomData;

pub use crate::structures::port::{PortRead, PortWrite};

impl PortRead for u8 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> u8 {
        let value: u8;
        unsafe {
            asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
        }
        value
    }
}

impl PortRead for u16 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> u16 {
        let value: u16;
        unsafe {
            asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack, preserves_flags));
        }
        value
    }
}

impl PortRead for u32 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> u32 {
        let value: u32;
        unsafe {
            asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack, preserves_flags));
        }
        value
    }
}

impl PortWrite for u8 {
    #[inline]
    unsafe fn write_to_port(port: u16, value: u8) {
        unsafe {
            asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
        }
    }
}

impl PortWrite for u16 {
    #[inline]
    unsafe fn write_to_port(port: u16, value: u16) {
        unsafe {
            asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags));
        }
    }
}

impl PortWrite for u32 {
    #[inline]
    unsafe fn write_to_port(port: u16, value: u32) {
        unsafe {
            asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
        }
    }
}

mod sealed {
    pub trait Access {
        const DEBUG_NAME: &'static str;
    }
}

/// A marker trait for access types which allow reading port values.
pub trait PortReadAccess: sealed::Access {}

/// A marker trait for access types which allow writing port values.
pub trait PortWriteAccess: sealed::Access {}

/// An access marker type indicating that a port is only allowed to read values.
#[derive(Debug)]
pub struct ReadOnlyAccess(());

impl sealed::Access for ReadOnlyAccess {
    const DEBUG_NAME: &'static str = "ReadOnly";
}
impl PortReadAccess for ReadOnlyAccess {}

/// An access marker type indicating that a port is only allowed to write values.
#[derive(Debug)]
pub struct WriteOnlyAccess(());

impl sealed::Access for WriteOnlyAccess {
    const DEBUG_NAME: &'static str = "WriteOnly";
}
impl PortWriteAccess for WriteOnlyAccess {}

/// An access marker type indicating that a port is allowed to read or write values.
#[derive(Debug)]
pub struct ReadWriteAccess(());

impl sealed::Access for ReadWriteAccess {
    const DEBUG_NAME: &'static str = "ReadWrite";
}
impl PortReadAccess for ReadWriteAccess {}
impl PortWriteAccess for ReadWriteAccess {}

/// An I/O port.
///
/// The port reads or writes values of type `T` and has read/write access specified by `A`.
///
/// Use the provided marker types or aliases to get a port type with the access you need:
/// * `PortGeneric<T, ReadWriteAccess>` -> `Port<T>`
/// * `PortGeneric<T, ReadOnlyAccess>` -> `PortReadOnly<T>`
/// * `PortGeneric<T, WriteOnlyAccess>` -> `PortWriteOnly<T>`
pub struct PortGeneric<T, A> {
    port: u16,
    phantom: PhantomData<(T, A)>,
}

/// A read-write I/O port.
pub type Port<T> = PortGeneric<T, ReadWriteAccess>;

/// A read-only I/O port.
pub type PortReadOnly<T> = PortGeneric<T, ReadOnlyAccess>;

/// A write-only I/O port.
pub type PortWriteOnly<T> = PortGeneric<T, WriteOnlyAccess>;

impl<T, A> PortGeneric<T, A> {
    /// Creates an I/O port with the given port number.
    #[inline]
    pub const fn new(port: u16) -> PortGeneric<T, A> {
        PortGeneric {
            port,
            phantom: PhantomData,
        }
    }
}

impl<T: PortRead, A: PortReadAccess> PortGeneric<T, A> {
    /// Reads from the port.
    ///
    /// ## Safety
    ///
    /// This function is unsafe because the I/O port could have side effects that violate memory
    /// safety.
    #[inline]
    pub unsafe fn read(&mut self) -> T {
        unsafe { T::read_from_port(self.port) }
    }
}

impl<T: PortWrite, A: PortWriteAccess> PortGeneric<T, A> {
    /// Writes to the port.
    ///
    /// ## Safety
    ///
    /// This function is unsafe because the I/O port could have side effects that violate memory
    /// safety.
    #[inline]
    pub unsafe fn write(&mut self, value: T) {
        unsafe { T::write_to_port(self.port, value) }
    }
}

impl<T, A: sealed::Access> fmt::Debug for PortGeneric<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortGeneric")
            .field("port", &self.port)
            .field("size", &core::mem::size_of::<T>())
            .field("access", &format_args!("{}", A::DEBUG_NAME))
            .finish()
    }
}

impl<T, A> Clone for PortGeneric<T, A> {
    fn clone(&self) -> Self {
        Self {
            port: self.port,
            phantom: PhantomData,
        }
    }
}

impl<T, A> PartialEq for PortGeneric<T, A> {
    fn eq(&self, other: &Self) -> bool {
        self.port == other.port
    }
}

impl<T, A> Eq for PortGeneric<T, A> {}
