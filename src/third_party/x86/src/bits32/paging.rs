//! Description of the data-structures for IA-32 paging mode.

use bitflags::*;

use core::convert::{From, Into};
use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops;

macro_rules! check_flag {
    ($doc:meta, $fun:ident, $flag:expr) => {
        #[$doc]
        pub fn $fun(self) -> bool {
            self.flags().contains($flag)
        }
    };
}

/// Align address downwards.
///
/// Returns the greatest x with alignment `align` so that x <= addr.
/// The alignment must be a power of 2.
#[inline(always)]
fn align_down(addr: u32, align: u32) -> u32 {
    addr & !(align - 1)
}

/// Align address upwards.
///
/// Returns the smallest x with alignment `align` so that x >= addr.
/// The alignment must be a power of 2.
#[inline(always)]
fn align_up(addr: u32, align: u32) -> u32 {
    let align_mask = align - 1;
    if addr & align_mask == 0 {
        addr
    } else {
        (addr | align_mask) + 1
    }
}

/// A wrapper for a physical address.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct PAddr(pub u32);

impl PAddr {
    /// Convert to `u32`
    pub fn as_u32(self) -> u32 {
        self.0
    }

    /// Convert to `usize`
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }

    /// Convert to mutable pointer.
    pub fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }

    /// Convert to pointer.
    pub fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    /// Physical Address zero.
    pub const fn zero() -> Self {
        PAddr(0)
    }

    /// Is zero?
    pub fn is_zero(self) -> bool {
        self == PAddr::zero()
    }

    fn align_up<U>(self, align: U) -> Self
    where
        U: Into<u32>,
    {
        PAddr(align_up(self.0, align.into()))
    }

    fn align_down<U>(self, align: U) -> Self
    where
        U: Into<u32>,
    {
        PAddr(align_down(self.0, align.into()))
    }

    /// Offset within the 4 KiB page.
    pub fn base_page_offset(self) -> u32 {
        self.0 & (BASE_PAGE_SIZE as u32 - 1)
    }

    /// Offset within the 4 MiB page.
    pub fn large_page_offset(self) -> u32 {
        self.0 & (LARGE_PAGE_SIZE as u32 - 1)
    }

    /// Return address of nearest 4 KiB page (lower or equal than self).
    pub fn align_down_to_base_page(self) -> Self {
        self.align_down(BASE_PAGE_SIZE as u32)
    }

    /// Return address of nearest 4 MiB page (lower or equal than self).
    pub fn align_down_to_large_page(self) -> Self {
        self.align_down(LARGE_PAGE_SIZE as u32)
    }

    /// Return address of nearest 4 KiB page (higher or equal than self).
    pub fn align_up_to_base_page(self) -> Self {
        self.align_up(BASE_PAGE_SIZE as u32)
    }

    /// Return address of nearest 4 MiB page (higher or equal than self).
    pub fn align_up_to_large_page(self) -> Self {
        self.align_up(LARGE_PAGE_SIZE as u32)
    }

    /// Is this address aligned to a 4 KiB page?
    pub fn is_base_page_aligned(self) -> bool {
        self.align_down(BASE_PAGE_SIZE as u32) == self
    }

    /// Is this address aligned to a 4 MiB page?
    pub fn is_large_page_aligned(self) -> bool {
        self.align_down(LARGE_PAGE_SIZE as u32) == self
    }

    /// Is this address aligned to `align`?
    ///
    /// # Note
    /// `align` must be a power of two.
    pub fn is_aligned<U>(self, align: U) -> bool
    where
        U: Into<u32> + Copy,
    {
        if !align.into().is_power_of_two() {
            return false;
        }

        self.align_down(align) == self
    }
}

impl From<u32> for PAddr {
    fn from(num: u32) -> Self {
        PAddr(num)
    }
}

impl From<usize> for PAddr {
    fn from(num: usize) -> Self {
        PAddr(num as u32)
    }
}

impl From<i32> for PAddr {
    fn from(num: i32) -> Self {
        PAddr(num as u32)
    }
}

#[allow(clippy::clippy::from_over_into)]
impl Into<u32> for PAddr {
    fn into(self) -> u32 {
        self.0
    }
}

#[allow(clippy::clippy::from_over_into)]
impl Into<usize> for PAddr {
    fn into(self) -> usize {
        self.0 as usize
    }
}

impl ops::Add for PAddr {
    type Output = PAddr;

    fn add(self, rhs: PAddr) -> Self::Output {
        PAddr(self.0 + rhs.0)
    }
}

impl ops::Add<u32> for PAddr {
    type Output = PAddr;

    fn add(self, rhs: u32) -> Self::Output {
        PAddr::from(self.0 + rhs)
    }
}

impl ops::Add<usize> for PAddr {
    type Output = PAddr;

    fn add(self, rhs: usize) -> Self::Output {
        PAddr::from(self.0 + rhs as u32)
    }
}

impl ops::AddAssign for PAddr {
    fn add_assign(&mut self, other: PAddr) {
        *self = PAddr::from(self.0 + other.0);
    }
}

impl ops::AddAssign<u32> for PAddr {
    fn add_assign(&mut self, offset: u32) {
        *self = PAddr::from(self.0 + offset);
    }
}

impl ops::Sub for PAddr {
    type Output = PAddr;

    fn sub(self, rhs: PAddr) -> Self::Output {
        PAddr::from(self.0 - rhs.0)
    }
}

impl ops::Sub<u32> for PAddr {
    type Output = PAddr;

    fn sub(self, rhs: u32) -> Self::Output {
        PAddr::from(self.0 - rhs)
    }
}

impl ops::Sub<usize> for PAddr {
    type Output = PAddr;

    fn sub(self, rhs: usize) -> Self::Output {
        PAddr::from(self.0 - rhs as u32)
    }
}

impl ops::Rem for PAddr {
    type Output = PAddr;

    fn rem(self, rhs: PAddr) -> Self::Output {
        PAddr(self.0 % rhs.0)
    }
}

impl ops::Rem<u32> for PAddr {
    type Output = u32;

    fn rem(self, rhs: u32) -> Self::Output {
        self.0 % rhs
    }
}

impl ops::Rem<usize> for PAddr {
    type Output = u32;

    fn rem(self, rhs: usize) -> Self::Output {
        self.0 % (rhs as u32)
    }
}

impl ops::BitAnd for PAddr {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        PAddr(self.0 & rhs.0)
    }
}

impl ops::BitAnd<u32> for PAddr {
    type Output = u32;

    fn bitand(self, rhs: u32) -> Self::Output {
        Into::<u32>::into(self) & rhs
    }
}

impl ops::BitOr for PAddr {
    type Output = PAddr;

    fn bitor(self, rhs: PAddr) -> Self::Output {
        PAddr(self.0 | rhs.0)
    }
}

impl ops::BitOr<u32> for PAddr {
    type Output = u32;

    fn bitor(self, rhs: u32) -> Self::Output {
        self.0 | rhs
    }
}

impl ops::Shr<u32> for PAddr {
    type Output = u32;

    fn shr(self, rhs: u32) -> Self::Output {
        self.0 >> rhs
    }
}

impl fmt::Binary for PAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for PAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for PAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::LowerHex for PAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Octal for PAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::UpperHex for PAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Pointer for PAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use core::fmt::LowerHex;
        self.0.fmt(f)
    }
}

#[allow(clippy::clippy::derive_hash_xor_eq)]
impl Hash for PAddr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// A wrapper for an IO address (IOVA / DMA Address for devices)
#[repr(transparent)]
#[derive(Copy, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct IOAddr(pub u32);

impl IOAddr {
    /// Convert to `u32`
    pub fn as_u32(self) -> u32 {
        self.0
    }

    /// Convert to `usize`
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }

    /// IO Address zero.
    pub const fn zero() -> Self {
        IOAddr(0)
    }

    /// Is zero?
    pub fn is_zero(self) -> bool {
        self == IOAddr::zero()
    }

    fn align_up<U>(self, align: U) -> Self
    where
        U: Into<u32>,
    {
        IOAddr(align_up(self.0, align.into()))
    }

    fn align_down<U>(self, align: U) -> Self
    where
        U: Into<u32>,
    {
        IOAddr(align_down(self.0, align.into()))
    }

    /// Offset within the 4 KiB page.
    pub fn base_page_offset(self) -> u32 {
        self.0 & (BASE_PAGE_SIZE as u32 - 1)
    }

    /// Offset within the 4 MiB page.
    pub fn large_page_offset(self) -> u32 {
        self.0 & (LARGE_PAGE_SIZE as u32 - 1)
    }

    /// Return address of nearest 4 KiB page (lower or equal than self).
    pub fn align_down_to_base_page(self) -> Self {
        self.align_down(BASE_PAGE_SIZE as u32)
    }

    /// Return address of nearest 4 MiB page (lower or equal than self).
    pub fn align_down_to_large_page(self) -> Self {
        self.align_down(LARGE_PAGE_SIZE as u32)
    }

    /// Return address of nearest 4 KiB page (higher or equal than self).
    pub fn align_up_to_base_page(self) -> Self {
        self.align_up(BASE_PAGE_SIZE as u32)
    }

    /// Return address of nearest 4 MiB page (higher or equal than self).
    pub fn align_up_to_large_page(self) -> Self {
        self.align_up(LARGE_PAGE_SIZE as u32)
    }

    /// Is this address aligned to a 4 KiB page?
    pub fn is_base_page_aligned(self) -> bool {
        self.align_down(BASE_PAGE_SIZE as u32) == self
    }

    /// Is this address aligned to a 4 MiB page?
    pub fn is_large_page_aligned(self) -> bool {
        self.align_down(LARGE_PAGE_SIZE as u32) == self
    }

    /// Is this address aligned to `align`?
    ///
    /// # Note
    /// `align` must be a power of two.
    pub fn is_aligned<U>(self, align: U) -> bool
    where
        U: Into<u32> + Copy,
    {
        if !align.into().is_power_of_two() {
            return false;
        }

        self.align_down(align) == self
    }
}

impl From<u32> for IOAddr {
    fn from(num: u32) -> Self {
        IOAddr(num)
    }
}

impl From<usize> for IOAddr {
    fn from(num: usize) -> Self {
        IOAddr(num as u32)
    }
}

impl From<i32> for IOAddr {
    fn from(num: i32) -> Self {
        IOAddr(num as u32)
    }
}

#[allow(clippy::clippy::from_over_into)]
impl Into<u32> for IOAddr {
    fn into(self) -> u32 {
        self.0
    }
}

#[allow(clippy::clippy::from_over_into)]
impl Into<usize> for IOAddr {
    fn into(self) -> usize {
        self.0 as usize
    }
}

impl ops::Add for IOAddr {
    type Output = IOAddr;

    fn add(self, rhs: IOAddr) -> Self::Output {
        IOAddr(self.0 + rhs.0)
    }
}

impl ops::Add<u32> for IOAddr {
    type Output = IOAddr;

    fn add(self, rhs: u32) -> Self::Output {
        IOAddr::from(self.0 + rhs)
    }
}

impl ops::Add<usize> for IOAddr {
    type Output = IOAddr;

    fn add(self, rhs: usize) -> Self::Output {
        IOAddr::from(self.0 + rhs as u32)
    }
}

impl ops::AddAssign for IOAddr {
    fn add_assign(&mut self, other: IOAddr) {
        *self = IOAddr::from(self.0 + other.0);
    }
}

impl ops::AddAssign<u32> for IOAddr {
    fn add_assign(&mut self, offset: u32) {
        *self = IOAddr::from(self.0 + offset);
    }
}

impl ops::Sub for IOAddr {
    type Output = IOAddr;

    fn sub(self, rhs: IOAddr) -> Self::Output {
        IOAddr::from(self.0 - rhs.0)
    }
}

impl ops::Sub<u32> for IOAddr {
    type Output = IOAddr;

    fn sub(self, rhs: u32) -> Self::Output {
        IOAddr::from(self.0 - rhs)
    }
}

impl ops::Sub<usize> for IOAddr {
    type Output = IOAddr;

    fn sub(self, rhs: usize) -> Self::Output {
        IOAddr::from(self.0 - rhs as u32)
    }
}

impl ops::Rem for IOAddr {
    type Output = IOAddr;

    fn rem(self, rhs: IOAddr) -> Self::Output {
        IOAddr(self.0 % rhs.0)
    }
}

impl ops::Rem<u32> for IOAddr {
    type Output = u32;

    fn rem(self, rhs: u32) -> Self::Output {
        self.0 % rhs
    }
}

impl ops::Rem<usize> for IOAddr {
    type Output = u32;

    fn rem(self, rhs: usize) -> Self::Output {
        self.0 % (rhs as u32)
    }
}

impl ops::BitAnd for IOAddr {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        IOAddr(self.0 & rhs.0)
    }
}

impl ops::BitAnd<u32> for IOAddr {
    type Output = u32;

    fn bitand(self, rhs: u32) -> Self::Output {
        Into::<u32>::into(self) & rhs
    }
}

impl ops::BitOr for IOAddr {
    type Output = IOAddr;

    fn bitor(self, rhs: IOAddr) -> Self::Output {
        IOAddr(self.0 | rhs.0)
    }
}

impl ops::BitOr<u32> for IOAddr {
    type Output = u32;

    fn bitor(self, rhs: u32) -> Self::Output {
        self.0 | rhs
    }
}

impl ops::Shr<u32> for IOAddr {
    type Output = u32;

    fn shr(self, rhs: u32) -> Self::Output {
        self.0 >> rhs
    }
}

impl fmt::Binary for IOAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for IOAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for IOAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::LowerHex for IOAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Octal for IOAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::UpperHex for IOAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Pointer for IOAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use core::fmt::LowerHex;
        self.0.fmt(f)
    }
}

#[allow(clippy::clippy::derive_hash_xor_eq)]
impl Hash for IOAddr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// A wrapper for a virtual address.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct VAddr(pub u32);

impl VAddr {
    /// Convert from `u32`
    pub const fn from_u32(v: u32) -> Self {
        VAddr(v)
    }

    /// Convert from `usize`
    pub const fn from_usize(v: usize) -> Self {
        VAddr(v as u32)
    }

    /// Convert to `u32`
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Convert to `usize`
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    /// Convert to mutable pointer.
    pub fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }

    /// Convert to pointer.
    pub fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    /// Virtual Address zero.
    pub const fn zero() -> Self {
        VAddr(0)
    }

    /// Is zero?
    pub fn is_zero(self) -> bool {
        self == VAddr::zero()
    }

    fn align_up<U>(self, align: U) -> Self
    where
        U: Into<u32>,
    {
        VAddr(align_up(self.0, align.into()))
    }

    fn align_down<U>(self, align: U) -> Self
    where
        U: Into<u32>,
    {
        VAddr(align_down(self.0, align.into()))
    }

    /// Offset within the 4 KiB page.
    pub fn base_page_offset(self) -> u32 {
        self.0 & (BASE_PAGE_SIZE as u32 - 1)
    }

    /// Offset within the 4 MiB page.
    pub fn large_page_offset(self) -> u32 {
        self.0 & (LARGE_PAGE_SIZE as u32 - 1)
    }

    /// Return address of nearest 4 KiB page (lower or equal than self).
    pub fn align_down_to_base_page(self) -> Self {
        self.align_down(BASE_PAGE_SIZE as u32)
    }

    /// Return address of nearest 4 MiB page (lower or equal than self).
    pub fn align_down_to_large_page(self) -> Self {
        self.align_down(LARGE_PAGE_SIZE as u32)
    }

    /// Return address of nearest 4 KiB page (higher or equal than self).
    pub fn align_up_to_base_page(self) -> Self {
        self.align_up(BASE_PAGE_SIZE as u32)
    }

    /// Return address of nearest 4 MiB page (higher or equal than self).
    pub fn align_up_to_large_page(self) -> Self {
        self.align_up(LARGE_PAGE_SIZE as u32)
    }

    /// Is this address aligned to a 4 KiB page?
    pub fn is_base_page_aligned(self) -> bool {
        self.align_down(BASE_PAGE_SIZE as u32) == self
    }

    /// Is this address aligned to a 4 MiB page?
    pub fn is_large_page_aligned(self) -> bool {
        self.align_down(LARGE_PAGE_SIZE as u32) == self
    }

    /// Is this address aligned to `align`?
    ///
    /// # Note
    /// `align` must be a power of two.
    pub fn is_aligned<U>(self, align: U) -> bool
    where
        U: Into<u32> + Copy,
    {
        if !align.into().is_power_of_two() {
            return false;
        }

        self.align_down(align) == self
    }
}

impl From<u32> for VAddr {
    fn from(num: u32) -> Self {
        VAddr(num)
    }
}

impl From<i32> for VAddr {
    fn from(num: i32) -> Self {
        VAddr(num as u32)
    }
}

#[allow(clippy::clippy::from_over_into)]
impl Into<u32> for VAddr {
    fn into(self) -> u32 {
        self.0
    }
}

impl From<usize> for VAddr {
    fn from(num: usize) -> Self {
        VAddr(num as u32)
    }
}

#[allow(clippy::clippy::from_over_into)]
impl Into<usize> for VAddr {
    fn into(self) -> usize {
        self.0 as usize
    }
}

impl ops::Add for VAddr {
    type Output = VAddr;

    fn add(self, rhs: VAddr) -> Self::Output {
        VAddr(self.0 + rhs.0)
    }
}

impl ops::Add<u32> for VAddr {
    type Output = VAddr;

    fn add(self, rhs: u32) -> Self::Output {
        VAddr(self.0 + rhs)
    }
}

impl ops::Add<usize> for VAddr {
    type Output = VAddr;

    fn add(self, rhs: usize) -> Self::Output {
        VAddr::from(self.0 + rhs as u32)
    }
}

impl ops::AddAssign for VAddr {
    fn add_assign(&mut self, other: VAddr) {
        *self = VAddr::from(self.0 + other.0);
    }
}

impl ops::AddAssign<u32> for VAddr {
    fn add_assign(&mut self, offset: u32) {
        *self = VAddr::from(self.0 + offset);
    }
}

impl ops::AddAssign<usize> for VAddr {
    fn add_assign(&mut self, offset: usize) {
        *self = VAddr::from(self.0 + offset as u32);
    }
}

impl ops::Sub for VAddr {
    type Output = VAddr;

    fn sub(self, rhs: VAddr) -> Self::Output {
        VAddr::from(self.0 - rhs.0)
    }
}

impl ops::Sub<u32> for VAddr {
    type Output = VAddr;

    fn sub(self, rhs: u32) -> Self::Output {
        VAddr::from(self.0 - rhs)
    }
}

impl ops::Sub<usize> for VAddr {
    type Output = VAddr;

    fn sub(self, rhs: usize) -> Self::Output {
        VAddr::from(self.0 - rhs as u32)
    }
}

impl ops::Rem for VAddr {
    type Output = VAddr;

    fn rem(self, rhs: VAddr) -> Self::Output {
        VAddr(self.0 % rhs.0)
    }
}

impl ops::Rem<u32> for VAddr {
    type Output = u32;

    fn rem(self, rhs: Self::Output) -> Self::Output {
        self.0 % rhs
    }
}

impl ops::Rem<usize> for VAddr {
    type Output = usize;

    fn rem(self, rhs: Self::Output) -> Self::Output {
        self.as_usize() % rhs
    }
}

impl ops::BitAnd for VAddr {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        VAddr(self.0 & rhs.0)
    }
}

impl ops::BitAnd<u32> for VAddr {
    type Output = VAddr;

    fn bitand(self, rhs: u32) -> Self::Output {
        VAddr(self.0 & rhs)
    }
}

impl ops::BitAnd<usize> for VAddr {
    type Output = VAddr;

    fn bitand(self, rhs: usize) -> Self::Output {
        VAddr(self.0 & rhs as u32)
    }
}

impl ops::BitAnd<i32> for VAddr {
    type Output = VAddr;

    fn bitand(self, rhs: i32) -> Self::Output {
        VAddr(self.0 & rhs as u32)
    }
}

impl ops::BitOr for VAddr {
    type Output = VAddr;

    fn bitor(self, rhs: VAddr) -> VAddr {
        VAddr(self.0 | rhs.0)
    }
}

impl ops::BitOr<u32> for VAddr {
    type Output = VAddr;

    fn bitor(self, rhs: u32) -> Self::Output {
        VAddr(self.0 | rhs)
    }
}

impl ops::BitOr<usize> for VAddr {
    type Output = VAddr;

    fn bitor(self, rhs: usize) -> Self::Output {
        VAddr(self.0 | rhs as u32)
    }
}

impl ops::Shr<u32> for VAddr {
    type Output = u32;

    fn shr(self, rhs: u32) -> Self::Output {
        self.0 >> rhs as u32
    }
}

impl ops::Shr<usize> for VAddr {
    type Output = u32;

    fn shr(self, rhs: usize) -> Self::Output {
        self.0 >> rhs as u32
    }
}

impl ops::Shr<i32> for VAddr {
    type Output = u32;

    fn shr(self, rhs: i32) -> Self::Output {
        self.0 >> rhs as u32
    }
}

impl fmt::Binary for VAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for VAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::Debug for VAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::LowerHex for VAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Octal for VAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::UpperHex for VAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Pointer for VAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use core::fmt::LowerHex;
        self.0.fmt(f)
    }
}

#[allow(clippy::clippy::derive_hash_xor_eq)]
impl Hash for VAddr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

/// Log2 of base page size (12 bits).
pub const BASE_PAGE_SHIFT: usize = 12;

/// Size of a base page (4 KiB)
pub const BASE_PAGE_SIZE: usize = 4096;

/// Size of a large page (4 MiB)
pub const LARGE_PAGE_SIZE: usize = 1024 * 1024 * 4;

/// Size of a cache-line
pub const CACHE_LINE_SIZE: usize = 64;

/// A type wrapping a base page with a 4 KiB buffer.
pub struct Page([u8; BASE_PAGE_SIZE]);

/// A type wrapping a large page with a 4 MiB buffer.
pub struct LargePage([u8; LARGE_PAGE_SIZE]);

/// Mask to find the physical address of an entry in a page-table.
const ADDRESS_MASK: u32 = !0xfff;
const ADDRESS_MASK_PSE: u32 = !0x3fffff;

/// Page tables have 512 = 4096 / 32 entries.
pub const PAGE_SIZE_ENTRIES: usize = 1024;

/// A page directory.
pub type PD = [PDEntry; PAGE_SIZE_ENTRIES];

/// A page table.
pub type PT = [PTEntry; PAGE_SIZE_ENTRIES];

/// Given virtual address calculate corresponding entry in PD.
#[inline]
pub fn pd_index(addr: VAddr) -> usize {
    ((addr >> 22usize) & 0b1111111111) as usize
}

/// Given virtual address calculate corresponding entry in PT.
#[inline]
pub fn pt_index(addr: VAddr) -> usize {
    ((addr >> 12usize) & 0b1111111111) as usize
}

bitflags! {
    /// PD configuration bits description.
    #[repr(transparent)]
    pub struct PDFlags: u32 {
        /// Present; must be 1 to map a 4-MByte page.
        const P       = bit!(0);
        /// Read/write; if 0, writes may not be allowed to the 4-MByte page referenced by this entry.
        const RW      = bit!(1);
        /// User/supervisor; if 0, user-mode accesses are not allowed to the 4-MByte page referenced by this entry.
        const US      = bit!(2);
        /// Page-level write-through.
        const PWT     = bit!(3);
        /// Page-level cache disable.
        const PCD     = bit!(4);
        /// Accessed; indicates whether software has accessed the 4-MByte page referenced by this entry.
        const A       = bit!(5);
        /// Dirty; indicates whether software has written to the 4-MByte page referenced by this entry.
        const D       = bit!(6);
        /// Page size; if set this entry maps a 4-MByte page; otherwise, this entry references a page directory.
        const PS      = bit!(7);
        /// Global; if CR4.PGE = 1, determines whether the translation is global; ignored otherwise.
        const G       = bit!(8);
        /// If the PAT is supported, indirectly determines the memory type used to access the 4-MByte page referenced by this entry;
        /// otherwise, reserved (must be 0)
        const PAT     = bit!(12);
    }
}

/// A PD Entry consists of an address and a bunch of flags.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PDEntry(pub u32);

impl fmt::Debug for PDEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PDEntry {{ {:#x}, {:?} }}", self.address(), self.flags())
    }
}

impl PDEntry {
    /// Creates a new PDEntry.
    ///
    /// # Arguments
    ///
    ///  * `pt` - The physical address of the page table.
    ///  * `flags`- Additional flags for the entry.
    ///
    /// # Implementation notes
    ///
    /// This doesn't support PSE-36 or PSE-40.
    pub fn new(pt: PAddr, flags: PDFlags) -> PDEntry {
        let mask = if flags.contains(PDFlags::PS) {
            ADDRESS_MASK_PSE
        } else {
            ADDRESS_MASK
        };
        let pt_val = pt & mask;
        assert!(pt_val == pt.into());
        assert!(pt % BASE_PAGE_SIZE == 0);
        PDEntry(pt_val | flags.bits)
    }

    /// Retrieves the physical address in this entry.
    pub fn address(self) -> PAddr {
        if self.flags().contains(PDFlags::PS) {
            PAddr::from(self.0 & ADDRESS_MASK_PSE)
        } else {
            PAddr::from(self.0 & ADDRESS_MASK)
        }
    }

    /// Returns the flags corresponding to this entry.
    pub fn flags(self) -> PDFlags {
        PDFlags::from_bits_truncate(self.0)
    }

    check_flag!(
        doc = "Present; must be 1 to map a 4-MByte page.",
        is_present,
        PDFlags::P
    );
    check_flag!(doc = "Read/write; if 0, writes may not be allowed to the 4-MByte page referenced by this entry.",
                is_writeable, PDFlags::RW);
    check_flag!(doc = "User/supervisor; if 0, user-mode accesses are not allowed to the 4-MByte page referenced by this entry.",
                is_user_mode_allowed, PDFlags::US);
    check_flag!(
        doc = "Page-level write-through.",
        is_page_write_through,
        PDFlags::PWT
    );
    check_flag!(
        doc = "Page-level cache disable.",
        is_page_level_cache_disabled,
        PDFlags::PCD
    );
    check_flag!(doc = "Accessed; indicates whether software has accessed the 4-MByte page referenced by this entry.",
                is_accessed, PDFlags::A);
    check_flag!(doc = "Dirty; indicates whether software has written to the 4-MByte page referenced by this entry.",
                is_dirty, PDFlags::D);
    check_flag!(doc = "Page size; if set this entry maps a 4-MByte page; otherwise, this entry references a page directory.",
                is_page, PDFlags::PS);
    check_flag!(doc = "Global; if CR4.PGE = 1, determines whether the translation is global; ignored otherwise.",
                is_global, PDFlags::G);
    check_flag!(doc = "If the PAT is supported, indirectly determines the memory type used to access the 4-MByte page referenced by this entry; otherwise, reserved (must be 0)",
                is_pat, PDFlags::PAT);
}

bitflags! {
    /// PT Entry bits description.
    #[repr(transparent)]
    pub struct PTFlags: u32 {
        /// Present; must be 1 to map a 4-KByte page.
        const P       = bit!(0);
        /// Read/write; if 0, writes may not be allowed to the 4-KByte page referenced by this entry.
        const RW      = bit!(1);
        /// User/supervisor; if 0, user-mode accesses are not allowed to the 4-KByte page referenced by this entry.
        const US      = bit!(2);
        /// Page-level write-through.
        const PWT     = bit!(3);
        /// Page-level cache disable.
        const PCD     = bit!(4);
        /// Accessed; indicates whether software has accessed the 4-KByte page referenced by this entry.
        const A       = bit!(5);
        /// Dirty; indicates whether software has written to the 4-KByte page referenced by this entry.
        const D       = bit!(6);
        /// If the PAT is supported, indirectly determines the memory type used to access the 4-KByte page referenced by this entry;
        /// otherwise, reserved (must be 0)
        const PAT     = bit!(7);
        /// Global; if CR4.PGE = 1, determines whether the translation is global; ignored otherwise.
        const G       = bit!(8);
    }
}

/// A PT Entry consists of an address and a bunch of flags.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PTEntry(pub u32);

impl fmt::Debug for PTEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PTEntry {{ {:#x}, {:?} }}", self.address(), self.flags())
    }
}

impl PTEntry {
    /// Creates a new PTEntry.
    ///
    /// # Arguments
    ///
    ///  * `page` - The physical address of the backing 4 KiB page.
    ///  * `flags`- Additional flags for the entry.
    pub fn new(page: PAddr, flags: PTFlags) -> PTEntry {
        let page_val = page & ADDRESS_MASK;
        assert!(page_val == page.into());
        assert!(page % BASE_PAGE_SIZE == 0);
        PTEntry(page_val | flags.bits)
    }

    /// Retrieves the physical address in this entry.
    pub fn address(self) -> PAddr {
        PAddr::from(self.0 & ADDRESS_MASK)
    }

    /// Returns the flags corresponding to this entry.
    pub fn flags(self) -> PTFlags {
        PTFlags::from_bits_truncate(self.0)
    }

    check_flag!(
        doc = "Present; must be 1 to map a 4-KByte page.",
        is_present,
        PTFlags::P
    );
    check_flag!(doc = "Read/write; if 0, writes may not be allowed to the 4-KByte page referenced by this entry.",
                is_writeable, PTFlags::RW);
    check_flag!(doc = "User/supervisor; if 0, user-mode accesses are not allowed to the 4-KByte page referenced by this entry.",
                is_user_mode_allowed, PTFlags::US);
    check_flag!(
        doc = "Page-level write-through.",
        is_page_write_through,
        PTFlags::PWT
    );
    check_flag!(
        doc = "Page-level cache disable.",
        is_page_level_cache_disabled,
        PTFlags::PCD
    );
    check_flag!(doc = "Accessed; indicates whether software has accessed the 4-KByte page referenced by this entry.",
                is_accessed, PTFlags::A);
    check_flag!(doc = "Dirty; indicates whether software has written to the 4-KByte page referenced by this entry.",
                is_dirty, PTFlags::D);
    check_flag!(doc = "If the PAT is supported, indirectly determines the memory type used to access the 4-KByte page referenced by this entry; otherwise, reserved (must be 0)",
                is_pat, PTFlags::PAT);
    check_flag!(doc = "Global; if CR4.PGE = 1, determines whether the translation is global; ignored otherwise.",
                is_global, PTFlags::G);
}

#[cfg(all(test, feature = "utest"))]
mod test {
    use super::*;

    #[test]
    fn paddr_align() {
        let base = PAddr::from(0x1000);
        assert_eq!(base.base_page_offset(), 0x0);
        assert_eq!(base.large_page_offset(), 0x1000);
        assert_eq!(base.align_down_to_base_page(), PAddr::from(0x1000));
        assert_eq!(base.align_down_to_large_page(), PAddr::from(0x0));
        assert_eq!(base.align_up_to_base_page(), PAddr::from(0x1000));
        assert_eq!(base.align_up_to_large_page(), PAddr::from(0x400000));
        assert!(base.is_base_page_aligned());
        assert!(!base.is_large_page_aligned());
        assert!(base.is_aligned(0x1u32));
        assert!(base.is_aligned(0x2u32));
        assert!(!base.is_aligned(0x3u32));
        assert!(base.is_aligned(0x4u32));

        let base = PAddr::from(0x1001);
        assert_eq!(base.base_page_offset(), 0x1);
        assert_eq!(base.large_page_offset(), 0x1001);
        assert_eq!(base.align_down_to_base_page(), PAddr::from(0x1000));
        assert_eq!(base.align_down_to_large_page(), PAddr::from(0x0));
        assert_eq!(base.align_up_to_base_page(), PAddr::from(0x2000));
        assert_eq!(base.align_up_to_large_page(), PAddr::from(0x400000));
        assert!(!base.is_base_page_aligned());
        assert!(!base.is_large_page_aligned());
        assert!(base.is_aligned(0x1u32));
        assert!(!base.is_aligned(0x2u32));
        assert!(!base.is_aligned(0x3u32));
        assert!(!base.is_aligned(0x4u32));

        let base = PAddr::from(0x400000);
        assert_eq!(base.base_page_offset(), 0x0);
        assert_eq!(base.large_page_offset(), 0x0);
        assert_eq!(base.align_down_to_base_page(), PAddr::from(0x400000));
        assert_eq!(base.align_down_to_large_page(), PAddr::from(0x400000));
        assert_eq!(base.align_up_to_base_page(), PAddr::from(0x400000));
        assert_eq!(base.align_up_to_large_page(), PAddr::from(0x400000));
        assert!(base.is_base_page_aligned());
        assert!(base.is_large_page_aligned());
        assert!(base.is_aligned(0x1u32));
        assert!(base.is_aligned(0x2u32));
        assert!(!base.is_aligned(0x3u32));
        assert!(base.is_aligned(0x4u32));

        let base = PAddr::from(0x400002);
        assert_eq!(base.base_page_offset(), 0x2);
        assert_eq!(base.large_page_offset(), 0x2);
        assert_eq!(base.align_down_to_base_page(), PAddr::from(0x400000));
        assert_eq!(base.align_down_to_large_page(), PAddr::from(0x400000));
        assert_eq!(base.align_up_to_base_page(), PAddr::from(0x401000));
        assert_eq!(base.align_up_to_large_page(), PAddr::from(0x800000));
        assert!(!base.is_base_page_aligned());
        assert!(!base.is_large_page_aligned());
        assert!(base.is_aligned(0x1u32));
        assert!(base.is_aligned(0x2u32));
        assert!(!base.is_aligned(0x3u32));
        assert!(!base.is_aligned(0x4u32));
    }

    #[test]
    fn ioaddr_align() {
        let base = IOAddr::from(0x1000);
        assert_eq!(base.base_page_offset(), 0x0);
        assert_eq!(base.large_page_offset(), 0x1000);
        assert_eq!(base.align_down_to_base_page(), IOAddr::from(0x1000));
        assert_eq!(base.align_down_to_large_page(), IOAddr::from(0x0));
        assert_eq!(base.align_up_to_base_page(), IOAddr::from(0x1000));
        assert_eq!(base.align_up_to_large_page(), IOAddr::from(0x400000));
        assert!(base.is_base_page_aligned());
        assert!(!base.is_large_page_aligned());
        assert!(base.is_aligned(0x1u32));
        assert!(base.is_aligned(0x2u32));
        assert!(!base.is_aligned(0x3u32));
        assert!(base.is_aligned(0x4u32));

        let base = IOAddr::from(0x1001);
        assert_eq!(base.base_page_offset(), 0x1);
        assert_eq!(base.large_page_offset(), 0x1001);
        assert_eq!(base.align_down_to_base_page(), IOAddr::from(0x1000));
        assert_eq!(base.align_down_to_large_page(), IOAddr::from(0x0));
        assert_eq!(base.align_up_to_base_page(), IOAddr::from(0x2000));
        assert_eq!(base.align_up_to_large_page(), IOAddr::from(0x400000));
        assert!(!base.is_base_page_aligned());
        assert!(!base.is_large_page_aligned());
        assert!(base.is_aligned(0x1u32));
        assert!(!base.is_aligned(0x2u32));
        assert!(!base.is_aligned(0x3u32));
        assert!(!base.is_aligned(0x4u32));

        let base = IOAddr::from(0x400000);
        assert_eq!(base.base_page_offset(), 0x0);
        assert_eq!(base.large_page_offset(), 0x0);
        assert_eq!(base.align_down_to_base_page(), IOAddr::from(0x400000));
        assert_eq!(base.align_down_to_large_page(), IOAddr::from(0x400000));
        assert_eq!(base.align_up_to_base_page(), IOAddr::from(0x400000));
        assert_eq!(base.align_up_to_large_page(), IOAddr::from(0x400000));
        assert!(base.is_base_page_aligned());
        assert!(base.is_large_page_aligned());
        assert!(base.is_aligned(0x1u32));
        assert!(base.is_aligned(0x2u32));
        assert!(!base.is_aligned(0x3u32));
        assert!(base.is_aligned(0x4u32));

        let base = IOAddr::from(0x400002);
        assert_eq!(base.base_page_offset(), 0x2);
        assert_eq!(base.large_page_offset(), 0x2);
        assert_eq!(base.align_down_to_base_page(), IOAddr::from(0x400000));
        assert_eq!(base.align_down_to_large_page(), IOAddr::from(0x400000));
        assert_eq!(base.align_up_to_base_page(), IOAddr::from(0x401000));
        assert_eq!(base.align_up_to_large_page(), IOAddr::from(0x800000));
        assert!(!base.is_base_page_aligned());
        assert!(!base.is_large_page_aligned());
        assert!(base.is_aligned(0x1u32));
        assert!(base.is_aligned(0x2u32));
        assert!(!base.is_aligned(0x3u32));
        assert!(!base.is_aligned(0x4u32));
    }

    #[test]
    fn vaddr_align() {
        let base = VAddr::from(0x1000);
        assert_eq!(base.base_page_offset(), 0x0);
        assert_eq!(base.large_page_offset(), 0x1000);
        assert_eq!(base.align_down_to_base_page(), VAddr::from(0x1000));
        assert_eq!(base.align_down_to_large_page(), VAddr::from(0x0));
        assert_eq!(base.align_up_to_base_page(), VAddr::from(0x1000));
        assert_eq!(base.align_up_to_large_page(), VAddr::from(0x400000));
        assert!(base.is_base_page_aligned());
        assert!(!base.is_large_page_aligned());
        assert!(base.is_aligned(0x1u32));
        assert!(base.is_aligned(0x2u32));
        assert!(!base.is_aligned(0x3u32));
        assert!(base.is_aligned(0x4u32));

        let base = VAddr::from(0x1001);
        assert_eq!(base.base_page_offset(), 0x1);
        assert_eq!(base.large_page_offset(), 0x1001);
        assert_eq!(base.align_down_to_base_page(), VAddr::from(0x1000));
        assert_eq!(base.align_down_to_large_page(), VAddr::from(0x0));
        assert_eq!(base.align_up_to_base_page(), VAddr::from(0x2000));
        assert_eq!(base.align_up_to_large_page(), VAddr::from(0x400000));
        assert!(!base.is_base_page_aligned());
        assert!(!base.is_large_page_aligned());
        assert!(base.is_aligned(0x1u32));
        assert!(!base.is_aligned(0x2u32));
        assert!(!base.is_aligned(0x3u32));
        assert!(!base.is_aligned(0x4u32));

        let base = VAddr::from(0x400000);
        assert_eq!(base.base_page_offset(), 0x0);
        assert_eq!(base.large_page_offset(), 0x0);
        assert_eq!(base.align_down_to_base_page(), VAddr::from(0x400000));
        assert_eq!(base.align_down_to_large_page(), VAddr::from(0x400000));
        assert_eq!(base.align_up_to_base_page(), VAddr::from(0x400000));
        assert_eq!(base.align_up_to_large_page(), VAddr::from(0x400000));
        assert!(base.is_base_page_aligned());
        assert!(base.is_large_page_aligned());
        assert!(base.is_aligned(0x1u32));
        assert!(base.is_aligned(0x2u32));
        assert!(!base.is_aligned(0x3u32));
        assert!(base.is_aligned(0x4u32));

        let base = VAddr::from(0x400002);
        assert_eq!(base.base_page_offset(), 0x2);
        assert_eq!(base.large_page_offset(), 0x2);
        assert_eq!(base.align_down_to_base_page(), VAddr::from(0x400000));
        assert_eq!(base.align_down_to_large_page(), VAddr::from(0x400000));
        assert_eq!(base.align_up_to_base_page(), VAddr::from(0x401000));
        assert_eq!(base.align_up_to_large_page(), VAddr::from(0x800000));
        assert!(!base.is_base_page_aligned());
        assert!(!base.is_large_page_aligned());
        assert!(base.is_aligned(0x1u32));
        assert!(base.is_aligned(0x2u32));
        assert!(!base.is_aligned(0x3u32));
        assert!(!base.is_aligned(0x4u32));
    }
}
