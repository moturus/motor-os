use crate::TagType;

/// This tag contains the name of the bootloader that is booting the kernel.
///
/// The name is a normal C-style UTF-8 zero-terminated string that can be
/// obtained via the `name` method.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)] // only repr(C) would add unwanted padding before first_section
pub struct BootLoaderNameTag {
    typ: TagType,
    size: u32,
    string: u8,
}

impl BootLoaderNameTag {
    /// Read the name of the bootloader that is booting the kernel.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// if let Some(tag) = boot_info.boot_loader_name_tag() {
    ///     let name = tag.name();
    ///     assert_eq!("GRUB 2.02~beta3-5", name);
    /// }
    /// ```
    pub fn name(&self) -> &str {
        use core::{mem, slice, str};
        unsafe {
            let strlen = self.size as usize - mem::size_of::<BootLoaderNameTag>();
            str::from_utf8_unchecked(slice::from_raw_parts((&self.string) as *const u8, strlen))
        }
    }
}
