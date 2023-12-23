use crate::TagType;

/// This tag contains the command line string.
///
/// The string is a normal C-style UTF-8 zero-terminated string that can be
/// obtained via the `command_line` method.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)] // only repr(C) would add unwanted padding before first_section
pub struct CommandLineTag {
    typ: TagType,
    size: u32,
    string: u8,
}

impl CommandLineTag {
    /// Read the command line string that is being passed to the booting kernel.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// if let Some(tag) = boot_info.command_line_tag() {
    ///     let command_line = tag.command_line();
    ///     assert_eq!("/bootarg", command_line);
    /// }
    /// ```
    pub fn command_line(&self) -> &str {
        use core::{mem, slice, str};
        unsafe {
            let strlen = self.size as usize - mem::size_of::<CommandLineTag>();
            str::from_utf8_unchecked(slice::from_raw_parts((&self.string) as *const u8, strlen))
        }
    }
}
