use crate::tag_type::{Tag, TagIter, TagType};
use core::fmt::{Debug, Formatter};

/// This tag indicates to the kernel what boot module was loaded along with
/// the kernel image, and where it can be found.
#[derive(Clone, Copy)]
#[repr(C, packed)] // only repr(C) would add unwanted padding near name_byte.
pub struct ModuleTag {
    typ: TagType,
    size: u32,
    mod_start: u32,
    mod_end: u32,
    /// Begin of the command line string.
    cmdline_str: u8,
}

impl ModuleTag {
    // The multiboot specification defines the module str as valid utf-8 (zero terminated string),
    // therefore this function produces defined behavior
    /// Get the cmdline of the module. If the GRUB configuration contains
    /// `module2 /foobar/some_boot_module --test cmdline-option`, then this method
    /// will return `--test cmdline-option`.
    pub fn cmdline(&self) -> &str {
        use core::{mem, slice, str};
        let strlen = self.size as usize - mem::size_of::<ModuleTag>();
        unsafe {
            str::from_utf8_unchecked(slice::from_raw_parts(
                &self.cmdline_str as *const u8,
                strlen,
            ))
        }
    }

    /// Start address of the module.
    pub fn start_address(&self) -> u32 {
        self.mod_start
    }

    /// End address of the module
    pub fn end_address(&self) -> u32 {
        self.mod_end
    }

    /// The size of the module/the BLOB in memory.
    pub fn module_size(&self) -> u32 {
        self.mod_end - self.mod_start
    }
}

impl Debug for ModuleTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ModuleTag")
            .field("type", &{ self.typ })
            .field("size (tag)", &{ self.size })
            .field("size (module)", &self.module_size())
            .field("mod_start", &(self.mod_start as *const usize))
            .field("mod_end", &(self.mod_end as *const usize))
            .field("cmdline", &self.cmdline())
            .finish()
    }
}

pub fn module_iter(iter: TagIter) -> ModuleIter {
    ModuleIter { iter }
}

/// An iterator over all module tags.
#[derive(Clone)]
pub struct ModuleIter<'a> {
    iter: TagIter<'a>,
}

impl<'a> Iterator for ModuleIter<'a> {
    type Item = &'a ModuleTag;

    fn next(&mut self) -> Option<&'a ModuleTag> {
        self.iter
            .find(|x| x.typ == TagType::Module)
            .map(|tag| unsafe { &*(tag as *const Tag as *const ModuleTag) })
    }
}

impl<'a> Debug for ModuleIter<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut list = f.debug_list();
        self.clone().for_each(|tag| {
            list.entry(&tag);
        });
        list.finish()
    }
}
