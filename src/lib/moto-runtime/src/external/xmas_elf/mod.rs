#![allow(unused)]
/*
#![no_std]
#![warn(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations
)]
#![warn(
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![warn(variant_size_differences)]
#![allow(elided_lifetimes_in_paths)]
*/

macro_rules! check {
    ($e:expr) => {
        if !$e {
            return Err("");
        }
    };
    ($e:expr, $msg: expr) => {
        if !$e {
            return Err($msg);
        }
    };
}

pub mod dynamic;
pub mod hash;
pub mod header;
pub mod program;
pub mod sections;
pub mod symbol_table;

use crate::external::zero;
use header::Header;
use program::{ProgramHeader, ProgramIter};
use sections::{SectionHeader, SectionIter};
use zero::{read, read_str};

pub type P32 = u32;
pub type P64 = u64;

#[derive(Debug)]
pub struct ElfFile<'a> {
    pub input: &'a [u8],
    pub header: Header<'a>,
}

impl<'a> ElfFile<'a> {
    pub fn new(input: &'a [u8]) -> Result<ElfFile<'a>, &'static str> {
        header::parse_header(input).map(|header| ElfFile { input, header })
    }

    pub fn section_header(&self, index: u16) -> Result<SectionHeader<'a>, &'static str> {
        sections::parse_section_header(self.input, self.header, index)
    }

    pub fn section_iter(&self) -> impl Iterator<Item = SectionHeader<'a>> + '_ {
        SectionIter {
            file: self,
            next_index: 0,
        }
    }

    pub fn program_header(&self, index: u16) -> Result<ProgramHeader<'a>, &'static str> {
        program::parse_program_header(self.input, self.header, index)
    }

    pub fn program_iter(&self) -> ProgramIter {
        // impl Iterator<Item = ProgramHeader<'_>> {
        ProgramIter {
            file: self,
            next_index: 0,
        }
    }

    pub fn get_shstr(&self, index: u32) -> Result<&'a str, &'static str> {
        self.get_shstr_table()
            .map(|shstr_table| read_str(&shstr_table[(index as usize)..]))
    }

    pub fn get_string(&self, index: u32) -> Result<&'a str, &'static str> {
        let header = self
            .find_section_by_name(".strtab")
            .ok_or("no .strtab section")?;
        if header.get_type()? != sections::ShType::StrTab {
            return Err("expected .strtab to be StrTab");
        }
        Ok(read_str(&header.raw_data(self)[(index as usize)..]))
    }

    pub fn get_dyn_string(&self, index: u32) -> Result<&'a str, &'static str> {
        let header = self
            .find_section_by_name(".dynstr")
            .ok_or("no .dynstr section")?;
        Ok(read_str(&header.raw_data(self)[(index as usize)..]))
    }

    // This is really, stupidly slow. Not sure how to fix that, perhaps keeping
    // a HashTable mapping names to section header indices?
    pub fn find_section_by_name(&self, name: &str) -> Option<SectionHeader<'a>> {
        for sect in self.section_iter() {
            if let Ok(sect_name) = sect.get_name(self) {
                if sect_name == name {
                    return Some(sect);
                }
            }
        }

        None
    }

    fn get_shstr_table(&self) -> Result<&'a [u8], &'static str> {
        // TODO cache this?
        let header = self.section_header(self.header.pt2.sh_str_index());
        header.map(|h| &self.input[(h.offset() as usize)..])
    }
}

/// A trait for things that are common ELF conventions but not part of the ELF
/// specification.
pub trait Extensions<'a> {
    /// Parse and return the value of the .note.gnu.build-id section, if it
    /// exists and is well-formed.
    fn get_gnu_buildid(&self) -> Option<&'a [u8]>;

    /// Parse and return the value of the .gnu_debuglink section, if it
    /// exists and is well-formed.
    fn get_gnu_debuglink(&self) -> Option<(&'a str, u32)>;

    /// Parse and return the value of the .gnu_debugaltlink section, if it
    /// exists and is well-formed.
    fn get_gnu_debugaltlink(&self) -> Option<(&'a str, &'a [u8])>;
}

impl<'a> Extensions<'a> for ElfFile<'a> {
    fn get_gnu_buildid(&self) -> Option<&'a [u8]> {
        self.find_section_by_name(".note.gnu.build-id")
            .and_then(|header| header.get_data(self).ok())
            .and_then(|data| match data {
                // Handle Note32 if it's ever implemented!
                sections::SectionData::Note64(header, data) => Some((header, data)),
                _ => None,
            })
            .and_then(|(header, data)| {
                // Check for NT_GNU_BUILD_ID
                if header.type_() != 0x3 {
                    return None;
                }

                if header.name(data) != "GNU" {
                    return None;
                }

                Some(header.desc(data))
            })
    }

    fn get_gnu_debuglink(&self) -> Option<(&'a str, u32)> {
        self.find_section_by_name(".gnu_debuglink")
            .and_then(|header| {
                let data = header.raw_data(self);
                let file = read_str(data);
                // Round up to the nearest multiple of 4.
                let checksum_pos = ((file.len() + 4) / 4) * 4;
                if checksum_pos + 4 <= data.len() {
                    let checksum: u32 = *read(&data[checksum_pos..]);
                    Some((file, checksum))
                } else {
                    None
                }
            })
    }

    fn get_gnu_debugaltlink(&self) -> Option<(&'a str, &'a [u8])> {
        self.find_section_by_name(".gnu_debugaltlink")
            .map(|header| header.raw_data(self))
            .and_then(|data| {
                let file = read_str(data);
                // The rest of the data is a SHA1 checksum of the debuginfo, no alignment
                let checksum_pos = file.len() + 1;
                if checksum_pos <= data.len() {
                    Some((file, &data[checksum_pos..]))
                } else {
                    None
                }
            })
    }
}
