extern crate zero;

pub mod dynamic;
pub mod header;
pub mod program;
pub mod sections;
pub mod symbol_table;

use header::Header;
use program::{ProgramHeader, ProgramIter};
use sections::{SectionHeader, SectionIter};
use zero::read_str;

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

    pub fn program_iter(&self) -> ProgramIter<'_, '_> {
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
