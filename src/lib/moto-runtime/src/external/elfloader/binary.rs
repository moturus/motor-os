use super::{
    DynamicFlags1, DynamicInfo, ElfLoader, ElfLoaderErr, LoadableHeaders, RelocationEntry,
    RelocationType,
};
use core::fmt;

use crate::external::xmas_elf;

use xmas_elf::dynamic::Tag;
use xmas_elf::program::ProgramHeader::{self, Ph32, Ph64};
use xmas_elf::program::{ProgramIter, SegmentData, Type};
use xmas_elf::sections::SectionData;
pub use xmas_elf::symbol_table::Entry;
use xmas_elf::ElfFile;
use xmas_elf::*;

/// Abstract representation of a loadable ELF binary.
pub struct ElfBinary<'s> {
    /// The ELF file in question.
    pub file: ElfFile<'s>,
    /// Parsed information from the .dynamic section (if the binary has it).
    pub dynamic: Option<DynamicInfo>,
}

impl<'s> fmt::Debug for ElfBinary<'s> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ElfBinary{{ [")?;
        for p in self.program_headers() {
            write!(f, " pheader = {}", p)?;
        }
        write!(f, "] }}")
    }
}

impl<'s> ElfBinary<'s> {
    /// Create a new ElfBinary.
    pub fn new(region: &'s [u8]) -> Result<ElfBinary<'s>, ElfLoaderErr> {
        let file = ElfFile::new(region)?;

        // Parse relevant parts out of the the .dynamic section
        let mut dynamic = None;
        for p in file.program_iter() {
            let typ = match p {
                Ph64(header) => header.get_type()?,
                Ph32(header) => header.get_type()?,
            };

            if typ == Type::Dynamic {
                dynamic = ElfBinary::parse_dynamic(&file, &p)?;
                break;
            }
        }

        Ok(ElfBinary { file, dynamic })
    }

    /// Returns true if the binary is compiled as position independent code or false otherwise.
    ///
    /// For the binary to be PIE it needs to have a .dynamic section with PIE set in the flags1
    /// field.
    pub fn is_pie(&self) -> bool {
        self.dynamic.as_ref().map_or(false, |d: &DynamicInfo| {
            d.flags1.contains(DynamicFlags1::PIE)
        })
    }

    /// Returns the dynamic loader if present.
    ///
    /// readelf -x .interp <binary>
    ///
    /// For a statically compiled binary this will return None
    pub fn interpreter(&'s self) -> Option<&'s str> {
        let section = self.file.find_section_by_name(".interp");
        section.and_then(|interp_section| {
            let data = interp_section.get_data(&self.file).ok()?;
            let cstr = match data {
                SectionData::Undefined(val) => val,
                _ => return None,
            };

            // Validate there is room for a null terminator
            if cstr.len() < 2 {
                return None;
            }

            // Ensure it is a valid utf8 string
            core::str::from_utf8(&cstr[..cstr.len() - 1]).ok()
        })
    }

    /// Returns the target architecture
    pub fn get_arch(&self) -> header::Machine {
        self.file.header.pt2.machine().as_machine()
    }

    /// Return the entry point of the ELF file.
    ///
    /// Note this may be zero in case of position independent executables.
    pub fn entry_point(&self) -> u64 {
        self.file.header.pt2.entry_point()
    }

    /// Create a slice of the program headers.
    pub fn program_headers(&self) -> ProgramIter {
        self.file.program_iter()
    }

    /// Get the name of the sectione
    pub fn symbol_name(&self, symbol: &'s dyn Entry) -> &'s str {
        symbol.get_name(&self.file).unwrap_or("unknown")
    }

    /// Enumerate all the symbols in the file
    pub fn for_each_symbol<F: FnMut(&'s dyn Entry)>(
        &self,
        mut func: F,
    ) -> Result<(), ElfLoaderErr> {
        let symbol_section = self
            .file
            .find_section_by_name(".symtab")
            .ok_or(ElfLoaderErr::SymbolTableNotFound)?;
        let symbol_table = symbol_section.get_data(&self.file)?;
        match symbol_table {
            SectionData::SymbolTable32(entries) => {
                for entry in entries {
                    func(entry);
                }
                Ok(())
            }
            SectionData::SymbolTable64(entries) => {
                for entry in entries {
                    func(entry);
                }
                Ok(())
            }
            _ => Err(ElfLoaderErr::SymbolTableNotFound),
        }
    }

    /// Can we load this binary on our platform?
    fn is_loadable(&self) -> Result<(), ElfLoaderErr> {
        let header = self.file.header;
        let typ = header.pt2.type_().as_type();

        if header.pt1.version() != header::Version::Current {
            Err(ElfLoaderErr::UnsupportedElfVersion)
        } else if header.pt1.data() != header::Data::LittleEndian {
            Err(ElfLoaderErr::UnsupportedEndianness)
        } else if !(header.pt1.os_abi() == header::OsAbi::SystemV
            || header.pt1.os_abi() == header::OsAbi::Linux)
        {
            Err(ElfLoaderErr::UnsupportedAbi)
        } else if !(typ == header::Type::Executable || typ == header::Type::SharedObject) {
            Err(ElfLoaderErr::UnsupportedElfType)
        } else {
            Ok(())
        }
    }

    /// Process the relocation entries for the ELF file.
    ///
    /// Issues call to `loader.relocate` and passes the relocation entry.
    fn maybe_relocate(&self, loader: &mut dyn ElfLoader) -> Result<(), ElfLoaderErr> {
        // Relocation types are architecture specific
        let arch = self.get_arch();

        // It's easier to just locate the section by name, either:
        // - .rela.dyn
        // - .rel.dyn
        let relocation_section = self
            .file
            .find_section_by_name(".rela.dyn")
            .or_else(|| self.file.find_section_by_name(".rel.dyn"));

        // Helper macro to call loader.relocate() on all entries
        macro_rules! iter_entries_and_relocate {
            ($rela_entries:expr, $create_addend:ident) => {
                for entry in $rela_entries {
                    loader.relocate(RelocationEntry {
                        rtype: RelocationType::from(arch, entry.get_type() as u32)?,
                        offset: entry.get_offset() as u64,
                        index: entry.get_symbol_table_index(),
                        addend: $create_addend!(entry),
                    })?;
                }
            };
        }

        // Construct from Rel<T> entries. Does not contain an addend.
        macro_rules! rel_entry {
            ($entry:ident) => {
                None
            };
        }

        // Construct from Rela<T> entries. Contains an addend.
        macro_rules! rela_entry {
            ($entry:ident) => {
                Some($entry.get_addend() as u64)
            };
        }

        // If either section exists apply the relocations
        relocation_section.map_or(Ok(()), |rela_section_dyn| {
            let data = rela_section_dyn.get_data(&self.file)?;
            match data {
                SectionData::Rel32(rel_entries) => {
                    iter_entries_and_relocate!(rel_entries, rel_entry);
                }
                SectionData::Rela32(rela_entries) => {
                    iter_entries_and_relocate!(rela_entries, rela_entry);
                }
                SectionData::Rel64(rel_entries) => {
                    iter_entries_and_relocate!(rel_entries, rel_entry);
                }
                SectionData::Rela64(rela_entries) => {
                    iter_entries_and_relocate!(rela_entries, rela_entry);
                }
                _ => return Err(ElfLoaderErr::UnsupportedSectionData),
            }
            Ok(())
        })
    }

    /// Processes a dynamic header section.
    ///
    /// This section contains mostly entry points to other section headers (like relocation).
    /// At the moment this just does sanity checking for relocation later.
    ///
    /// A human readable version of the dynamic section is best obtained with `readelf -d <binary>`.
    fn parse_dynamic<'a>(
        file: &ElfFile,
        dynamic_header: &'a ProgramHeader<'a>,
    ) -> Result<Option<DynamicInfo>, ElfLoaderErr> {
        // Walk through the dynamic program header and find the rela and sym_tab section offsets:
        let segment = dynamic_header.get_data(file)?;

        // Init result
        let mut info = DynamicInfo {
            flags1: Default::default(),
            rela: 0,
            rela_size: 0,
        };

        // Each entry/section is parsed for the same information currently
        macro_rules! parse_entry_tags {
            ($info:ident, $entry:ident, $tag:ident) => {
                match $tag {
                    // Trace required libs
                    Tag::Needed => {}

                    // Rel<T>
                    Tag::Rel => $info.rela = $entry.get_ptr()?.into(),
                    Tag::RelSize => $info.rela_size = $entry.get_val()?.into(),

                    // Rela<T>
                    Tag::Rela => $info.rela = $entry.get_ptr()?.into(),
                    Tag::RelaSize => $info.rela_size = $entry.get_val()?.into(),
                    Tag::Flags1 => {
                        $info.flags1 =
                            unsafe { DynamicFlags1::from_bits_unchecked($entry.get_val()? as _) };
                    }
                    _ => {}
                }
            };
        }

        // Helper macro to iterate all entries
        macro_rules! iter_entries_and_parse {
            ($info:ident, $dyn_entries:expr) => {
                for dyn_entry in $dyn_entries {
                    let tag = dyn_entry.get_tag()?;
                    parse_entry_tags!($info, dyn_entry, tag);
                }
            };
        }

        match segment {
            SegmentData::Dynamic32(dyn_entries) => {
                iter_entries_and_parse!(info, dyn_entries);
            }
            SegmentData::Dynamic64(dyn_entries) => {
                iter_entries_and_parse!(info, dyn_entries);
            }
            _ => {
                return Err(ElfLoaderErr::UnsupportedSectionData);
            }
        };

        Ok(Some(info))
    }

    /// Processing the program headers and issue commands to loader.
    ///
    /// Will tell loader to create space in the address space / region where the
    /// header is supposed to go, then copy it there, and finally relocate it.
    pub fn load(&self, loader: &mut dyn ElfLoader) -> Result<(), ElfLoaderErr> {
        self.is_loadable()?;

        loader.allocate(self.iter_loadable_headers())?;

        // Load all headers
        for header in self.file.program_iter() {
            let raw = match header {
                Ph32(inner) => inner.raw_data(&self.file),
                Ph64(inner) => inner.raw_data(&self.file),
            };
            let typ = header.get_type()?;
            match typ {
                Type::Load => {
                    loader.load(header.flags(), header.virtual_addr(), raw)?;
                }
                Type::Tls => {
                    loader.tls(
                        header.virtual_addr(),
                        header.file_size(),
                        header.mem_size(),
                        header.align(),
                    )?;
                }
                _ => {} // skip for now
            }
        }

        // Relocate headers
        self.maybe_relocate(loader)?;

        // Process .data.rel.ro
        for header in self.file.program_iter() {
            if header.get_type()? == Type::GnuRelro {
                loader.make_readonly(header.virtual_addr(), header.mem_size() as usize)?
            }
        }

        Ok(())
    }

    fn iter_loadable_headers(&self) -> LoadableHeaders {
        // Trying to determine loadeable headers
        fn select_load(pheader: &ProgramHeader) -> bool {
            match pheader {
                Ph32(header) => header
                    .get_type()
                    .map(|typ| typ == Type::Load)
                    .unwrap_or(false),
                Ph64(header) => header
                    .get_type()
                    .map(|typ| typ == Type::Load)
                    .unwrap_or(false),
            }
        }

        // Create an iterator (well filter really) that has all loadeable
        // headers and pass it to the loader
        // TODO: This is pretty ugly, maybe we can do something with impl Trait?
        // https://stackoverflow.com/questions/27535289/what-is-the-correct-way-to-return-an-iterator-or-any-other-trait
        self.file.program_iter().filter(select_load)
    }
}
