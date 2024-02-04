use core::fmt;
use core::mem;
use core::slice;

use crate::external::zero;

use super::dynamic::Dynamic;
use super::hash::HashTable;
use super::header::{Class, Header};
use super::symbol_table;
use super::{ElfFile, P32, P64};
use zero::{read, read_array, read_str, read_strs_to_null, Pod, StrReaderIterator};

pub fn parse_section_header<'a>(
    input: &'a [u8],
    header: Header<'a>,
    index: u16,
) -> Result<SectionHeader<'a>, &'static str> {
    // Trying to get index 0 (SHN_UNDEF) is also probably an error, but it is a legitimate section.
    assert!(
        index < SHN_LORESERVE,
        "Attempt to get section for a reserved index"
    );

    let start =
        (index as u64 * header.pt2.sh_entry_size() as u64 + header.pt2.sh_offset() as u64) as usize;
    let end = start + header.pt2.sh_entry_size() as usize;

    Ok(match header.pt1.class() {
        Class::ThirtyTwo => {
            let header: &'a SectionHeader_<P32> = read(&input[start..end]);
            SectionHeader::Sh32(header)
        }
        Class::SixtyFour => {
            let header: &'a SectionHeader_<P64> = read(&input[start..end]);
            SectionHeader::Sh64(header)
        }
        Class::None | Class::Other(_) => unreachable!(),
    })
}

#[derive(Debug, Clone)]
pub struct SectionIter<'b, 'a> {
    pub file: &'b ElfFile<'a>,
    pub next_index: u16,
}

impl<'b, 'a> Iterator for SectionIter<'b, 'a> {
    type Item = SectionHeader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let count = self.file.header.pt2.sh_count();
        if self.next_index >= count {
            return None;
        }

        let result = self.file.section_header(self.next_index);
        self.next_index += 1;
        result.ok()
    }
}

// Distinguished section indices.
pub const SHN_UNDEF: u16 = 0;
pub const SHN_LORESERVE: u16 = 0xff00;
pub const SHN_LOPROC: u16 = 0xff00;
pub const SHN_HIPROC: u16 = 0xff1f;
pub const SHN_LOOS: u16 = 0xff20;
pub const SHN_HIOS: u16 = 0xff3f;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;
pub const SHN_XINDEX: u16 = 0xffff;
pub const SHN_HIRESERVE: u16 = 0xffff;

#[derive(Clone, Copy, Debug)]
pub enum SectionHeader<'a> {
    Sh32(&'a SectionHeader_<P32>),
    Sh64(&'a SectionHeader_<P64>),
}

macro_rules! getter {
    ($name: ident, $typ: ident) => {
        pub fn $name(&self) -> $typ {
            match *self {
                SectionHeader::Sh32(h) => h.$name as $typ,
                SectionHeader::Sh64(h) => h.$name as $typ,
            }
        }
    };
}

impl<'a> SectionHeader<'a> {
    // Note that this function is O(n) in the length of the name.
    pub fn get_name(&self, elf_file: &ElfFile<'a>) -> Result<&'a str, &'static str> {
        self.get_type().and_then(|typ| match typ {
            ShType::Null => Err("Attempt to get name of null section"),
            _ => elf_file.get_shstr(self.name()),
        })
    }

    pub fn get_type(&self) -> Result<ShType, &'static str> {
        self.type_().as_sh_type()
    }

    pub fn get_data(&self, elf_file: &ElfFile<'a>) -> Result<SectionData<'a>, &'static str> {
        macro_rules! array_data {
            ($data32: ident, $data64: ident) => {{
                let data = self.raw_data(elf_file);
                match elf_file.header.pt1.class() {
                    Class::ThirtyTwo => SectionData::$data32(read_array(data)),
                    Class::SixtyFour => SectionData::$data64(read_array(data)),
                    Class::None | Class::Other(_) => unreachable!(),
                }
            }};
        }

        self.get_type().and_then(|typ| {
            Ok(match typ {
                ShType::Null | ShType::NoBits => SectionData::Empty,
                ShType::ProgBits
                | ShType::ShLib
                | ShType::OsSpecific(_)
                | ShType::ProcessorSpecific(_)
                | ShType::User(_) => SectionData::Undefined(self.raw_data(elf_file)),
                ShType::SymTab => array_data!(SymbolTable32, SymbolTable64),
                ShType::DynSym => array_data!(DynSymbolTable32, DynSymbolTable64),
                ShType::StrTab => SectionData::StrArray(self.raw_data(elf_file)),
                ShType::InitArray | ShType::FiniArray | ShType::PreInitArray => {
                    array_data!(FnArray32, FnArray64)
                }
                ShType::Rela => array_data!(Rela32, Rela64),
                ShType::Rel => array_data!(Rel32, Rel64),
                ShType::Dynamic => array_data!(Dynamic32, Dynamic64),
                ShType::Group => {
                    let data = self.raw_data(elf_file);
                    unsafe {
                        let flags: &'a u32 = mem::transmute(&data[0]);
                        let indicies: &'a [u32] = read_array(&data[4..]);
                        SectionData::Group { flags, indicies }
                    }
                }
                ShType::SymTabShIndex => {
                    SectionData::SymTabShIndex(read_array(self.raw_data(elf_file)))
                }
                ShType::Note => {
                    let data = self.raw_data(elf_file);
                    match elf_file.header.pt1.class() {
                        Class::ThirtyTwo => return Err("32-bit binaries not implemented"),
                        Class::SixtyFour => {
                            let header: &'a NoteHeader = read(&data[0..12]);
                            let index = &data[12..];
                            SectionData::Note64(header, index)
                        }
                        Class::None | Class::Other(_) => return Err("Unknown ELF class"),
                    }
                }
                ShType::Hash => {
                    let data = self.raw_data(elf_file);
                    SectionData::HashTable(read(&data[0..12]))
                }
            })
        })
    }

    pub fn raw_data(&self, elf_file: &ElfFile<'a>) -> &'a [u8] {
        assert_ne!(self.get_type().unwrap(), ShType::Null);
        &elf_file.input[self.offset() as usize..(self.offset() + self.size()) as usize]
    }

    #[cfg(feature = "compression")]
    pub fn decompressed_data(&self, elf_file: &ElfFile<'a>) -> Result<Cow<'a, [u8]>, &'static str> {
        let raw = self.raw_data(elf_file);
        Ok(if (self.flags() & SHF_COMPRESSED) == 0 {
            Cow::Borrowed(raw)
        } else {
            let (compression_type, size, compressed_data) = match elf_file.header.pt1.class() {
                Class::ThirtyTwo => {
                    if raw.len() < 12 {
                        return Err("Unexpected EOF in compressed section");
                    }
                    let header: &'a CompressionHeader32 = read(&raw[..12]);
                    (
                        header.type_.as_compression_type(),
                        header.size as usize,
                        &raw[12..],
                    )
                }
                Class::SixtyFour => {
                    if raw.len() < 24 {
                        return Err("Unexpected EOF in compressed section");
                    }
                    let header: &'a CompressionHeader64 = read(&raw[..24]);
                    (
                        header.type_.as_compression_type(),
                        header.size as usize,
                        &raw[24..],
                    )
                }
                Class::None | Class::Other(_) => unreachable!(),
            };

            if compression_type != Ok(CompressionType::Zlib) {
                return Err("Unknown compression type");
            }

            let mut decompressed = Vec::with_capacity(size);
            let mut decompress = Decompress::new(true);
            if let Err(_) = decompress.decompress_vec(
                compressed_data,
                &mut decompressed,
                FlushDecompress::Finish,
            ) {
                return Err("Decompression error");
            }
            Cow::Owned(decompressed)
        })
    }

    getter!(flags, u64);
    getter!(name, u32);
    getter!(address, u64);
    getter!(offset, u64);
    getter!(size, u64);
    getter!(type_, ShType_);
    getter!(link, u32);
    getter!(info, u32);
    getter!(entry_size, u32);
    getter!(align, u64);
}

impl<'a> fmt::Display for SectionHeader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        macro_rules! sh_display {
            ($sh: ident) => {{
                writeln!(f, "Section header:")?;
                writeln!(f, "    name:             {:?}", $sh.name)?;
                writeln!(f, "    type:             {:?}", self.get_type())?;
                writeln!(f, "    flags:            {:?}", $sh.flags)?;
                writeln!(f, "    address:          {:?}", $sh.address)?;
                writeln!(f, "    offset:           {:?}", $sh.offset)?;
                writeln!(f, "    size:             {:?}", $sh.size)?;
                writeln!(f, "    link:             {:?}", $sh.link)?;
                writeln!(f, "    align:            {:?}", $sh.align)?;
                writeln!(f, "    entry size:       {:?}", $sh.entry_size)?;
                Ok(())
            }};
        }

        match *self {
            SectionHeader::Sh32(sh) => sh_display!(sh),
            SectionHeader::Sh64(sh) => sh_display!(sh),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct SectionHeader_<P> {
    name: u32,
    type_: ShType_,
    flags: P,
    address: P,
    offset: P,
    size: P,
    link: u32,
    info: u32,
    align: P,
    entry_size: P,
}

unsafe impl<P> Pod for SectionHeader_<P> {}

#[derive(Copy, Clone)]
pub struct ShType_(u32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShType {
    Null,
    ProgBits,
    SymTab,
    StrTab,
    Rela,
    Hash,
    Dynamic,
    Note,
    NoBits,
    Rel,
    ShLib,
    DynSym,
    InitArray,
    FiniArray,
    PreInitArray,
    Group,
    SymTabShIndex,
    OsSpecific(u32),
    ProcessorSpecific(u32),
    User(u32),
}

impl ShType_ {
    fn as_sh_type(self) -> Result<ShType, &'static str> {
        match self.0 {
            0 => Ok(ShType::Null),
            1 => Ok(ShType::ProgBits),
            2 => Ok(ShType::SymTab),
            3 => Ok(ShType::StrTab),
            4 => Ok(ShType::Rela),
            5 => Ok(ShType::Hash),
            6 => Ok(ShType::Dynamic),
            7 => Ok(ShType::Note),
            8 => Ok(ShType::NoBits),
            9 => Ok(ShType::Rel),
            10 => Ok(ShType::ShLib),
            11 => Ok(ShType::DynSym),
            // sic.
            14 => Ok(ShType::InitArray),
            15 => Ok(ShType::FiniArray),
            16 => Ok(ShType::PreInitArray),
            17 => Ok(ShType::Group),
            18 => Ok(ShType::SymTabShIndex),
            st if (SHT_LOOS..=SHT_HIOS).contains(&st) => Ok(ShType::OsSpecific(st)),
            st if (SHT_LOPROC..=SHT_HIPROC).contains(&st) => Ok(ShType::ProcessorSpecific(st)),
            st if (SHT_LOUSER..=SHT_HIUSER).contains(&st) => Ok(ShType::User(st)),
            _ => Err("Invalid sh type"),
        }
    }
}

impl fmt::Debug for ShType_ {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_sh_type().fmt(f)
    }
}

#[derive(Debug)]
pub enum SectionData<'a> {
    Empty,
    Undefined(&'a [u8]),
    Group { flags: &'a u32, indicies: &'a [u32] },
    StrArray(&'a [u8]),
    FnArray32(&'a [u32]),
    FnArray64(&'a [u64]),
    SymbolTable32(&'a [symbol_table::Entry32]),
    SymbolTable64(&'a [symbol_table::Entry64]),
    DynSymbolTable32(&'a [symbol_table::DynEntry32]),
    DynSymbolTable64(&'a [symbol_table::DynEntry64]),
    SymTabShIndex(&'a [u32]),
    // Note32 uses 4-byte words, which I'm not sure how to manage.
    // The pointer is to the start of the name field in the note.
    Note64(&'a NoteHeader, &'a [u8]),
    Rela32(&'a [Rela<P32>]),
    Rela64(&'a [Rela<P64>]),
    Rel32(&'a [Rel<P32>]),
    Rel64(&'a [Rel<P64>]),
    Dynamic32(&'a [Dynamic<P32>]),
    Dynamic64(&'a [Dynamic<P64>]),
    HashTable(&'a HashTable),
}

#[derive(Debug)]
pub struct SectionStrings<'a> {
    inner: StrReaderIterator<'a>,
}

impl<'a> Iterator for SectionStrings<'a> {
    type Item = &'a str;

    #[inline]
    fn next(&mut self) -> Option<&'a str> {
        self.inner.next()
    }
}

impl<'a> SectionData<'a> {
    pub fn strings(&self) -> Result<SectionStrings<'a>, ()> {
        if let SectionData::StrArray(data) = *self {
            Ok(SectionStrings {
                inner: read_strs_to_null(data),
            })
        } else {
            Err(())
        }
    }
}

// Distinguished ShType values.
pub const SHT_LOOS: u32 = 0x60000000;
pub const SHT_HIOS: u32 = 0x6fffffff;
pub const SHT_LOPROC: u32 = 0x70000000;
pub const SHT_HIPROC: u32 = 0x7fffffff;
pub const SHT_LOUSER: u32 = 0x80000000;
pub const SHT_HIUSER: u32 = 0xffffffff;

// Flags (SectionHeader::flags)
pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_MERGE: u64 = 0x10;
pub const SHF_STRINGS: u64 = 0x20;
pub const SHF_INFO_LINK: u64 = 0x40;
pub const SHF_LINK_ORDER: u64 = 0x80;
pub const SHF_OS_NONCONFORMING: u64 = 0x100;
pub const SHF_GROUP: u64 = 0x200;
pub const SHF_TLS: u64 = 0x400;
pub const SHF_COMPRESSED: u64 = 0x800;
pub const SHF_MASKOS: u64 = 0x0ff00000;
pub const SHF_MASKPROC: u64 = 0xf0000000;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct CompressionHeader64 {
    type_: CompressionType_,
    _reserved: u32,
    size: u64,
    align: u64,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct CompressionHeader32 {
    type_: CompressionType_,
    size: u32,
    align: u32,
}

unsafe impl Pod for CompressionHeader64 {}
unsafe impl Pod for CompressionHeader32 {}

#[derive(Copy, Clone)]
pub struct CompressionType_(u32);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CompressionType {
    Zlib,
    OsSpecific(u32),
    ProcessorSpecific(u32),
}

impl CompressionType_ {
    fn as_compression_type(&self) -> Result<CompressionType, &'static str> {
        match self.0 {
            1 => Ok(CompressionType::Zlib),
            ct if (COMPRESS_LOOS..=COMPRESS_HIOS).contains(&ct) => {
                Ok(CompressionType::OsSpecific(ct))
            }
            ct if (COMPRESS_LOPROC..=COMPRESS_HIPROC).contains(&ct) => {
                Ok(CompressionType::ProcessorSpecific(ct))
            }
            _ => Err("Invalid compression type"),
        }
    }
}

impl fmt::Debug for CompressionType_ {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_compression_type().fmt(f)
    }
}

// Distinguished CompressionType values.
pub const COMPRESS_LOOS: u32 = 0x60000000;
pub const COMPRESS_HIOS: u32 = 0x6fffffff;
pub const COMPRESS_LOPROC: u32 = 0x70000000;
pub const COMPRESS_HIPROC: u32 = 0x7fffffff;

// Group flags
pub const GRP_COMDAT: u64 = 0x1;
pub const GRP_MASKOS: u64 = 0x0ff00000;
pub const GRP_MASKPROC: u64 = 0xf0000000;

#[derive(Debug)]
#[repr(C)]
pub struct Rela<P> {
    offset: P,
    info: P,
    addend: P,
}

#[derive(Debug)]
#[repr(C)]
pub struct Rel<P> {
    offset: P,
    info: P,
}

unsafe impl<P> Pod for Rela<P> {}
unsafe impl<P> Pod for Rel<P> {}

impl Rela<P32> {
    pub fn get_offset(&self) -> u32 {
        self.offset
    }
    pub fn get_addend(&self) -> u32 {
        self.addend
    }
    pub fn get_symbol_table_index(&self) -> u32 {
        self.info >> 8
    }
    pub fn get_type(&self) -> u8 {
        self.info as u8
    }
}
impl Rela<P64> {
    pub fn get_offset(&self) -> u64 {
        self.offset
    }
    pub fn get_addend(&self) -> u64 {
        self.addend
    }
    pub fn get_symbol_table_index(&self) -> u32 {
        (self.info >> 32) as u32
    }
    pub fn get_type(&self) -> u32 {
        (self.info & 0xffffffff) as u32
    }
}
impl Rel<P32> {
    pub fn get_offset(&self) -> u32 {
        self.offset
    }
    pub fn get_symbol_table_index(&self) -> u32 {
        self.info >> 8
    }
    pub fn get_type(&self) -> u8 {
        self.info as u8
    }
}
impl Rel<P64> {
    pub fn get_offset(&self) -> u64 {
        self.offset
    }
    pub fn get_symbol_table_index(&self) -> u32 {
        (self.info >> 32) as u32
    }
    pub fn get_type(&self) -> u32 {
        (self.info & 0xffffffff) as u32
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct NoteHeader {
    name_size: u32,
    desc_size: u32,
    type_: u32,
}

unsafe impl Pod for NoteHeader {}

impl NoteHeader {
    pub fn type_(&self) -> u32 {
        self.type_
    }

    pub fn name<'a>(&'a self, input: &'a [u8]) -> &'a str {
        let result = read_str(input);
        // - 1 is due to null terminator
        assert_eq!(result.len(), (self.name_size - 1) as usize);
        result
    }

    pub fn desc<'a>(&'a self, input: &'a [u8]) -> &'a [u8] {
        // Account for padding to the next u32.
        unsafe {
            let offset = (self.name_size + 3) & !0x3;
            let ptr = (&input[0] as *const u8).offset(offset as isize);
            slice::from_raw_parts(ptr, self.desc_size as usize)
        }
    }
}

pub fn sanity_check<'a>(
    header: SectionHeader<'a>,
    _file: &ElfFile<'a>,
) -> Result<(), &'static str> {
    if header.get_type()? == ShType::Null {
        return Ok(());
    }
    // TODO
    Ok(())
}
