// Some code here is copied from https://github.com/vincenthouyi/elf_rs,
// which is licensed under the MIT license.

use core::ptr::read_unaligned;

use moto_sys::ErrorCode;

// Usually loading an elf file means copying bytes from a file
// into an address space that is not the current address space,
// so LoaderHelper trait helps with these "memory-like" operations.
pub trait LoaderHelper {
    fn load_into_memory(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), ErrorCode>;

    fn allocate_target(
        &mut self,
        offset: usize,
        size: usize,
        writable: bool,
    ) -> Result<(), ErrorCode>;

    fn load_into_target(
        &mut self,
        source_offset: usize,
        target_offset: usize,
        size: usize,
    ) -> Result<(), ErrorCode>;
}

pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ElfClass {
    Elf32, // 1
    Elf64, // 2
    Unknown(u8),
}

impl From<u8> for ElfClass {
    fn from(n: u8) -> Self {
        match n {
            1 => ElfClass::Elf32,
            2 => ElfClass::Elf64,
            n => ElfClass::Unknown(n),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ElfEndian {
    LittleEndian, // 1,
    BigEndian,    // 2,
    Unknown(u8),
}

impl From<u8> for ElfEndian {
    fn from(n: u8) -> Self {
        match n {
            1 => ElfEndian::LittleEndian,
            2 => ElfEndian::BigEndian,
            n => ElfEndian::Unknown(n),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ElfAbi {
    SystemV,       // 0x00,
    HPUX,          // 0x01,
    NetBSD,        // 0x02,
    Linux,         // 0x03,
    Hurd,          // 0x04,
    Solaris,       // 0x06,
    AIX,           // 0x07,
    IRIX,          // 0x08,
    FreeBSD,       // 0x09,
    Tru64,         // 0x0A,
    NovellModesto, // 0x0B,
    OpenBSD,       // 0x0C,
    OpenVMS,       // 0x0D,
    NonStopKernel, // 0x0E,
    AROS,          // 0x0F,
    FenixOS,       // 0x10,
    CloudABI,      // 0x11,
    Unknown(u8),
}

impl From<u8> for ElfAbi {
    fn from(n: u8) -> Self {
        match n {
            0x00 => ElfAbi::SystemV,
            0x01 => ElfAbi::HPUX,
            0x02 => ElfAbi::NetBSD,
            0x03 => ElfAbi::Linux,
            0x04 => ElfAbi::Hurd,
            0x06 => ElfAbi::Solaris,
            0x07 => ElfAbi::AIX,
            0x08 => ElfAbi::IRIX,
            0x09 => ElfAbi::FreeBSD,
            0x0A => ElfAbi::Tru64,
            0x0B => ElfAbi::NovellModesto,
            0x0C => ElfAbi::OpenBSD,
            0x0D => ElfAbi::OpenVMS,
            0x0E => ElfAbi::NonStopKernel,
            0x0F => ElfAbi::AROS,
            0x10 => ElfAbi::FenixOS,
            0x11 => ElfAbi::CloudABI,
            n => ElfAbi::Unknown(n),
        }
    }
}

const ET_LOOS: u16 = 0xfe00;
const ET_HIOS: u16 = 0xfeff;
const ET_LOPROC: u16 = 0xff00;
const ET_HIPROC: u16 = 0xffff;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ElfType {
    ET_NONE, // 0x00,
    ET_REL,  // 0x01,
    ET_EXEC, // 0x02,
    ET_DYN,  // 0x03,
    ET_CORE, // 0x04,
    OsSpecific(u16),
    ProcessorSpecific(u16),
    Unknown(u16),
}

impl From<u16> for ElfType {
    fn from(n: u16) -> Self {
        match n {
            0x00 => ElfType::ET_NONE,
            0x01 => ElfType::ET_REL,
            0x02 => ElfType::ET_EXEC,
            0x03 => ElfType::ET_DYN,
            0x04 => ElfType::ET_CORE,
            x @ ET_LOOS..=ET_HIOS => ElfType::OsSpecific(x),
            x @ ET_LOPROC..=ET_HIPROC => ElfType::ProcessorSpecific(x),
            n => ElfType::Unknown(n),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ElfMachine {
    Unknown, // 0x00
    SPARC,   // 0x02
    x86,     // 0x03
    MIPS,    // 0x08
    PowerPC, // 0x14
    S390,    // 0x16
    ARM,     // 0x28
    SuperH,  // 0x2A
    IA_64,   // 0x32
    x86_64,  // 0x3E
    AArch64, // 0xB7
    RISC_V,  // 0xF3
    MachineUnknown(u16),
}

impl From<u16> for ElfMachine {
    fn from(n: u16) -> Self {
        match n {
            0x00 => ElfMachine::Unknown,
            0x02 => ElfMachine::SPARC,
            0x03 => ElfMachine::x86,
            0x08 => ElfMachine::MIPS,
            0x14 => ElfMachine::PowerPC,
            0x16 => ElfMachine::S390,
            0x28 => ElfMachine::ARM,
            0x2A => ElfMachine::SuperH,
            0x32 => ElfMachine::IA_64,
            0x3E => ElfMachine::x86_64,
            0xB7 => ElfMachine::AArch64,
            0xF3 => ElfMachine::RISC_V,
            n => ElfMachine::MachineUnknown(n),
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct ElfHeader64 {
    magic: [u8; 4],
    class: u8,
    endianness: u8,
    header_version: u8,
    abi: u8,
    abi_version: u8,
    unused: [u8; 7],
    elftype: u16,
    machine: u16,
    elf_version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

const ELF_HEADER_SIZE: usize = 64;

const _: () = assert!(core::mem::size_of::<ElfHeader64>() == ELF_HEADER_SIZE);

impl ElfHeader64 {
    pub fn class(&self) -> ElfClass {
        self.class.into()
    }

    pub fn endianness(&self) -> ElfEndian {
        self.endianness.into()
    }

    pub fn header_version(&self) -> u8 {
        self.header_version
    }

    pub fn abi(&self) -> ElfAbi {
        self.abi.into()
    }

    pub fn abi_version(&self) -> u8 {
        self.abi_version
    }

    pub fn elftype(&self) -> ElfType {
        unsafe { read_unaligned(&self.elftype).into() }
    }

    pub fn machine(&self) -> ElfMachine {
        unsafe { read_unaligned(&self.machine).into() }
    }

    pub fn elf_version(&self) -> u32 {
        unsafe { read_unaligned(&self.elf_version) }
    }

    pub fn entry_point(&self) -> u64 {
        unsafe { read_unaligned(&self.entry).into() }
    }

    pub fn program_header_offset(&self) -> u64 {
        unsafe { read_unaligned(&self.phoff).into() }
    }

    pub fn section_header_offset(&self) -> u64 {
        unsafe { read_unaligned(&self.shoff).into() }
    }

    pub fn flags(&self) -> u32 {
        unsafe { read_unaligned(&self.flags) }
    }

    pub fn elf_header_size(&self) -> u16 {
        unsafe { read_unaligned(&self.ehsize) }
    }

    pub fn program_header_entry_size(&self) -> u16 {
        unsafe { read_unaligned(&self.phentsize) }
    }

    pub fn program_header_entry_num(&self) -> u16 {
        unsafe { read_unaligned(&self.phnum) }
    }

    pub fn section_header_entry_size(&self) -> u16 {
        unsafe { read_unaligned(&self.shentsize) }
    }

    pub fn section_header_entry_num(&self) -> u16 {
        unsafe { read_unaligned(&self.shnum) }
    }

    pub fn shstr_index(&self) -> u16 {
        unsafe { read_unaligned(&self.shstrndx) }
    }
}
