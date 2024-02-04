// Should be in xmas-elf see: https://github.com/nrc/xmas-elf/issues/54
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum RelocationTypes {
    /// No relocation.
    R_386_NONE,
    /// Add 32 bit dword symbol value.
    R_386_32,
    /// PC-relative 32 bit signed sym value.
    R_386_PC32,
    /// 32 bit GOT offset.
    R_386_GOT32,
    /// 32 bit PLT offset.
    R_386_PLT32,
    /// Copy data from shared object.
    R_386_COPY,
    /// Set GOT entry to data address.
    R_386_GLOB_DAT,
    /// Set PLT entry to code address.
    R_386_JMP_SLOT,
    /// Add load address of shared object.
    R_386_RELATIVE,
    /// 32-bit GOT offset
    R_386_GOTOFF,
    /// 32-bit PC relative offset to GOT
    R_386_GOTPC,
    /// Direct 32 bit PLT address
    R_386_32PLT,
    /// Direct 16 bit zero extended
    R_386_16,
    /// 16 bit sign extended pc relative
    R_386_PC16,
    /// Direct 8 bit sign extended
    R_386_8,
    /// 8 bit sign extended pc relative
    R_386_PC8,
    /// 32-bit symbol size
    R_386_SIZE32,
    /// Unknown
    Unknown(u32),
}

impl RelocationTypes {
    pub fn from(typ: u32) -> RelocationTypes {
        use RelocationTypes::*;
        match typ {
            0 => R_386_NONE,
            1 => R_386_PC32,
            2 => R_386_32,
            3 => R_386_GOT32,
            4 => R_386_PLT32,
            5 => R_386_COPY,
            6 => R_386_GLOB_DAT,
            7 => R_386_JMP_SLOT,
            8 => R_386_RELATIVE,
            9 => R_386_GOTOFF,
            10 => R_386_GOTPC,
            11 => R_386_32PLT,
            20 => R_386_16,
            21 => R_386_PC16,
            22 => R_386_8,
            23 => R_386_PC8,
            38 => R_386_SIZE32,
            x => Unknown(x),
        }
    }
}
