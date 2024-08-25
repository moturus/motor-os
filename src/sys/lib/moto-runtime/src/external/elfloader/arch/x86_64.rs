// Should be in xmas-elf see: https://github.com/nrc/xmas-elf/issues/54
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum RelocationTypes {
    /// No relocation.
    R_AMD64_NONE,
    /// Add 64 bit symbol value.
    R_AMD64_64,
    /// PC-relative 32 bit signed sym value.
    R_AMD64_PC32,
    /// PC-relative 32 bit GOT offset.
    R_AMD64_GOT32,
    /// PC-relative 32 bit PLT offset.
    R_AMD64_PLT32,
    /// Copy data from shared object.
    R_AMD64_COPY,
    /// Set GOT entry to data address.
    R_AMD64_GLOB_DAT,
    /// Set GOT entry to code address.
    R_AMD64_JMP_SLOT,
    /// Add load address of shared object.
    R_AMD64_RELATIVE,
    /// Add 32 bit signed pcrel offset to GOT.
    R_AMD64_GOTPCREL,
    /// Add 32 bit zero extended symbol value
    R_AMD64_32,
    /// Add 32 bit sign extended symbol value
    R_AMD64_32S,
    /// Add 16 bit zero extended symbol value
    R_AMD64_16,
    /// Add 16 bit signed extended pc relative symbol value
    R_AMD64_PC16,
    /// Add 8 bit zero extended symbol value
    R_AMD64_8,
    /// Add 8 bit signed extended pc relative symbol value
    R_AMD64_PC8,
    /// ID of module containing symbol
    R_AMD64_DTPMOD64,
    /// Offset in TLS block
    R_AMD64_DTPOFF64,
    /// Offset in static TLS block
    R_AMD64_TPOFF64,
    /// PC relative offset to GD GOT entry
    R_AMD64_TLSGD,
    /// PC relative offset to LD GOT entry
    R_AMD64_TLSLD,
    /// Offset in TLS block
    R_AMD64_DTPOFF32,
    /// PC relative offset to IE GOT entry
    R_AMD64_GOTTPOFF,
    /// Offset in static TLS block
    R_AMD64_TPOFF32,
    /// Unknown
    Unknown(u32),
}

impl RelocationTypes {
    // Construct a new x86_64::RelocationTypes
    pub fn from(typ: u32) -> RelocationTypes {
        use RelocationTypes::*;
        match typ {
            0 => R_AMD64_NONE,
            1 => R_AMD64_64,
            2 => R_AMD64_PC32,
            3 => R_AMD64_GOT32,
            4 => R_AMD64_PLT32,
            5 => R_AMD64_COPY,
            6 => R_AMD64_GLOB_DAT,
            7 => R_AMD64_JMP_SLOT,
            8 => R_AMD64_RELATIVE,
            9 => R_AMD64_GOTPCREL,
            10 => R_AMD64_32,
            11 => R_AMD64_32S,
            12 => R_AMD64_16,
            13 => R_AMD64_PC16,
            14 => R_AMD64_8,
            15 => R_AMD64_PC8,
            16 => R_AMD64_DTPMOD64,
            17 => R_AMD64_DTPOFF64,
            18 => R_AMD64_TPOFF64,
            19 => R_AMD64_TLSGD,
            20 => R_AMD64_TLSLD,
            21 => R_AMD64_DTPOFF32,
            22 => R_AMD64_GOTTPOFF,
            23 => R_AMD64_TPOFF32,
            x => Unknown(x),
        }
    }
}
