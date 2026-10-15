//! A checked parser for the executables sys-io loads: ELF64 x86-64 static
//! (PIE) images linked at their run address. Every field is validated with
//! checked arithmetic; malformed input is an error, never a panic.

pub const PAGE: u64 = 4096;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_TLS: u32 = 7;

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

const MAX_PHDRS: u64 = 64;
/// Limits that keep a hostile header from requesting unbounded work. A huge
/// segment is not one: admission refuses its memory (`E_OUT_OF_MEMORY`),
/// as it did for the eager loader.
const MAX_DYNAMIC_BYTES: u64 = 64 * 1024;
pub const USER_LIMIT: u64 = 1 << 46;

pub const DT_NULL: u64 = 0;
pub const DT_RELA: u64 = 7;
pub const DT_RELASZ: u64 = 8;
pub const DT_RELAENT: u64 = 9;

pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const RELA_ENTRY_SIZE: u64 = 24;

#[derive(Debug)]
pub enum ElfError {
    Invalid,
    Unsupported,
}

impl From<ElfError> for std::io::Error {
    fn from(_: ElfError) -> Self {
        std::io::Error::from(std::io::ErrorKind::InvalidInput)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Segment {
    pub vaddr: u64,
    pub offset: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub writable: bool,
    pub executable: bool,
}

impl Segment {
    pub fn page_start(&self) -> u64 {
        self.vaddr & !(PAGE - 1)
    }

    /// Exclusive; computed from validated, non-overflowing fields.
    pub fn page_end(&self) -> u64 {
        (self.vaddr + self.memsz + PAGE - 1) & !(PAGE - 1)
    }

    pub fn num_pages(&self) -> u64 {
        (self.page_end() - self.page_start()) / PAGE
    }

    /// Whether file offsets and addresses agree page by page, which demand
    /// paging needs; the eager path copies bytes and does not.
    pub fn congruent(&self) -> bool {
        self.vaddr % PAGE == self.offset % PAGE
    }

    pub fn contains(&self, vaddr: u64, len: u64) -> bool {
        vaddr >= self.vaddr
            && vaddr
                .checked_add(len)
                .is_some_and(|end| end <= self.vaddr + self.memsz)
    }

    /// The file offset of `vaddr` if it lies in the segment's file bytes.
    pub fn file_offset(&self, vaddr: u64, len: u64) -> Option<u64> {
        (vaddr >= self.vaddr
            && vaddr
                .checked_add(len)
                .is_some_and(|end| end <= self.vaddr + self.filesz))
        .then(|| self.offset + (vaddr - self.vaddr))
    }
}

#[derive(Debug)]
pub struct Header {
    pub entry: u64,
    pub phoff: u64,
    pub phnum: u64,
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

pub fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// Parses the 64-byte file header.
pub fn parse_header(bytes: &[u8], file_size: u64) -> Result<Header, ElfError> {
    if bytes.len() < 64 || bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(ElfError::Invalid);
    }
    // ELFCLASS64, little-endian, current version.
    if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
        return Err(ElfError::Unsupported);
    }
    let e_type = u16_at(bytes, 16);
    let machine = u16_at(bytes, 18);
    if !(e_type == 2 || e_type == 3) || machine != 62 || u32_at(bytes, 20) != 1 {
        return Err(ElfError::Unsupported);
    }
    let header = Header {
        entry: u64_at(bytes, 24),
        phoff: u64_at(bytes, 32),
        phnum: u16_at(bytes, 56) as u64,
    };
    if u16_at(bytes, 54) != 56 || header.phnum == 0 || header.phnum > MAX_PHDRS {
        return Err(ElfError::Unsupported);
    }
    let table_end = header
        .phoff
        .checked_add(header.phnum * 56)
        .ok_or(ElfError::Invalid)?;
    if table_end > file_size {
        return Err(ElfError::Invalid);
    }
    Ok(header)
}

#[derive(Debug)]
pub struct Image {
    pub entry: u64,
    /// `PT_LOAD` segments with a nonzero size, in ascending page order.
    pub segments: Vec<Segment>,
    /// `PT_DYNAMIC`: (file offset, size).
    pub dynamic: Option<(u64, u64)>,
}

/// Parses the program header table (`table` holds `phnum` entries).
pub fn parse_program_headers(
    header: &Header,
    table: &[u8],
    file_size: u64,
) -> Result<Image, ElfError> {
    let mut segments: Vec<Segment> = Vec::new();
    let mut dynamic = None;
    for idx in 0..header.phnum as usize {
        let ph = &table[idx * 56..idx * 56 + 56];
        let p_type = u32_at(ph, 0);
        let flags = u32_at(ph, 4);
        let offset = u64_at(ph, 8);
        let vaddr = u64_at(ph, 16);
        let filesz = u64_at(ph, 32);
        let memsz = u64_at(ph, 40);
        match p_type {
            PT_INTERP | PT_TLS => return Err(ElfError::Unsupported),
            PT_DYNAMIC => {
                if filesz > MAX_DYNAMIC_BYTES
                    || offset.checked_add(filesz).is_none_or(|end| end > file_size)
                {
                    return Err(ElfError::Invalid);
                }
                dynamic = Some((offset, filesz));
            }
            PT_LOAD if memsz != 0 => {
                let segment = Segment {
                    vaddr,
                    offset,
                    filesz,
                    memsz,
                    writable: flags & PF_W != 0,
                    executable: flags & PF_X != 0,
                };
                if flags & PF_R == 0 || (segment.writable && segment.executable) {
                    return Err(ElfError::Unsupported);
                }
                if filesz > memsz
                    || offset.checked_add(filesz).is_none_or(|end| end > file_size)
                    || vaddr
                        .checked_add(memsz)
                        .is_none_or(|end| end > USER_LIMIT - PAGE)
                {
                    return Err(ElfError::Invalid);
                }
                // Page ranges must ascend without sharing a page in memory.
                if segments
                    .last()
                    .is_some_and(|prev| prev.page_end() > segment.page_start())
                {
                    return Err(ElfError::Unsupported);
                }
                segments.push(segment);
            }
            _ => {}
        }
    }
    if segments.is_empty()
        || !segments
            .iter()
            .any(|s| s.executable && s.contains(header.entry, 1))
    {
        return Err(ElfError::Invalid);
    }
    Ok(Image {
        entry: header.entry,
        segments,
        dynamic,
    })
}

/// The relocation table named by the dynamic section.
#[derive(Debug, Default, Clone)]
pub struct Relocations {
    /// File offset and size in bytes of the RELA table; size 0 for none.
    pub offset: u64,
    pub size: u64,
}

pub fn parse_dynamic(image: &Image, bytes: &[u8], file_size: u64) -> Result<Relocations, ElfError> {
    let (mut rela, mut relasz, mut relaent) = (None, 0, RELA_ENTRY_SIZE);
    for entry in bytes.as_chunks::<16>().0 {
        let (tag, val) = (u64_at(entry, 0), u64_at(entry, 8));
        match tag {
            DT_NULL => break,
            DT_RELA => rela = Some(val),
            DT_RELASZ => relasz = val,
            DT_RELAENT => relaent = val,
            _ => {}
        }
    }
    let Some(rela) = rela else {
        return Ok(Relocations::default());
    };
    if relaent != RELA_ENTRY_SIZE || relasz % RELA_ENTRY_SIZE != 0 {
        return Err(ElfError::Unsupported);
    }
    // The table must lie in one segment's file bytes.
    let offset = image
        .segments
        .iter()
        .find_map(|s| s.file_offset(rela, relasz))
        .ok_or(ElfError::Invalid)?;
    if offset.checked_add(relasz).is_none_or(|end| end > file_size) {
        return Err(ElfError::Invalid);
    }
    Ok(Relocations {
        offset,
        size: relasz,
    })
}

/// Decodes one RELA record: (destination, type, addend).
pub fn rela_at(bytes: &[u8]) -> (u64, u32, u64) {
    (u64_at(bytes, 0), u64_at(bytes, 8) as u32, u64_at(bytes, 16))
}
