use core::fmt;
use {P32, P64};
use zero::Pod;

#[derive(Debug)]
#[repr(C)]
pub struct Dynamic<P> where Tag_<P>: fmt::Debug {
    tag: Tag_<P>,
    un: P,
}

unsafe impl<P> Pod for Dynamic<P> where Tag_<P>: fmt::Debug {}

#[derive(Copy, Clone)]
pub struct Tag_<P>(P);

#[derive(Debug, PartialEq, Eq)]
pub enum Tag<P> {
    Null,
    Needed,
    PltRelSize,
    Pltgot,
    Hash,
    StrTab,
    SymTab,
    Rela,
    RelaSize,
    RelaEnt,
    StrSize,
    SymEnt,
    Init,
    Fini,
    SoName,
    RPath,
    Symbolic,
    Rel,
    RelSize,
    RelEnt,
    PltRel,
    Debug,
    TextRel,
    JmpRel,
    BindNow,
    InitArray,
    FiniArray,
    InitArraySize,
    FiniArraySize,
    RunPath,
    Flags,
    PreInitArray,
    PreInitArraySize,
    SymTabShIndex,
    Flags1,
    OsSpecific(P),
    ProcessorSpecific(P),
}

macro_rules! impls {
    ($p: ident) => {
        impl Dynamic<$p> {
            pub fn get_tag(&self) -> Result<Tag<$p>, &'static str> {
                self.tag.as_tag()
            }

            pub fn get_val(&self) -> Result<$p, &'static str> {
                match self.get_tag()? {
                    Tag::Needed | Tag::PltRelSize | Tag::RelaSize | Tag::RelaEnt | Tag::StrSize |
                    Tag::SymEnt | Tag::SoName | Tag::RPath | Tag::RelSize | Tag::RelEnt | Tag::PltRel |
                    Tag::InitArraySize | Tag::FiniArraySize | Tag::RunPath | Tag::Flags |
                    Tag::PreInitArraySize | Tag::Flags1 | Tag::OsSpecific(_) |
                    Tag::ProcessorSpecific(_) => Ok(self.un),
                    _ => Err("Invalid value"),
                }
            }

            pub fn get_ptr(&self) -> Result<$p, &'static str> {
                match self.get_tag()? {
                    Tag::Pltgot | Tag::Hash | Tag::StrTab | Tag::SymTab | Tag::Rela | Tag::Init | Tag::Fini |
                    Tag::Rel | Tag::Debug | Tag::JmpRel | Tag::InitArray | Tag::FiniArray |
                    Tag::PreInitArray | Tag::SymTabShIndex  | Tag::OsSpecific(_) | Tag::ProcessorSpecific(_)
                    => Ok(self.un),
                     _ => Err("Invalid ptr"),
                }
            }
        }

        impl Tag_<$p> {
            fn as_tag(self) -> Result<Tag<$p>, &'static str> {
                match self.0 {
                    0 => Ok(Tag::Null),
                    1 => Ok(Tag::Needed),
                    2 => Ok(Tag::PltRelSize),
                    3 => Ok(Tag::Pltgot),
                    4 => Ok(Tag::Hash),
                    5 => Ok(Tag::StrTab),
                    6 => Ok(Tag::SymTab),
                    7 => Ok(Tag::Rela),
                    8 => Ok(Tag::RelaSize),
                    9 => Ok(Tag::RelaEnt),
                    10 => Ok(Tag::StrSize),
                    11 => Ok(Tag::SymEnt),
                    12 => Ok(Tag::Init),
                    13 => Ok(Tag::Fini),
                    14 => Ok(Tag::SoName),
                    15 => Ok(Tag::RPath),
                    16 => Ok(Tag::Symbolic),
                    17 => Ok(Tag::Rel),
                    18 => Ok(Tag::RelSize),
                    19 => Ok(Tag::RelEnt),
                    20 => Ok(Tag::PltRel),
                    21 => Ok(Tag::Debug),
                    22 => Ok(Tag::TextRel),
                    23 => Ok(Tag::JmpRel),
                    24 => Ok(Tag::BindNow),
                    25 => Ok(Tag::InitArray),
                    26 => Ok(Tag::FiniArray),
                    27 => Ok(Tag::InitArraySize),
                    28 => Ok(Tag::FiniArraySize),
                    29 => Ok(Tag::RunPath),
                    30 => Ok(Tag::Flags),
                    32 => Ok(Tag::PreInitArray),
                    33 => Ok(Tag::PreInitArraySize),
                    34 => Ok(Tag::SymTabShIndex),
                    0x6ffffffb => Ok(Tag::Flags1),
                    t if (0x6000000D..0x70000000).contains(&t) => Ok(Tag::OsSpecific(t)),
                    t if (0x70000000..0x80000000).contains(&t) => Ok(Tag::ProcessorSpecific(t)),
                    _ => Err("Invalid tag value"),
                }
            }
        }

        impl fmt::Debug for Tag_<$p> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.as_tag().fmt(f)
            }
        }
    }
}

impls!(P32);
impls!(P64);

/* Flag values used in the DT_FLAGS_1 .dynamic entry.  */
pub const FLAG_1_NOW: u64 = 0x00000001;
pub const FLAG_1_GLOBAL: u64 = 0x00000002;
pub const FLAG_1_GROUP: u64 = 0x00000004;
pub const FLAG_1_NODELETE: u64 = 0x00000008;
pub const FLAG_1_LOADFLTR: u64 = 0x00000010;
pub const FLAG_1_INITFIRST: u64 = 0x00000020;
pub const FLAG_1_NOOPEN: u64 = 0x00000040;
pub const FLAG_1_ORIGIN: u64 = 0x00000080;
pub const FLAG_1_DIRECT: u64 = 0x00000100;
pub const FLAG_1_TRANS: u64 = 0x00000200;
pub const FLAG_1_INTERPOSE: u64 = 0x00000400;
pub const FLAG_1_NODEFLIB: u64 = 0x00000800;
pub const FLAG_1_NODUMP: u64 = 0x00001000;
pub const FLAG_1_CONFALT: u64 = 0x00002000;
pub const FLAG_1_ENDFILTEE: u64 = 0x00004000;
pub const FLAG_1_DISPRELDNE: u64 = 0x00008000;
pub const FLAG_1_DISPRELPND: u64 = 0x00010000;
pub const FLAG_1_NODIRECT: u64 = 0x00020000;
pub const FLAG_1_IGNMULDEF: u64 = 0x00040000;
pub const FLAG_1_NOKSYMS: u64 = 0x00080000;
pub const FLAG_1_NOHDR: u64 = 0x00100000;
pub const FLAG_1_EDITED: u64 = 0x00200000;
pub const FLAG_1_NORELOC: u64 = 0x00400000;
pub const FLAG_1_SYMINTPOSE: u64 = 0x00800000;
pub const FLAG_1_GLOBAUDIT: u64 = 0x01000000;
pub const FLAG_1_SINGLETON: u64 = 0x02000000;
pub const FLAG_1_STUB: u64 = 0x04000000;
pub const FLAG_1_PIE: u64 = 0x08000000;
