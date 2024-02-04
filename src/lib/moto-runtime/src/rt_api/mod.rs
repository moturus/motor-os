pub mod fs;
pub mod net;
pub mod process;

pub const TEMP_DIR: &str = "/sys/tmp";

#[repr(C, align(8))]
pub struct RequestHeader {
    pub command: u16,
    pub version: u16,
    pub flags: u32,
}
