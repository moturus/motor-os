pub mod net;

#[repr(C, align(8))]
pub struct RequestHeader {
    pub command: u16,
    pub version: u16,
    pub flags: u32,
}
