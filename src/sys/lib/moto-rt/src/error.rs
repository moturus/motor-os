//! Common Motor OS error codes.
pub type ErrorCode = u16;

pub const E_OK: u16 = 0;
pub const E_UNSPECIFIED: u16 = 1;
pub const E_UNKNOWN: u16 = 2;
pub const E_NOT_READY: u16 = 3;
pub const E_NOT_IMPLEMENTED: u16 = 5;
pub const E_VERSION_TOO_HIGH: u16 = 6;
pub const E_VERSION_TOO_LOW: u16 = 7;
pub const E_INVALID_ARGUMENT: u16 = 8;
pub const E_OUT_OF_MEMORY: u16 = 9;
pub const E_NOT_ALLOWED: u16 = 10; // PERMISSION ERROR.
pub const E_NOT_FOUND: u16 = 11;
pub const E_INTERNAL_ERROR: u16 = 12;
pub const E_TIMED_OUT: u16 = 13;
pub const E_ALREADY_IN_USE: u16 = 14;
pub const E_UNEXPECTED_EOF: u16 = 15;
pub const E_INVALID_FILENAME: u16 = 16;
pub const E_NOT_A_DIRECTORY: u16 = 17;
pub const E_BAD_HANDLE: u16 = 18;
pub const E_FILE_TOO_LARGE: u16 = 19;
pub const E_BUFFER_FULL: u16 = 20;

pub const E_MAX: u16 = u16::MAX;
