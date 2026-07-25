use std::fmt;

pub type CurlResult<T> = Result<T, CurlError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurlError {
    code: u8,
    message: String,
}

impl CurlError {
    pub const UNSUPPORTED_PROTOCOL: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const MALFORMED_URL: u8 = 3;
    pub const RESOLVE: u8 = 6;
    pub const CONNECT: u8 = 7;
    pub const LOCAL_WRITE: u8 = 23;
    pub const TIMEOUT: u8 = 28;
    pub const TLS_CONNECT: u8 = 35;
    pub const EMPTY_REPLY: u8 = 52;
    pub const SEND: u8 = 55;
    pub const RECEIVE: u8 = 56;
    pub const CERTIFICATE: u8 = 60;
    pub const CA_CERTIFICATE: u8 = 77;

    pub fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(Self::USAGE, message)
    }

    pub fn code(&self) -> u8 {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CurlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CurlError {}
