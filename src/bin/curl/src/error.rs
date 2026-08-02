use std::fmt;
use std::io;

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
    pub const LOCAL_READ: u8 = 26;
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

    pub(crate) fn from_io(error: io::Error, default_code: u8, context: &str) -> Self {
        let code = match error.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Self::TIMEOUT,
            _ => error
                .get_ref()
                .and_then(|source| source.downcast_ref::<rustls::Error>())
                .map_or(default_code, |error| match error {
                    rustls::Error::InvalidCertificate(_)
                    | rustls::Error::NoCertificatesPresented
                    | rustls::Error::UnsupportedNameType => Self::CERTIFICATE,
                    _ => Self::TLS_CONNECT,
                }),
        };
        Self::new(code, format!("{context}: {error}"))
    }
}

impl fmt::Display for CurlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CurlError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_timeouts_certificate_failures_and_ordinary_io() {
        let timeout = CurlError::from_io(
            io::Error::from(io::ErrorKind::TimedOut),
            CurlError::RECEIVE,
            "read",
        );
        assert_eq!(timeout.code(), CurlError::TIMEOUT);

        let certificate = CurlError::from_io(
            io::Error::new(
                io::ErrorKind::InvalidData,
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
            ),
            CurlError::TLS_CONNECT,
            "handshake",
        );
        assert_eq!(certificate.code(), CurlError::CERTIFICATE);

        let ordinary = CurlError::from_io(
            io::Error::from(io::ErrorKind::BrokenPipe),
            CurlError::LOCAL_WRITE,
            "write",
        );
        assert_eq!(ordinary.code(), CurlError::LOCAL_WRITE);
    }
}
