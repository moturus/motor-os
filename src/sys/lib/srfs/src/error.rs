use srfs_core::FsError;

pub fn to_ioerror(err: FsError) -> std::io::Error {
    use std::io::Error;
    use std::io::ErrorKind;

    match err {
        FsError::AlreadyExists => Error::from(ErrorKind::AlreadyExists),
        FsError::FsFull => Error::from(ErrorKind::FilesystemQuotaExceeded),
        FsError::InvalidArgument => Error::from(ErrorKind::InvalidInput),
        FsError::IoError => Error::from(ErrorKind::BrokenPipe),
        FsError::NotFound => Error::from(ErrorKind::NotFound),
        FsError::TooLarge => Error::from(ErrorKind::FileTooLarge),
        FsError::UnsupportedVersion => Error::from(ErrorKind::InvalidData),
        FsError::Utf8Error => Error::from(ErrorKind::InvalidInput),
        FsError::ValidationFailed => Error::from(ErrorKind::InvalidData),
    }
}
