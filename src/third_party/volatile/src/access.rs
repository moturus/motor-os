/// Helper trait that is implemented by [`ReadWrite`] and [`ReadOnly`].
pub trait Readable {}

/// Helper trait that is implemented by [`ReadWrite`] and [`WriteOnly`].
pub trait Writable {}

/// Zero-sized marker type for allowing both read and write access.
#[derive(Debug, Copy, Clone)]
pub struct ReadWrite;
impl Readable for ReadWrite {}
impl Writable for ReadWrite {}

/// Zero-sized marker type for allowing only read access.
#[derive(Debug, Copy, Clone)]
pub struct ReadOnly;

impl Readable for ReadOnly {}

/// Zero-sized marker type for allowing only write access.
#[derive(Debug, Copy, Clone)]
pub struct WriteOnly;
impl Writable for WriteOnly {}
