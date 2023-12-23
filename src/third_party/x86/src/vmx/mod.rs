//! Data structures and definitions used by Virtual Machine Extensions.

pub mod vmcs;

/// A specialized [`Result`](core::result::Result) type for VMX operations.
///
/// This type closely replicates VMX instruction conventions described in
/// Intel SDM, Volume 3C, Section 30.2.
pub type Result<T> = core::result::Result<T, VmFail>;

/// Possible outcomes of VMfail pseudo-function used to convey VMX operation errors.
///
/// Definitions of all these pseudo-functions can be found in Intel SDM, Volume 3C, Section 30.2.
#[derive(Debug)]
pub enum VmFail {
    /// VMCS pointer is valid, but some other error was encountered. Read
    /// VM-instruction error field of VMCS for more details.
    VmFailValid,
    /// VMCS pointer is not valid.
    VmFailInvalid,
}
