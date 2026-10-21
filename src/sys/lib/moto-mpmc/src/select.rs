//! Operation tokens and the selection state shared by the channel flavors
//! and the blocking context.

use crate::flavors;

/// Temporary data that gets initialized during a blocking operation and is consumed by
/// `read` or `write`.
///
/// Each field contains data associated with a specific channel flavor.
#[derive(Debug, Default)]
pub struct Token {
    pub(crate) array: flavors::array::ArrayToken,
}

/// Identifier associated with an operation by a specific thread on a specific channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operation(usize);

impl Operation {
    /// Creates an operation identifier from a mutable reference.
    ///
    /// This function essentially just turns the address of the reference into a number. The
    /// reference should point to a variable that is specific to the thread and the operation,
    /// and is alive for the entire duration of the blocking operation.
    #[inline]
    pub fn hook<T>(r: &mut T) -> Self {
        let val = r as *mut T as usize;
        // Make sure that the pointer address doesn't equal the numerical representation of
        // `Selected::{Waiting, Aborted, Disconnected}`.
        assert!(val > 2);
        Self(val)
    }
}

/// Current state of a blocking operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selected {
    /// Still waiting for an operation.
    Waiting,

    /// The attempt to block the current thread has been aborted.
    Aborted,

    /// An operation became ready because a channel is disconnected.
    Disconnected,

    /// An operation became ready because a message can be sent or received.
    Operation(Operation),
}

impl From<usize> for Selected {
    #[inline]
    fn from(val: usize) -> Self {
        match val {
            0 => Self::Waiting,
            1 => Self::Aborted,
            2 => Self::Disconnected,
            oper => Self::Operation(Operation(oper)),
        }
    }
}

impl From<Selected> for usize {
    #[inline]
    fn from(val: Selected) -> Self {
        match val {
            Selected::Waiting => 0,
            Selected::Aborted => 1,
            Selected::Disconnected => 2,
            Selected::Operation(Operation(val)) => val,
        }
    }
}
