use core::fmt::{self, Display, Formatter};
#[cfg(feature = "kernel")]
use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProcessId {
    System,
    Kernel,
    SysIO,
    Userspace(u64),
}

#[cfg(feature = "kernel")]
const FIRST_USERSPACE_PID: u64 = 3;

impl ProcessId {
    /// generate a new userspace process ID
    #[cfg(feature = "kernel")]
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(FIRST_USERSPACE_PID);
        Self::Userspace(NEXT_ID.fetch_add(1, Relaxed))
    }

    /// whether the process ID is reversed by the OS
    pub fn is_system(&self) -> bool {
        match self {
            Self::System => true,
            Self::Kernel => true,
            Self::SysIO => true,
            Self::Userspace(_) => false,
        }
    }
}

/// provides .into()
impl From<u64> for ProcessId {
    fn from(pid: u64) -> Self {
        match pid {
            0 => Self::System,
            1 => Self::Kernel,
            2 => Self::SysIO,
            userspace_pid => Self::Userspace(userspace_pid),
        }
    }
}

/// produce u64 from a reference
impl From<&ProcessId> for u64 {
    fn from(id: &ProcessId) -> u64 {
        match id {
            ProcessId::Kernel => 0,
            ProcessId::System => 1,
            ProcessId::SysIO => 2,
            ProcessId::Userspace(pid) => *pid,
        }
    }
}

/// extracts u64 from the owned value
impl From<ProcessId> for u64 {
    fn from(id: ProcessId) -> u64 {
        match id {
            ProcessId::Kernel => 0,
            ProcessId::System => 1,
            ProcessId::SysIO => 2,
            ProcessId::Userspace(pid) => pid,
        }
    }
}

impl Display for ProcessId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::System => write!(f, "(idle)"),
            Self::Kernel => write!(f, "kernel"),
            Self::SysIO => write!(f, "sys-io"),
            Self::Userspace(pid) => write!(f, "{pid}"),
        }
    }
}

impl PartialEq<u64> for ProcessId {
    fn eq(&self, other: &u64) -> bool {
        other == &self.into()
    }
}
