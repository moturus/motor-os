// Process capabilities.

// Cap Manager (init) can grant any capability to any process, including
// delegating CAP_MANAGER.
pub const CAP_CAP_MANAGER: u64 = u64::MAX;

// Memory manager (userspace).
pub const CAP_MEM_MANAGER: u64 = 2;

// CPU manager (userspace).
pub const CAP_CPU_MANAGER: u64 = 4;

// IO Manager. The IO manager has access to the serial console (COM1 port).
pub const CAP_IO_MANAGER: u64 = 8;

// The process can spawn other processes.
pub const CAP_SPAWN: u64 = 0x10;

// The process can created shared memory/handles.
pub const CAP_SHARE: u64 = 0x20;

// The process can use SysMem::OP_DEBUG and SysCtl::OP_SET_LOG_LEVEL.
pub const CAP_LOG: u64 = 0x40;

// This ENV key can be used to specify caps for the
// process being created. The value must be formated in hex.
// Currently works with Rust's std::process::Command.
pub const MOTURUS_CAPS_ENV_KEY: &str = "MOTURUS_CAPS";
