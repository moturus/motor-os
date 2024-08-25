// Process capabilities.

// This is a system process (cannot be killed by userspace).
pub const CAP_SYS: u64 = 1 << 0;

// IO Manager. The IO manager has access to the serial console (COM1 port)
// and can do mmio.
pub const CAP_IO_MANAGER: u64 = 1 << 1;

// The process can spawn other processes.
pub const CAP_SPAWN: u64 = 1 << 2;

// The process can use SysMem::OP_DEBUG and SysCtl::OP_SET_LOG_LEVEL.
pub const CAP_LOG: u64 = 1 << 3;

// This ENV key can be used to specify caps for the
// process being created. The value must be formated in hex.
// Currently works with Rust's std::process::Command.
pub const MOTURUS_CAPS_ENV_KEY: &str = "MOTURUS_CAPS";
