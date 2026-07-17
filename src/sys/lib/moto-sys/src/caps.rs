//! Process capabilities.

/// This is a system process (cannot be killed by userspace).
pub const CAP_SYS: u64 = 1 << 0;

/// IO Manager. The IO manager has access to the serial console (COM1 port)
/// and can do mmio.
pub const CAP_IO_MANAGER: u64 = 1 << 1;

/// The process can spawn other processes.
///
/// Note: at the moment this is not used (every process can spawn).
///       But there are vague plans to change this.
pub const CAP_SPAWN: u64 = 1 << 2;

/// The process can use SysRay::OP_LOG.
pub const CAP_LOG: u64 = 1 << 3;

/// The process can shut down the system.
pub const CAP_SHUTDOWN: u64 = 1 << 4;

/// The process may spawn *detached* children: a child whose owner is the kernel,
/// not the spawner, and which therefore outlives the spawner's exit (and its
/// reaping). This is Motor's equivalent of Unix's reparent-to-init, and the only
/// way a userspace daemon can survive the process that launched it.
///
/// It is deliberately **not** granted by default (see the default caps in
/// `rt.vdso`'s spawn path): a process gets it only if an ancestor that holds it
/// passes it on explicitly via [`MOTOR_OS_CAPS_ENV_KEY`]. Because a non-system
/// parent may already grant any capability it holds, that pass-on is transitive
/// without any special kernel rule — the kernel only checks, at a detached
/// spawn, that the *spawner* holds this bit.
pub const CAP_SPAWN_DETACHED: u64 = 1 << 5;

// This ENV key can be used to specify caps for the
// process being created. The value must be formated in hex.
// Currently works with Rust's std::process::Command.
pub const MOTOR_OS_CAPS_ENV_KEY: &str = "MOTOR_OS_CAPS";

/// If this ENV key is present with value "true"/"TRUE" when spawning, the child
/// is spawned *detached* (see [`CAP_SPAWN_DETACHED`]). Consumed by the spawner's
/// runtime (like [`MOTOR_OS_CAPS_ENV_KEY`]) and never seen by the child. The
/// spawner must hold `CAP_SPAWN_DETACHED` or the spawn fails with `E_NOT_ALLOWED`.
pub const MOTOR_OS_DETACHED_ENV_KEY: &str = "MOTOR_OS_DETACHED";
