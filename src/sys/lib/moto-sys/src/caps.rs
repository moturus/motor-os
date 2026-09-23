//! Process capabilities.

/// This is a system process (cannot be killed by userspace).
pub const CAP_SYS: u64 = 1 << 0;

/// IO Manager. The IO manager has access to the serial console (COM1 port)
/// and can do mmio.
pub const CAP_IO_MANAGER: u64 = 1 << 1;

/// The process can spawn other processes.
pub const CAP_SPAWN: u64 = 1 << 2;

/// The process can submit records to the kernel log and strobe's record channel.
///
/// This does not grant direct access to `/system/logs`. Unlike most
/// capabilities, a None-role process cannot delegate this bit.
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
/// parent may already grant most capabilities it holds, that pass-on is
/// transitive without any special kernel rule. `CAP_LOG` is the exception: a
/// None-role parent cannot delegate it. The kernel also checks, at a detached
/// spawn, that the *spawner* holds this bit.
pub const CAP_SPAWN_DETACHED: u64 = 1 << 5;

/// The process acts with the authority of the logged-in user.
///
/// [`CAP_SYS`] takes precedence when deriving a process role; it does not
/// imply this bit.
pub const CAP_INTERACTIVE: u64 = 1 << 6;

/// The process may create and listen on native virtio-vsock streams. It is
/// inherited by default when held; an explicit mask that omits it denies it,
/// and [`CAP_SYS`] does not allow a parent to grant it without holding it.
pub const CAP_VSOCK: u64 = 1 << 7;

/// The process may use sys-io's network API; sys-io drops a peer without it.
/// Native vsock access needs both this bit and [`CAP_VSOCK`].
///
/// Inherited by default when held. Like [`CAP_VSOCK`], every parent, including
/// a [`CAP_SYS`] one, must hold it to grant it.
pub const CAP_NET: u64 = 1 << 8;

/// The process may modify the filesystem and use file locks through sys-io.
/// Without it, sys-io serves only reads, and the runtime refuses write-intent
/// opens. It does not override filesystem permissions.
///
/// Inherited by default when held. Like [`CAP_VSOCK`], every parent, including
/// a [`CAP_SYS`] one, must hold it to grant it.
pub const CAP_FS_WRITE: u64 = 1 << 9;

/// Capabilities a child may receive only from a parent that holds them,
/// whatever the parent's role. They are inherited by default when held.
pub const PARENT_OWNED_CAPS: u64 = CAP_VSOCK | CAP_NET | CAP_FS_WRITE;

/// Filesystem-facing process privilege role.
///
/// The discriminants match `async_fs::Role` and the process-stats encoding.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProcessRole {
    None = 0,
    Interactive = 1,
    System = 2,
}

impl ProcessRole {
    /// Derives the role from the immutable process capability word.
    pub const fn from_caps(caps: u64) -> Self {
        if caps & CAP_SYS != 0 {
            Self::System
        } else if caps & CAP_INTERACTIVE != 0 {
            Self::Interactive
        } else {
            Self::None
        }
    }
}

/// Returns the capabilities used for a spawn with no explicit capability mask.
///
/// Interactive authority follows an Interactive parent. System authority never
/// follows implicitly. System grants logging authority by default; lower roles
/// do not. [`PARENT_OWNED_CAPS`] follow when the parent holds them. Defaults
/// from non-System parents are restricted to capabilities the parent actually
/// holds.
pub const fn default_child_capabilities(parent_caps: u64) -> u64 {
    let role = ProcessRole::from_caps(parent_caps);
    let mut child_caps = CAP_SPAWN;
    match role {
        ProcessRole::System => child_caps |= CAP_LOG,
        ProcessRole::Interactive => child_caps |= CAP_INTERACTIVE,
        ProcessRole::None => {}
    }
    child_caps |= parent_caps & PARENT_OWNED_CAPS;
    if !matches!(role, ProcessRole::System) {
        child_caps &= parent_caps;
    }
    child_caps
}

impl TryFrom<u8> for ProcessRole {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Interactive),
            2 => Ok(Self::System),
            _ => Err(()),
        }
    }
}

// This ENV key can be used to specify caps for the
// process being created. The value must be formated in hex.
// Currently works with Rust's std::process::Command.
pub const MOTOR_OS_CAPS_ENV_KEY: &str = "MOTOR_OS_CAPS";

/// If this ENV key is present with value "true"/"TRUE" when spawning, the child
/// is spawned *detached* (see [`CAP_SPAWN_DETACHED`]). Consumed by the spawner's
/// runtime (like [`MOTOR_OS_CAPS_ENV_KEY`]) and never seen by the child. The
/// spawner must hold `CAP_SPAWN_DETACHED` or the spawn fails with `E_NOT_ALLOWED`.
pub const MOTOR_OS_DETACHED_ENV_KEY: &str = "MOTOR_OS_DETACHED";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_child_caps_keep_logging_grantor_controlled() {
        let system_default = CAP_SPAWN | CAP_LOG;
        assert_eq!(
            system_default | PARENT_OWNED_CAPS,
            default_child_capabilities(u64::MAX)
        );
        assert_eq!(system_default, default_child_capabilities(CAP_SYS));
        assert_eq!(
            CAP_SPAWN | CAP_INTERACTIVE | CAP_VSOCK,
            default_child_capabilities(CAP_SPAWN | CAP_LOG | CAP_INTERACTIVE | CAP_VSOCK)
        );
        assert_eq!(CAP_SPAWN, default_child_capabilities(CAP_SPAWN | CAP_LOG));
        assert_eq!(CAP_SPAWN, default_child_capabilities(CAP_SPAWN));
        assert_eq!(0, default_child_capabilities(0));
    }

    #[test]
    fn default_child_caps_inherit_net_and_fs_write_only_when_held() {
        let system = CAP_SYS | CAP_SPAWN | CAP_SPAWN_DETACHED | CAP_INTERACTIVE;
        let system_default = CAP_SPAWN | CAP_LOG;
        for bits in [0, CAP_NET, CAP_FS_WRITE, CAP_NET | CAP_FS_WRITE] {
            let child = default_child_capabilities(system | bits);
            assert_eq!(system_default | bits, child);
            assert_eq!(ProcessRole::None, ProcessRole::from_caps(child));

            let interactive = CAP_SPAWN | CAP_LOG | CAP_SPAWN_DETACHED | CAP_INTERACTIVE;
            let child = default_child_capabilities(interactive | CAP_VSOCK | bits);
            assert_eq!(CAP_SPAWN | CAP_INTERACTIVE | CAP_VSOCK | bits, child);
            assert_eq!(
                CAP_SPAWN | CAP_INTERACTIVE | bits,
                default_child_capabilities(interactive | bits)
            );

            assert_eq!(bits, default_child_capabilities(CAP_LOG | bits));
            assert_eq!(
                CAP_SPAWN | CAP_VSOCK | bits,
                default_child_capabilities(CAP_SPAWN | CAP_LOG | CAP_VSOCK | bits)
            );
        }
    }
}
