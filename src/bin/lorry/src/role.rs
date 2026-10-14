//! Where Lorry keeps per-user state on Motor OS.
//!
//! Each process role has its own configuration, repository, cache, and scratch
//! directories, so a None-role Lorry never reads or writes Interactive state.
//! System has none: Lorry refuses to run as System.

use std::path::{Path, PathBuf};

use crate::diagnostic::Result;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    Interactive,
    #[cfg_attr(not(target_os = "motor"), allow(dead_code))]
    None,
}

impl Role {
    /// The role of this process. `main` refuses System before any command
    /// runs. Off Motor OS no role-based path is used.
    pub fn current() -> Self {
        #[cfg(target_os = "motor")]
        if moto_sys::ProcessStaticPage::get().capabilities
            & (moto_sys::caps::CAP_SYS | moto_sys::caps::CAP_INTERACTIVE)
            == 0
        {
            return Self::None;
        }
        Self::Interactive
    }

    /// Where this role's configuration lives.
    pub fn config_directory(self) -> &'static Path {
        Path::new(match self {
            Self::Interactive => "/user/cfg",
            Self::None => "/none/cfg",
        })
    }

    /// This role's repository and cache.
    pub fn state_directory(self) -> &'static Path {
        Path::new(match self {
            Self::Interactive => "/devtools/lorry/user",
            Self::None => "/devtools/lorry/none",
        })
    }

    /// This role's temporary directory.
    pub fn temp_directory(self) -> &'static Path {
        Path::new(match self {
            Self::Interactive => "/user/tmp",
            Self::None => "/none/tmp",
        })
    }

    pub fn config_file(self) -> PathBuf {
        self.config_directory().join("lorry.toml")
    }
}

/// Refuses a System-role process on Motor OS.
pub(crate) fn refuse_system() -> Result<()> {
    #[cfg(target_os = "motor")]
    if moto_sys::ProcessStaticPage::get().capabilities & moto_sys::caps::CAP_SYS != 0 {
        return Err(
            crate::diagnostic::Error::failure("Lorry does not run as System")
                .with_help("run Lorry from an Interactive shell, or as None"),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_role_keeps_its_own_directories() {
        assert_eq!(
            Role::Interactive.config_file(),
            Path::new("/user/cfg/lorry.toml")
        );
        assert_eq!(Role::None.config_file(), Path::new("/none/cfg/lorry.toml"));
        assert_eq!(
            Role::None.state_directory(),
            Path::new("/devtools/lorry/none")
        );
        assert_eq!(Role::None.temp_directory(), Path::new("/none/tmp"));
        refuse_system().unwrap();
    }
}
