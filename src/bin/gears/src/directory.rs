//! One user-state directory shared by configuration, locks and session storage.

use std::path::PathBuf;

pub const ENV: &str = "GEARS_DIRECTORY";

pub fn default_root() -> Result<PathBuf, String> {
    if let Some(value) = std::env::var_os(ENV) {
        let root = PathBuf::from(value);
        if !root.is_absolute() {
            return Err("GEARS_DIRECTORY must be an absolute directory".into());
        }
        crate::state::StateRoot::new(root.clone())?;
        return Ok(root);
    }
    #[cfg(target_os = "motor")]
    {
        Ok(PathBuf::from("/user/cfg/gears"))
    }
    #[cfg(all(unix, not(target_os = "motor")))]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".gears"))
            .ok_or("HOME is not set; cannot locate Gears directory".into())
    }
    #[cfg(not(any(target_os = "motor", unix)))]
    {
        Err("this platform has no Gears directory".into())
    }
}
