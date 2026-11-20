//! Share freshly created data fixtures with the None build worker.
#[cfg(target_os = "motor")]
use std::fs;
use std::{io, path::Path};

pub fn share(root: &Path) -> io::Result<()> {
    #[cfg(target_os = "motor")]
    {
        let directory = root.is_dir();
        crate::support::share(root, directory);
        if directory {
            for entry in fs::read_dir(root)? {
                share(&entry?.path())?;
            }
        }
    }
    #[cfg(not(target_os = "motor"))]
    let _ = root;
    Ok(())
}
