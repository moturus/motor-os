//! Share freshly created data fixtures with the None build worker.
#[cfg(target_os = "motor")]
use std::{fs, process::Command};
use std::{io, path::Path};

pub fn share(root: &Path) -> io::Result<()> {
    #[cfg(target_os = "motor")]
    {
        let directory = root.is_dir();
        let mode = if directory { "rwxrwxrwx" } else { "rwxrw-rw-" };
        if !Command::new("/user/bin/chmod")
            .arg(mode)
            .arg(root)
            .status()?
            .success()
        {
            return Err(io::Error::other(format!(
                "cannot share fixture {}",
                root.display()
            )));
        }
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
