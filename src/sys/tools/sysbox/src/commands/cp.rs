use std::{
    io::{Error, ErrorKind, Result},
    path::{Path, PathBuf},
};

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tcp [-r] $OLD_NAME $NEW_NAME\n");
    std::process::exit(exit_code);
}

fn invalid_input(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidInput, message.into())
}

pub fn canonicalize_pair(old: &str, new: &str) -> Result<(PathBuf, PathBuf)> {
    let old = old.trim();
    let new = new.trim();

    if old.is_empty() || new.is_empty() {
        return Err(invalid_input("source and destination must not be empty"));
    }

    let old = std::fs::canonicalize(old)?;
    if old.parent().is_none() {
        return Err(invalid_input(
            "operations on the root directory are not supported",
        ));
    }

    let new_path = Path::new(new);
    if !new_path.exists() {
        if new.ends_with('/') {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("destination directory '{new}' does not exist"),
            ));
        }

        return Ok((old, new_path.to_owned()));
    }

    let mut new = std::fs::canonicalize(new_path)?;
    if new.is_dir() {
        new.push(
            old.file_name()
                .ok_or_else(|| invalid_input("the source has no file name"))?,
        );
    }

    Ok((old, new))
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "cp");

    let (recursive, old, new) = match args {
        [_, old, new] => (false, old, new),
        [_, option, old, new] if option == "-r" => (true, old, new),
        _ => print_usage_and_exit(1),
    };

    if let Err(err) = copy(old, new, recursive) {
        eprintln!("cp failed: {err}");
        std::process::exit(1);
    }
}

fn copy(old: &str, new: &str, recursive: bool) -> Result<()> {
    let (old, new) = canonicalize_pair(old, new)?;
    let old_meta = std::fs::metadata(&old)?;

    if old_meta.is_dir() {
        if !recursive {
            return Err(invalid_input(format!(
                "'{}' is a directory (use -r to copy it)",
                old.display()
            )));
        }

        ensure_not_copying_into_itself(&old, &new)?;
        copy_directory(&old, &new)
    } else {
        copy_file(&old, &new)
    }
}

fn ensure_not_copying_into_itself(old: &Path, new: &Path) -> Result<()> {
    let new = if new.exists() {
        std::fs::canonicalize(new)?
    } else {
        let parent = new
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let file_name = new
            .file_name()
            .ok_or_else(|| invalid_input("the destination has no file name"))?;
        std::fs::canonicalize(parent)?.join(file_name)
    };

    if new.starts_with(old) {
        return Err(invalid_input(format!(
            "cannot copy '{}' into itself at '{}'",
            old.display(),
            new.display()
        )));
    }

    Ok(())
}

fn copy_directory(old: &Path, new: &Path) -> Result<()> {
    let permissions = std::fs::metadata(old)?.permissions();
    if new.exists() {
        if !new.is_dir() {
            return Err(invalid_input(format!(
                "cannot overwrite non-directory '{}' with directory '{}'",
                new.display(),
                old.display()
            )));
        }
    } else {
        std::fs::create_dir(new)?;
    }

    for entry in std::fs::read_dir(old)? {
        let entry = entry?;
        let old_child = entry.path();
        let new_child = new.join(entry.file_name());

        if entry.file_type()?.is_dir() {
            copy_directory(&old_child, &new_child)?;
        } else {
            copy_file(&old_child, &new_child)?;
        }
    }

    std::fs::set_permissions(new, permissions)?;
    Ok(())
}

fn copy_file(old: &Path, new: &Path) -> Result<()> {
    if new.is_dir() {
        return Err(invalid_input(format!(
            "cannot overwrite directory '{}' with file '{}'",
            new.display(),
            old.display()
        )));
    }

    let permissions = std::fs::metadata(old)?.permissions();
    std::fs::copy(old, new)?;
    std::fs::set_permissions(new, permissions)?;
    Ok(())
}
