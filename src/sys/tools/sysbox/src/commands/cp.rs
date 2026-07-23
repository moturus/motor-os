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

    std::fs::copy(old, new)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("sysbox-cp-{name}-{}-{id}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn recursively_copies_and_merges_directories() {
        let test_dir = TestDir::new("recursive");
        let source = test_dir.0.join("source");
        let nested = source.join("nested");
        let destination = test_dir.0.join("destination");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(source.join("top.txt"), b"top").unwrap();
        std::fs::write(nested.join("child.txt"), b"child").unwrap();

        let existing_target = destination.join("source");
        std::fs::create_dir(&existing_target).unwrap();
        std::fs::write(existing_target.join("untouched.txt"), b"keep").unwrap();
        std::fs::write(existing_target.join("top.txt"), b"old").unwrap();

        copy(
            source.to_str().unwrap(),
            destination.to_str().unwrap(),
            true,
        )
        .unwrap();

        assert_eq!(
            std::fs::read(existing_target.join("top.txt")).unwrap(),
            b"top"
        );
        assert_eq!(
            std::fs::read(existing_target.join("nested/child.txt")).unwrap(),
            b"child"
        );
        assert_eq!(
            std::fs::read(existing_target.join("untouched.txt")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn recursive_copy_rejects_a_destination_inside_the_source() {
        let test_dir = TestDir::new("self");
        let source = test_dir.0.join("source");
        std::fs::create_dir(&source).unwrap();

        let result = copy(
            source.to_str().unwrap(),
            source.join("child").to_str().unwrap(),
            true,
        );

        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
        assert!(!source.join("child").exists());
    }

    #[test]
    fn copying_a_directory_without_recursive_is_rejected() {
        let test_dir = TestDir::new("non-recursive");
        let source = test_dir.0.join("source");
        std::fs::create_dir(&source).unwrap();

        let result = copy(
            source.to_str().unwrap(),
            test_dir.0.join("copy").to_str().unwrap(),
            false,
        );

        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }
}
