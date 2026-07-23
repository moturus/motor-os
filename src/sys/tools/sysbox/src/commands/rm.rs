use std::{
    io::{Error, ErrorKind, Result},
    path::Path,
};

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\trm [-r] $FILE\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "rm");

    let (recursive, path) = match args {
        [_, path] => (false, path),
        [_, option, path] if option == "-r" => (true, path),
        _ => print_usage_and_exit(1),
    };

    if let Err(err) = remove(Path::new(path), recursive) {
        eprintln!("rm failed: {err}");
        std::process::exit(1);
    }
}

fn remove(path: &Path, recursive: bool) -> Result<()> {
    let metadata = std::fs::metadata(path)?;

    if !metadata.is_dir() {
        return std::fs::remove_file(path);
    }

    if !recursive {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("'{}' is a directory (use -r to remove it)", path.display()),
        ));
    }

    std::fs::remove_dir_all(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("sysbox-rm-{name}-{}-{id}", std::process::id()));
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
    fn recursively_removes_a_directory_tree() {
        let test_dir = TestDir::new("recursive");
        let target = test_dir.0.join("target");
        std::fs::create_dir_all(target.join("nested")).unwrap();
        std::fs::write(target.join("nested/file.txt"), b"contents").unwrap();

        remove(&target, true).unwrap();

        assert!(!target.exists());
    }

    #[test]
    fn recursive_remove_also_removes_a_file() {
        let test_dir = TestDir::new("file");
        let target = test_dir.0.join("file.txt");
        std::fs::write(&target, b"contents").unwrap();

        remove(&target, true).unwrap();

        assert!(!target.exists());
    }

    #[test]
    fn removing_a_directory_without_recursive_is_rejected() {
        let test_dir = TestDir::new("non-recursive");
        let target = test_dir.0.join("target");
        std::fs::create_dir(&target).unwrap();

        let result = remove(&target, false);

        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
        assert!(target.exists());
    }
}
