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
