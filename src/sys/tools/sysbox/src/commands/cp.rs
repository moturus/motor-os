use std::path::{Path, PathBuf};

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tcp [-r] $OLD_NAME $NEW_NAME\n");
    std::process::exit(exit_code);
}

pub fn canonicalize_pair(old: &str, new: &str) -> std::io::Result<(PathBuf, PathBuf)> {
    let old = old.trim();
    let new = new.trim();

    let Ok(old) = std::fs::canonicalize(Path::new(old)) else {
        eprintln!("bad filename '{old}'");
        std::process::exit(1);
    };

    let old_str = old.as_path().as_os_str().to_str().unwrap();
    if old_str.is_empty() || old_str == "/" {
        eprintln!("Operations on root not supported");
        std::process::exit(1);
    }

    let Some(last_char) = new.chars().last() else {
        eprintln!("bad filename: '{new}'");
        std::process::exit(1);
    };

    let has_trailing_slash = last_char == '/' || new == "." || new == "..";

    if !Path::new(new).exists() {
        if has_trailing_slash {
            eprintln!("'{new}' does not exist.");
            std::process::exit(1);
        }

        return Ok((old, Path::new(new).to_owned()));
    }

    let Ok(mut new) = std::fs::canonicalize(Path::new(new)) else {
        eprintln!("bad filename '{new}'");
        std::process::exit(1);
    };

    let new_meta =
        std::fs::metadata(&new).inspect_err(|e| eprintln!("Error {e:?} accessing '{new:?}'"))?;

    if !new_meta.is_dir() && has_trailing_slash {
        eprintln!("'{new:?}' is not a directory");
        std::process::exit(1);
    }

    if has_trailing_slash {
        new.push(old.as_path().file_name().unwrap());
    }

    Ok((old, new))
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "cp");

    if args.len() == 4 {
        if args[1].as_str() != "-r" {
            print_usage_and_exit(1);
        }

        copy_recursively(args[2].as_str(), args[3].as_str());
        return;
    }

    if args.len() != 3 {
        print_usage_and_exit(1);
    }

    let Ok((old, new)) = canonicalize_pair(args[1].as_str(), args[2].as_str()) else {
        std::process::exit(1);
    };

    do_copy(old, new)
}

fn do_copy(old: PathBuf, new: PathBuf) {
    let Ok(old_meta) = std::fs::metadata(old.as_path()) else {
        eprintln!("Bad filename: '{old:?}'");
        std::process::exit(1);
    };

    if !old_meta.is_file() {
        eprintln!("'{old:?}' is not a file");
        std::process::exit(1);
    }

    if !new.exists() {
        // Copy to a new location.
        if let Err(err) = std::fs::copy(old, new) {
            eprintln!("FS error: {err:?}.");
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    let Ok(new_meta) = std::fs::metadata(new.as_path()) else {
        eprintln!("Bad filename: '{new:?}'");
        std::process::exit(1);
    };

    if !new_meta.is_file() {
        eprintln!("'{new:?}' is not a file");
        std::process::exit(1);
    }

    // Copy over an existing file.
    if let Err(err) = std::fs::copy(old, new) {
        eprintln!("FS error: {err:?}.");
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn copy_recursively(_old: &str, _new: &str) {
    todo!()
}
