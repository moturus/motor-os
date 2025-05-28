fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tmv [$OLD_NAME] [$NEW_NAME]\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "mv");

    if args.len() != 3 {
        print_usage_and_exit(1);
    }

    let old = args[1].as_str();
    let new = args[2].as_str();

    match old.chars().last() {
        Some(c) => {
            if c == '/' {
                eprintln!("mv: bad argument: '{old}'");

                std::process::exit(1);
            }
        }
        None => {
            eprintln!("mv: empty first arg??");
            std::process::exit(1);
        }
    }
    let old_path = std::path::Path::new(old);

    let new_dir = match new.chars().last() {
        Some(c) => c == '/',
        None => {
            eprintln!("mv: empty second arg??");
            std::process::exit(1);
        }
    };

    if new_dir {
        // Need to add the filename, otherwise the last slash is lost,
        // but it is meaningful.
        let fname = old_path.file_name().unwrap();
        let mut new_path = std::path::Path::new(new).to_path_buf();
        new_path.push(fname);
        if let Err(err) = std::fs::rename(old_path, new_path.as_path()) {
            eprintln!("mv failed: {err:?}");
        }

        return;
    }

    if let Err(err) = std::fs::rename(old_path, std::path::Path::new(new)) {
        eprintln!("mv failed: {err:?}");
    }
}
