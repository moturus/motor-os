//! Directory creation, including idempotent parent creation for coding tools.

fn usage_error(message: &str) -> ! {
    eprintln!("mkdir: {message}");
    eprintln!("Try 'mkdir --help' for more information.");
    std::process::exit(1);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "mkdir");

    let mut parents = false;
    let mut options = true;
    let mut paths = Vec::new();
    // Parse everything before creating anything: an invalid flag has no effects.
    for argument in &args[1..] {
        match argument.as_str() {
            "--" if options => options = false,
            "--help" if options => {
                println!(
                    "usage: mkdir [-p | --parents] [--] DIRECTORY...\n\
                          Create directories; -p creates parents and accepts existing directories."
                );
                return;
            }
            "--parents" if options => parents = true,
            flag if options && flag.starts_with('-') && flag != "-" => {
                if flag[1..].chars().all(|option| option == 'p') {
                    parents = true;
                } else {
                    usage_error(&format!("unsupported option '{flag}'"));
                }
            }
            _ => paths.push(argument),
        }
    }
    if paths.is_empty() {
        usage_error("missing operand");
    }

    let mut failed = false;
    for path in paths {
        let result = if path.is_empty() {
            // create_dir_all("") is a no-op; report mkdir's error on either platform.
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        } else if parents {
            std::fs::create_dir_all(path)
        } else {
            std::fs::create_dir(path)
        };
        if let Err(error) = result {
            let reason = match error.kind() {
                std::io::ErrorKind::AlreadyExists => "File exists".to_owned(),
                std::io::ErrorKind::NotADirectory => "Not a directory".to_owned(),
                _ => super::wc::strerror(&error),
            };
            eprintln!("mkdir: cannot create directory '{path}': {reason}");
            failed = true;
        }
    }
    if failed {
        std::process::exit(1);
    }
}
