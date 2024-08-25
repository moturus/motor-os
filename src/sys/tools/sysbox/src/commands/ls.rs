use std::{io::IsTerminal, path::Path};

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tls [$DIR] [-l]\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "ls");

    let list_dots = false;
    let mut list_details = false;
    let mut dir: Option<&str> = None;

    for arg in &args[1..] {
        if arg.trim().is_empty() {
            continue;
        }

        let bytes = arg.trim().as_bytes();
        if bytes[0] == b'-' {
            for char in &bytes[1..] {
                match char {
                    b'l' => list_details = true,
                    // TODO: add "." and ".." manually.
                    // b'a' => list_dots = true,
                    _ => {
                        print_usage_and_exit(1);
                    }
                }
            }
        } else {
            if dir.is_some() {
                print_usage_and_exit(1);
            }
            dir = Some(arg.trim());
        }
    }

    if dir.is_none() {
        dir = Some(".");
    }

    let dir = unsafe { dir.unwrap_unchecked() };

    if list_details {
        list_detailed(dir, list_dots);
    } else {
        list_plain(dir, list_dots);
    }
}

fn list_detailed(dir: &str, list_dots: bool) {
    let path = std::fs::canonicalize(Path::new(dir));
    if path.is_err() {
        eprintln!("error reading directory '{}'.\n", dir);
        return;
    }
    let readdir = std::fs::read_dir(path.unwrap().as_path());
    if readdir.is_err() {
        eprintln!("error reading directory '{}'.\n", dir);
        return;
    }

    let mut entries = std::vec![];

    let mut max_size = 0;
    for e in readdir.unwrap() {
        max_size = max_size.max(e.as_ref().unwrap().metadata().unwrap().len());
        entries.push(e);
    }
    entries.sort_by(|a, b| {
        if a.as_ref().unwrap().file_type().unwrap().is_dir()
            && !&b.as_ref().unwrap().file_type().unwrap().is_dir()
        {
            std::cmp::Ordering::Less
        } else {
            a.as_ref()
                .unwrap()
                .file_name()
                .cmp(&b.as_ref().unwrap().file_name())
        }
    });

    let size_len = max_size.to_string().len();

    let (dir_in, dir_out) = if std::io::stdout().is_terminal() {
        ("\x1b[1m\x1b[34m", "\x1b[0m\x1b[0m")
    } else {
        ("", "")
    };

    let (file_in, file_out) = if std::io::stdout().is_terminal() {
        ("\x1b[1m\x1b[32m", "\x1b[0m\x1b[0m")
    } else {
        ("", "")
    };

    for e in &entries {
        match e {
            Ok(e) => {
                let ft = e.file_type().unwrap();
                let fname = e.file_name().to_str().unwrap().to_owned();
                if fname.as_str() == "." && !list_dots {
                    continue;
                }
                if fname.as_str() == ".." && !list_dots {
                    continue;
                }
                if ft.is_dir() {
                    print!("d ");
                    for _ in 0..size_len {
                        print!(" ");
                    }
                    println!(" {}{}{}", dir_in, fname, dir_out);
                } else if ft.is_file() {
                    println!(
                        "f {:width$} {}{}{}",
                        e.metadata().unwrap().len(),
                        file_in,
                        fname,
                        file_out,
                        width = size_len,
                    );
                } else {
                    println!("? {}", fname);
                }
            }
            Err(_) => {
                eprintln!("--error--");
            }
        }
    }
}

fn list_plain(dir: &str, list_dots: bool) {
    let path = std::fs::canonicalize(Path::new(dir));
    if path.is_err() {
        eprintln!("error reading directory '{}' (1).\n", dir);
        return;
    }
    let readdir = std::fs::read_dir(path.unwrap().as_path());
    if readdir.is_err() {
        eprintln!("error reading directory '{}' (2).\n", dir);
        return;
    }

    let mut entries = std::vec![];

    for e in readdir.unwrap() {
        if e.is_err() {
            continue;
        }
        entries.push(e.unwrap());
    }
    entries.sort_by(|a, b| {
        if a.file_type().unwrap().is_dir() && !&b.file_type().unwrap().is_dir() {
            std::cmp::Ordering::Less
        } else {
            a.file_name().cmp(&b.file_name())
        }
    });

    let (dir_in, dir_out) = if std::io::stdout().is_terminal() {
        ("\x1b[1m\x1b[34m", "\x1b[0m\x1b[0m")
    } else {
        ("", "")
    };

    let (file_in, file_out) = if std::io::stdout().is_terminal() {
        ("\x1b[33m", "\x1b[0m")
    } else {
        ("", "")
    };

    for e in &entries {
        let ft = e.file_type().unwrap();
        let fname = e.file_name().to_str().unwrap().to_owned();
        if fname.as_str() == "." && !list_dots {
            continue;
        }
        if fname.as_str() == ".." && !list_dots {
            continue;
        }
        if ft.is_dir() {
            print!("{}{}{} ", dir_in, fname, dir_out);
        } else if ft.is_file() {
            print!("{}{}{} ", file_in, fname, file_out);
        } else {
            print!("? {}", fname);
        }
    }
    println!("");
}
