use std::path::Path;

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tfind [$PATH]... [-type d|f]\n");
    std::process::exit(exit_code);
}

#[derive(Clone, Copy)]
enum TypeFilter {
    Dir,
    File,
}

impl TypeFilter {
    fn matches(filter: Option<Self>, is_dir: bool, is_file: bool) -> bool {
        match filter {
            None => true,
            Some(Self::Dir) => is_dir,
            Some(Self::File) => is_file,
        }
    }
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "find");

    let mut paths: Vec<&str> = vec![];
    let mut type_filter: Option<TypeFilter> = None;

    let mut idx = 1;
    while idx < args.len() {
        let arg = args[idx].as_str();
        match arg {
            "--help" => print_usage_and_exit(0),
            "-type" => {
                idx += 1;
                let filter = match args.get(idx).map(String::as_str) {
                    Some("d") => TypeFilter::Dir,
                    Some("f") => TypeFilter::File,
                    _ => print_usage_and_exit(1),
                };
                if type_filter.replace(filter).is_some() {
                    print_usage_and_exit(1);
                }
            }
            _ if arg.starts_with('-') => print_usage_and_exit(1),
            _ => paths.push(arg),
        }
        idx += 1;
    }

    if paths.is_empty() {
        paths.push(".");
    }

    let mut ok = true;
    for path in paths {
        ok &= walk_root(Path::new(path), type_filter);
    }
    if !ok {
        std::process::exit(1);
    }
}

fn report_error(path: &Path, err: &std::io::Error) {
    eprintln!("find: '{}': {err}", path.display());
}

fn walk_root(path: &Path, filter: Option<TypeFilter>) -> bool {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(err) => {
            report_error(path, &err);
            return false;
        }
    };

    if TypeFilter::matches(filter, meta.is_dir(), meta.is_file()) {
        println!("{}", path.display());
    }
    if meta.is_dir() {
        walk_dir(path, filter)
    } else {
        true
    }
}

// Preorder: a directory is printed by the caller, then its children follow,
// sorted by name for deterministic output.
fn walk_dir(path: &Path, filter: Option<TypeFilter>) -> bool {
    let readdir = match std::fs::read_dir(path) {
        Ok(readdir) => readdir,
        Err(err) => {
            report_error(path, &err);
            return false;
        }
    };

    let mut ok = true;
    let mut entries = vec![];
    for entry in readdir {
        match entry {
            Ok(entry) => {
                let name = entry.file_name();
                if name == "." || name == ".." {
                    continue;
                }
                match entry.file_type() {
                    Ok(file_type) => entries.push((name, file_type)),
                    Err(err) => {
                        report_error(&path.join(name), &err);
                        ok = false;
                    }
                }
            }
            Err(err) => {
                report_error(path, &err);
                ok = false;
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, file_type) in entries {
        let child = path.join(name);
        if TypeFilter::matches(filter, file_type.is_dir(), file_type.is_file()) {
            println!("{}", child.display());
        }
        if file_type.is_dir() {
            ok &= walk_dir(&child, filter);
        }
    }
    ok
}
