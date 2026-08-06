use std::path::Path;

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tfind [$PATH]... [-type d|f] [-name $PATTERN]\n");
    std::process::exit(exit_code);
}

#[derive(Clone, Copy)]
enum TypeFilter {
    Dir,
    File,
}

#[derive(Default)]
struct Filters {
    file_type: Option<TypeFilter>,
    name: Option<String>,
}

impl Filters {
    fn matches(&self, name: &str, is_dir: bool, is_file: bool) -> bool {
        let type_ok = match self.file_type {
            None => true,
            Some(TypeFilter::Dir) => is_dir,
            Some(TypeFilter::File) => is_file,
        };
        let name_ok = match &self.name {
            None => true,
            Some(pattern) => glob_match(pattern, name),
        };
        type_ok && name_ok
    }
}

// Matches `name` against `pattern`, where '*' matches any (possibly empty)
// sequence of characters and '?' matches exactly one character.
fn glob_match(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();

    let (mut p, mut n) = (0, 0);
    // On mismatch, backtrack to the most recent '*' and let it consume one
    // more character of the name.
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p + 1, n));
            p += 1;
        } else if let Some((star_p, star_n)) = star {
            p = star_p;
            n = star_n + 1;
            star = Some((star_p, star_n + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "find");

    let mut paths: Vec<&str> = vec![];
    let mut filters = Filters::default();

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
                if filters.file_type.replace(filter).is_some() {
                    print_usage_and_exit(1);
                }
            }
            "-name" => {
                idx += 1;
                let Some(pattern) = args.get(idx) else {
                    print_usage_and_exit(1);
                };
                if filters.name.replace(pattern.clone()).is_some() {
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
        ok &= walk_root(Path::new(path), &filters);
    }
    if !ok {
        std::process::exit(1);
    }
}

fn report_error(path: &Path, err: &std::io::Error) {
    eprintln!("find: '{}': {err}", path.display());
}

fn walk_root(path: &Path, filters: &Filters) -> bool {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(err) => {
            report_error(path, &err);
            return false;
        }
    };

    // Like the entries below, the start path is filtered by its last
    // component ("." and ".." are their own names).
    let name = match path.file_name() {
        Some(name) => name.to_string_lossy(),
        None => path.as_os_str().to_string_lossy(),
    };
    if filters.matches(&name, meta.is_dir(), meta.is_file()) {
        println!("{}", path.display());
    }
    if meta.is_dir() {
        walk_dir(path, filters)
    } else {
        true
    }
}

// Preorder: a directory is printed by the caller, then its children follow,
// sorted by name for deterministic output.
fn walk_dir(path: &Path, filters: &Filters) -> bool {
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
        let matched = filters.matches(
            &name.to_string_lossy(),
            file_type.is_dir(),
            file_type.is_file(),
        );
        let child = path.join(name);
        if matched {
            println!("{}", child.display());
        }
        if file_type.is_dir() {
            ok &= walk_dir(&child, filters);
        }
    }
    ok
}
