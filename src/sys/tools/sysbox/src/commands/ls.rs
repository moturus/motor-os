use std::{cmp::Ordering, io::IsTerminal, path::Path};

const DIRECTORY_COLOR: &str = "\x1b[1;38;5;214m";
const COLOR_RESET: &str = "\x1b[0m";

fn name_colors(is_directory: bool, stdout_is_terminal: bool) -> (&'static str, &'static str) {
    if is_directory && stdout_is_terminal {
        (DIRECTORY_COLOR, COLOR_RESET)
    } else {
        ("", "")
    }
}

struct DetailedEntry {
    name: String,
    kind: DetailedEntryKind,
    size: u64,
    permissions: [PermissionTriplet; 3],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DetailedEntryKind {
    Directory,
    File,
}

#[derive(Clone, Copy)]
struct PermissionTriplet {
    read: bool,
    write: bool,
    execute: bool,
}

fn compare_detailed_entries(a: &DetailedEntry, b: &DetailedEntry) -> Ordering {
    match (
        a.kind == DetailedEntryKind::Directory,
        b.kind == DetailedEntryKind::Directory,
    ) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => a.name.cmp(&b.name),
    }
}

fn permission_string(kind: DetailedEntryKind, permissions: [PermissionTriplet; 3]) -> String {
    let mut result = String::with_capacity(10);
    result.push(match kind {
        DetailedEntryKind::Directory => 'd',
        DetailedEntryKind::File => '-',
    });

    for permission in permissions {
        result.extend(permission_chars(permission));
    }
    result
}

fn permission_chars(permission: PermissionTriplet) -> [char; 3] {
    [
        if permission.read { 'r' } else { '-' },
        if permission.write { 'w' } else { '-' },
        if permission.execute { 'x' } else { '-' },
    ]
}

fn read_detailed_entries(dir: &Path) -> moto_rt::Result<Vec<DetailedEntry>> {
    use moto_io::fs::{EntryKind, FsClient, Role};

    let dir = dir
        .to_str()
        .ok_or(moto_rt::Error::InvalidArgument)?
        .to_owned();

    moto_async::LocalRuntime::new().block_on(async move {
        let client = FsClient::connect()?;
        let (dir_id, kind) = client.stat(&dir).await?;
        if kind != EntryKind::Directory {
            return Err(moto_rt::Error::NotADirectory);
        }

        let mut entries = Vec::new();
        let mut entry_id = client.get_first_entry(dir_id).await?;
        while let Some(id) = entry_id {
            // Fetch the successor first, as std::fs::read_dir does, so a
            // concurrently removed current entry cannot strand the cursor.
            entry_id = client.get_next_entry(id).await?;
            let metadata = client.metadata(id).await?;
            let kind = match metadata.try_kind()? {
                EntryKind::Directory => DetailedEntryKind::Directory,
                EntryKind::File => DetailedEntryKind::File,
            };
            let mut permissions = [PermissionTriplet {
                read: false,
                write: false,
                execute: false,
            }; 3];
            for (idx, role) in [Role::System, Role::Interactive, Role::None]
                .into_iter()
                .enumerate()
            {
                let (read, write, execute) = metadata.access(role)?.triple();
                permissions[idx] = PermissionTriplet {
                    read,
                    write,
                    execute,
                };
            }
            entries.push(DetailedEntry {
                name: client.name(id).await?,
                kind,
                size: metadata.size,
                permissions,
            });
        }
        Ok(entries)
    })
}

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tls [$DIR] [-l[h]]\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "ls");

    let list_dots = false;
    let mut list_details = false;
    let mut human_friendly = false;
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
                    b'h' => human_friendly = true,
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
        list_detailed(dir, list_dots, human_friendly);
    } else {
        list_plain(dir, list_dots);
    }
}

fn list_detailed(dir: &str, list_dots: bool, human_friendly: bool) {
    let path = match std::fs::canonicalize(Path::new(dir)) {
        Ok(path) => path,
        Err(_) => {
            eprintln!("error reading directory '{dir}'.\n");
            return;
        }
    };
    let mut entries = match read_detailed_entries(&path) {
        Ok(entries) => entries,
        Err(_) => {
            eprintln!("error reading directory '{dir}'.\n");
            return;
        }
    };

    let max_size = entries.iter().map(|entry| entry.size).max().unwrap_or(0);
    entries.sort_by(compare_detailed_entries);

    let size_len = max_size.to_string().len();

    let stdout_is_terminal = std::io::stdout().is_terminal();

    for entry in &entries {
        if (entry.name == "." || entry.name == "..") && !list_dots {
            continue;
        }
        let is_directory = entry.kind == DetailedEntryKind::Directory;
        let (color_in, color_out) = name_colors(is_directory, stdout_is_terminal);
        let permissions = permission_string(entry.kind, entry.permissions);
        if is_directory {
            println!(
                "{permissions} {:width$} {color_in}{}{color_out}",
                "",
                entry.name,
                width = size_len,
            );
        } else {
            println!(
                "{permissions} {:width$} {color_in}{}{color_out}",
                if human_friendly {
                    crate::format_bytes(entry.size)
                } else {
                    entry.size.to_string()
                },
                entry.name,
                width = size_len,
            );
        }
    }
}

fn list_plain(dir: &str, list_dots: bool) {
    let path = std::fs::canonicalize(Path::new(dir));
    if path.is_err() {
        eprintln!("error reading directory '{dir}' (1).\n");
        return;
    }
    let readdir = std::fs::read_dir(path.unwrap().as_path());
    if readdir.is_err() {
        eprintln!("error reading directory '{dir}' (2).\n");
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
        match (
            a.file_type().unwrap().is_dir(),
            b.file_type().unwrap().is_dir(),
        ) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => a.file_name().cmp(&b.file_name()),
        }
    });

    let stdout_is_terminal = std::io::stdout().is_terminal();

    for e in &entries {
        let ft = e.file_type().unwrap();
        let fname = e.file_name().to_str().unwrap().to_owned();
        if fname.as_str() == "." && !list_dots {
            continue;
        }
        if fname.as_str() == ".." && !list_dots {
            continue;
        }
        let (color_in, color_out) = name_colors(ft.is_dir(), stdout_is_terminal);
        if ft.is_dir() || ft.is_file() {
            print!("{color_in}{fname}{color_out} ");
        } else {
            print!("? {fname}");
        }
    }
    println!();
}
