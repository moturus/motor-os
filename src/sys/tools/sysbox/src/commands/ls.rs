use std::{cmp::Ordering, io::IsTerminal, path::Path};

// const DIRECTORY_COLOR: &str = "\x1b[1;38;5;214m"; // Bold orange.
const DIRECTORY_COLOR: &str = "\x1b[38;5;214m"; // Orange.
const EXECUTABLE_COLOR: &str = "\x1b[91m"; // Bright red.
const COLOR_RESET: &str = "\x1b[0m";

fn name_colors(
    is_directory: bool,
    is_executable: bool,
    stdout_is_terminal: bool,
) -> (&'static str, &'static str) {
    if !stdout_is_terminal {
        ("", "")
    } else if is_directory {
        (DIRECTORY_COLOR, COLOR_RESET)
    } else if is_executable {
        (EXECUTABLE_COLOR, COLOR_RESET)
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

impl DetailedEntry {
    fn is_executable(&self) -> bool {
        self.kind == DetailedEntryKind::File
            && self.permissions.iter().any(|permission| permission.execute)
    }
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

fn detailed_entry(
    name: String,
    metadata: &moto_io::fs::Metadata,
) -> moto_rt::Result<DetailedEntry> {
    use moto_io::fs::{EntryKind, Role};

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
    Ok(DetailedEntry {
        name,
        kind,
        size: metadata.size,
        permissions,
    })
}

fn read_entries(operand: &str, path: &Path) -> moto_rt::Result<Vec<DetailedEntry>> {
    use moto_io::fs::{EntryKind, FsClient};

    let path = path
        .to_str()
        .ok_or(moto_rt::Error::InvalidArgument)?
        .to_owned();
    let operand = operand.to_owned();

    moto_async::LocalRuntime::new().block_on(async move {
        let client = FsClient::connect()?;
        let (id, kind) = client.stat(&path).await?;
        // A file operand lists itself, named as it was typed, as ls(1) does.
        if kind == EntryKind::File {
            let metadata = client.metadata(id).await?;
            return Ok(vec![detailed_entry(operand, &metadata)?]);
        }

        let mut entries = Vec::new();
        let mut entry_id = client.get_first_entry(id).await?;
        while let Some(id) = entry_id {
            // Fetch the successor first, as std::fs::read_dir does, so a
            // concurrently removed current entry cannot strand the cursor.
            entry_id = client.get_next_entry(id).await?;
            let metadata = client.metadata(id).await?;
            entries.push(detailed_entry(client.name(id).await?, &metadata)?);
        }
        Ok(entries)
    })
}

// ls(1) exits with 2 when a command-line operand cannot be accessed.
fn operand_error_exit(operand: &str) -> ! {
    eprintln!("error reading directory '{operand}'.\n");
    std::process::exit(2);
}

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tls [-lh] [--] [DIR]\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "ls");

    let list_dots = false;
    let mut list_details = false;
    let mut human_friendly = false;
    let mut dir: Option<&str> = None;
    let mut parse_options = true;

    for arg in &args[1..] {
        if arg.trim().is_empty() {
            continue;
        }

        let arg = arg.trim();
        if parse_options && arg == "--" {
            parse_options = false;
            continue;
        }

        let bytes = arg.as_bytes();
        if parse_options && bytes[0] == b'-' {
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
            dir = Some(arg);
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
        Err(_) => operand_error_exit(dir),
    };
    let mut entries = match read_entries(dir, &path) {
        Ok(entries) => entries,
        Err(_) => operand_error_exit(dir),
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
        let (color_in, color_out) =
            name_colors(is_directory, entry.is_executable(), stdout_is_terminal);
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
    let path = match std::fs::canonicalize(Path::new(dir)) {
        Ok(path) => path,
        Err(_) => operand_error_exit(dir),
    };
    let mut entries = match read_entries(dir, &path) {
        Ok(entries) => entries,
        Err(_) => operand_error_exit(dir),
    };
    entries.sort_by(compare_detailed_entries);

    let stdout_is_terminal = std::io::stdout().is_terminal();

    for entry in &entries {
        if (entry.name == "." || entry.name == "..") && !list_dots {
            continue;
        }
        let is_directory = entry.kind == DetailedEntryKind::Directory;
        let (color_in, color_out) =
            name_colors(is_directory, entry.is_executable(), stdout_is_terminal);
        print!("{color_in}{}{color_out} ", entry.name);
    }
    println!();
}
