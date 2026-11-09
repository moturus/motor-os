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
        // The triplets are in System, Interactive, None order. System owns
        // installed content and may execute files that no lower role can.
        self.kind == DetailedEntryKind::File
            && self.permissions[1..]
                .iter()
                .any(|permission| permission.execute)
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
    metadata: &moto_sdk::io::fs::Metadata,
) -> moto_rt::Result<DetailedEntry> {
    use moto_sdk::io::fs::{EntryKind, Role};

    // Std builds of the SDK report a corrupt metadata byte as a std error.
    let corrupt = |_| moto_rt::Error::InvalidData;
    let kind = match metadata.try_kind().map_err(corrupt)? {
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
        let (read, write, execute) = metadata.access(role).map_err(corrupt)?.triple();
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

/// Whether a per-entry request failed because the entry was removed while
/// listing: motor-fs reports a freed entry block as InvalidArgument and a
/// reused one as InvalidData.
fn entry_vanished(err: moto_rt::Error) -> bool {
    matches!(
        err,
        moto_rt::Error::InvalidArgument | moto_rt::Error::InvalidData
    )
}

/// One walk of a directory. Entries removed after their successor was fetched
/// are skipped; an entry removed before that strands the cursor, and the
/// error it produced is returned.
async fn walk_dir(
    client: &std::rc::Rc<moto_sdk::io::fs::FsClient>,
    dir: moto_sdk::io::fs::EntryId,
) -> moto_rt::Result<Vec<DetailedEntry>> {
    let mut entries = Vec::new();
    let mut entry_id = client.get_first_entry(dir).await?;
    while let Some(id) = entry_id {
        // Fetch the successor first, as std::fs::read_dir does, so a
        // concurrently removed current entry cannot strand the cursor.
        entry_id = client.get_next_entry(id).await?;
        let metadata = match client.metadata(id).await {
            Ok(metadata) => metadata,
            Err(err) if entry_vanished(err) => continue,
            Err(err) => return Err(err),
        };
        let name = match client.name(id).await {
            Ok(name) => name,
            Err(err) if entry_vanished(err) => continue,
            Err(err) => return Err(err),
        };
        entries.push(detailed_entry(name, &metadata)?);
    }
    Ok(entries)
}

/// What one operand names: a file lists itself, a directory its entries.
enum Listing {
    File(DetailedEntry),
    Directory(Vec<DetailedEntry>),
}

async fn read_operand(
    client: &std::rc::Rc<moto_sdk::io::fs::FsClient>,
    operand: &str,
    path: &str,
) -> moto_rt::Result<Listing> {
    use moto_sdk::io::fs::EntryKind;

    let (id, kind) = client.stat(path).await?;
    // A file operand lists itself, named as it was typed, as ls(1) does.
    if kind == EntryKind::File {
        let metadata = client.metadata(id).await?;
        return Ok(Listing::File(detailed_entry(
            operand.to_owned(),
            &metadata,
        )?));
    }

    // A stranded cursor means the directory changed under the walk;
    // start over a bounded number of times, then report it.
    const WALKS: usize = 3;
    for walk in 1..=WALKS {
        match walk_dir(client, id).await {
            Err(err) if entry_vanished(err) && walk < WALKS => continue,
            result => return result.map(Listing::Directory),
        }
    }
    unreachable!()
}

/// Reads every operand over one file-system connection. An operand that
/// cannot be read yields `None`; the caller reports it and carries on.
fn read_operands(operands: &[&str]) -> Vec<Option<Listing>> {
    use moto_sdk::io::fs::FsClient;

    let paths: Vec<Option<String>> = operands
        .iter()
        .map(|operand| {
            std::fs::canonicalize(Path::new(operand))
                .ok()
                .and_then(|path| path.to_str().map(str::to_owned))
        })
        .collect();
    let operands: Vec<String> = operands.iter().map(|&operand| operand.to_owned()).collect();

    moto_sdk::async_runtime::LocalRuntime::new().block_on(async move {
        let mut listings = Vec::with_capacity(operands.len());
        let client = FsClient::connect().ok();
        for (operand, path) in operands.iter().zip(&paths) {
            let listing = match (&client, path) {
                (Some(client), Some(path)) => read_operand(client, operand, path).await.ok(),
                _ => None,
            };
            listings.push(listing);
        }
        listings
    })
}

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tls [-alh] [--] [FILE ...]\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "ls");

    let mut format = Format {
        details: false,
        human_friendly: false,
        stdout_is_terminal: std::io::stdout().is_terminal(),
    };
    let mut operands: Vec<&str> = Vec::new();
    let mut parse_options = true;

    // Operands are taken as typed: trimming or dropping them would rename
    // files with surrounding spaces and turn an empty operand into `.`.
    for arg in &args[1..] {
        if parse_options && arg == "--" {
            parse_options = false;
            continue;
        }

        // A lone `-` is an operand, as in ls(1).
        if parse_options && arg.len() > 1 && arg.starts_with('-') {
            for char in arg.bytes().skip(1) {
                match char {
                    b'l' => format.details = true,
                    b'h' => format.human_friendly = true,
                    // Motor FS has no hidden entries, so every listing is
                    // already complete; accepted for ls(1) compatibility.
                    b'a' => {}
                    _ => {
                        print_usage_and_exit(1);
                    }
                }
            }
        } else {
            operands.push(arg);
        }
    }

    if operands.is_empty() {
        operands.push(".");
    }

    // ls(1) exits with 2 when a command-line operand cannot be accessed, but
    // still lists the others: files first, then each directory under a
    // heading when more than one operand was given.
    let mut status = 0;
    let mut files = Vec::new();
    let mut directories = Vec::new();
    for (operand, listing) in operands.iter().zip(read_operands(&operands)) {
        match listing {
            None => {
                eprintln!("error reading directory '{operand}'.");
                status = 2;
            }
            Some(Listing::File(entry)) => files.push(entry),
            Some(Listing::Directory(entries)) => directories.push((*operand, entries)),
        }
    }

    let headings = operands.len() > 1;
    let mut first_group = true;
    if !files.is_empty() {
        files.sort_by(compare_detailed_entries);
        print_entries(&files, &format);
        first_group = false;
    }
    directories.sort_by(|a, b| a.0.cmp(b.0));
    for (operand, mut entries) in directories {
        if !first_group {
            println!();
        }
        if headings {
            println!("{operand}:");
        }
        entries.sort_by(compare_detailed_entries);
        print_entries(&entries, &format);
        first_group = false;
    }

    if status != 0 {
        std::process::exit(status);
    }
}

struct Format {
    details: bool,
    human_friendly: bool,
    stdout_is_terminal: bool,
}

/// Prints one group of sorted entries; `-l` sizes are right-aligned within
/// the group, as ls(1) does.
fn print_entries(entries: &[DetailedEntry], format: &Format) {
    if !format.details {
        for entry in entries {
            let is_directory = entry.kind == DetailedEntryKind::Directory;
            let (color_in, color_out) = name_colors(
                is_directory,
                entry.is_executable(),
                format.stdout_is_terminal,
            );
            print!("{color_in}{}{color_out} ", entry.name);
        }
        println!();
        return;
    }

    let max_size = entries.iter().map(|entry| entry.size).max().unwrap_or(0);
    let size_len = max_size.to_string().len();
    for entry in entries {
        let is_directory = entry.kind == DetailedEntryKind::Directory;
        let (color_in, color_out) = name_colors(
            is_directory,
            entry.is_executable(),
            format.stdout_is_terminal,
        );
        let permissions = permission_string(entry.kind, entry.permissions);
        let size = if is_directory {
            String::new()
        } else if format.human_friendly {
            crate::format_bytes(entry.size)
        } else {
            entry.size.to_string()
        };
        println!(
            "{permissions} {size:>width$} {color_in}{}{color_out}",
            entry.name,
            width = size_len,
        );
    }
}
