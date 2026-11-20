use moto_sdk::io::fs::{FsClient, MountInfo, MountKind};
use std::io::{Result, Write};

pub fn write_table(
    output: &mut impl Write,
    mounts: &mut [MountInfo],
    human_friendly: bool,
) -> Result<()> {
    mounts.sort_by_key(|mount| mount.id);
    let mut rows = vec![[
        "ID", "TARGET", "SOURCE", "FSTYPE", "STATE", "USED", "CAP", "ENTRIES",
    ]
    .map(str::to_owned)];
    for mount in mounts {
        let mut path = String::new();
        for byte in mount.path.bytes() {
            if byte == b' ' {
                path.push_str("\\x20");
            } else {
                path.extend(byte.escape_ascii().map(char::from));
            }
        }
        let kind = match mount.kind {
            MountKind::MotorFs => "motor-fs",
            MountKind::MemFs => "memfs",
        };
        let source = mount.source.map_or_else(
            || "-".into(),
            |source| match source.partition {
                Some(slot) => format!("virtio{}p{slot}", source.device),
                None => format!("virtio{}", source.device),
            },
        );
        let state = if mount.corrupted {
            "quarantined"
        } else if mount.read_only {
            "ro"
        } else {
            "rw"
        };
        let number = |value: Option<u64>, human: bool| {
            value.map_or_else(
                || "-".into(),
                |value| {
                    if human {
                        crate::format_bytes(value)
                    } else {
                        value.to_string()
                    }
                },
            )
        };
        rows.push([
            mount.id.to_string(),
            path,
            source,
            kind.into(),
            state.into(),
            number(mount.used, human_friendly),
            number(mount.cap, human_friendly),
            number(mount.entries, false),
        ]);
    }

    // Measure escaped paths and formatted sizes so every column fits its contents.
    let mut widths = [0; 8];
    for row in &rows {
        for (width, value) in widths.iter_mut().zip(row) {
            *width = (*width).max(value.len());
        }
    }
    for row in &rows {
        for (column, (value, width)) in row.iter().zip(widths).enumerate() {
            if column != 0 {
                write!(output, " ")?;
            }
            if matches!(column, 0 | 5..=7) {
                write!(output, "{value:>width$}")?;
            } else {
                write!(output, "{value:<width$}")?;
            }
        }
        writeln!(output)?;
    }
    Ok(())
}

pub fn do_command(args: &[String]) {
    if args.len() == 2 && args[1] == "--help" {
        println!(
            "usage: findmnt [-h]\nList mounted filesystems; sizes are bytes, unknown values are '-'.\n  -h      show sizes in powers of 1024 (K, M, G, T).\n  --help  show this help."
        );
        return;
    }
    let human_friendly = match args {
        [_] => false,
        [_, flag] if flag == "-h" => true,
        _ => {
            eprintln!("usage: findmnt [-h]");
            std::process::exit(1);
        }
    };
    let result = moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let client = FsClient::connect()?;
        client.mounts().await
    });
    let result = result
        .map_err(|error| std::io::Error::from_raw_os_error(error as u16 as i32))
        .and_then(|mut mounts| {
            write_table(&mut std::io::stdout().lock(), &mut mounts, human_friendly)
        });
    if let Err(error) = result {
        eprintln!("findmnt: {error}");
        std::process::exit(1);
    }
}
