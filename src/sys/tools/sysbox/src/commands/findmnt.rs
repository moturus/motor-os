use moto_sdk::io::fs::{FsClient, MountInfo, MountKind};
use std::io::{Result, Write};

pub fn write_table(output: &mut impl Write, mounts: &mut [MountInfo]) -> Result<()> {
    mounts.sort_by_key(|mount| mount.id);
    writeln!(output, "ID TARGET FSTYPE STATE USED CAP ENTRIES")?;
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
        let state = if mount.corrupted {
            "quarantined"
        } else if mount.read_only {
            "ro"
        } else {
            "rw"
        };
        let number = |value: Option<u64>| value.map_or_else(|| "-".into(), |v| v.to_string());
        writeln!(
            output,
            "{} {path} {kind} {state} {} {} {}",
            mount.id,
            number(mount.used),
            number(mount.cap),
            number(mount.entries)
        )?;
    }
    Ok(())
}

pub fn do_command(args: &[String]) {
    if args.len() == 2 && matches!(args[1].as_str(), "-h" | "--help") {
        println!(
            "usage: findmnt\nList mounted filesystems; sizes are bytes, unknown values are '-'."
        );
        return;
    }
    if args.len() != 1 {
        eprintln!("usage: findmnt");
        std::process::exit(1);
    }
    let result = moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let client = FsClient::connect()?;
        client.mounts().await
    });
    let result = result
        .map_err(|error| std::io::Error::from_raw_os_error(error as u16 as i32))
        .and_then(|mut mounts| write_table(&mut std::io::stdout().lock(), &mut mounts));
    if let Err(error) = result {
        eprintln!("findmnt: {error}");
        std::process::exit(1);
    }
}
