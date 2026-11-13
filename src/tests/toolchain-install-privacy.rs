//! Watch a real toolchain installation from the None role without logging secrets.
use std::io::{self, BufRead, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn check_file(path: &std::path::Path) -> io::Result<()> {
    const MARKER: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----";
    let mut input = io::BufReader::new(std::fs::File::open(path)?);
    let mut line = Vec::new();
    // Inspect each line as it arrives: deletion later must not discard evidence
    // already read from the start of a temporary file.
    while input.read_until(b'\n', &mut line)? != 0 {
        if line.windows(MARKER.len()).any(|value| value == MARKER) {
            return Err(io::Error::other("None read SSH private-key data"));
        }
        line.clear();
    }
    Ok(())
}

fn scan() -> io::Result<usize> {
    let mut invalidated = 0;
    for directory in ["/user/cfg", "/none/tmp"] {
        for entry in std::fs::read_dir(directory).map_err(|error| {
            io::Error::new(error.kind(), format!("open directory {directory}: {error}"))
        })? {
            let entry = match entry {
                Ok(entry) => entry,
                // Motor readdir exhausts its cursor if a pending entry is
                // removed (rt_fs.rs). Record that interruption of this sample;
                // the watch loop starts each subsequent sample with new cursors.
                Err(error) if error.raw_os_error() == Some(7) => {
                    invalidated += 1;
                    break;
                }
                Err(error) => return Err(error),
            };
            match entry.file_type() {
                Ok(kind) if kind.is_file() => {}
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("stat {}: {error}", entry.path().display()),
                    ));
                }
            }
            match check_file(&entry.path()) {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                    ) => {}
                // A temporary file can also vanish after open, invalidating
                // its Motor file handle. Only accept that if the name is gone.
                Err(error)
                    if error.kind() == io::ErrorKind::InvalidInput
                        && !entry.path().try_exists()? =>
                {
                    invalidated += 1;
                }
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("read {}: {error}", entry.path().display()),
                    ));
                }
            }
        }
    }
    Ok(invalidated)
}

fn main() -> io::Result<()> {
    match std::fs::read("/user/cfg/sshd.toml") {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {}
        _ => {
            return Err(io::Error::other(
                "SSH configuration must be private before installation",
            ));
        }
    }
    scan()?;
    println!("ready");
    io::stdout().flush()?;
    let done = Arc::new(AtomicBool::new(false));
    let input_done = done.clone();
    let input = std::thread::spawn(move || {
        let mut line = String::new();
        let result = io::stdin().lock().read_line(&mut line);
        input_done.store(true, Ordering::Relaxed);
        result.map(|_| line == "done\n").map_err(|error| {
            io::Error::new(error.kind(), format!("read observer control pipe: {error}"))
        })
    });
    let mut scans = 0;
    let mut invalidated = 0;
    while !done.load(Ordering::Relaxed) {
        let interruptions = scan()?;
        invalidated += interruptions;
        if interruptions == 0 {
            scans += 1;
        }
        std::thread::yield_now();
    }
    if !input.join().expect("stdin reader panicked")? || scans == 0 {
        return Err(io::Error::other(
            "privacy observation ended without completion",
        ));
    }
    println!(
        "installer privacy: {scans} complete scans, {invalidated} vanished entries; no readable SSH key"
    );
    Ok(())
}
