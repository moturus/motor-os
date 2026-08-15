//! Development-only wrapper for reproducible Gears baseline measurements.

#[cfg(not(unix))]
use std::process::Stdio;
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    if first.as_deref() == Some("--quality-policy") {
        return quality_policy(args);
    }
    let sample_memory = match first.as_deref() {
        Some("--") => false,
        Some("--memory") if args.next().as_deref() == Some("--") => true,
        _ => {
            eprintln!("usage: gears-measure [--memory] -- COMMAND [ARG ...]");
            return ExitCode::from(2);
        }
    };
    let Some(program) = args.next() else {
        eprintln!("gears-measure: missing command");
        return ExitCode::from(2);
    };

    let started = Instant::now();
    let mut child = match Command::new(program).args(args).spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("gears-measure: cannot start command: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut peak_memory = None;
    let status = if sample_memory {
        loop {
            if let Some(bytes) = memory_bytes(child.id()) {
                peak_memory = Some(peak_memory.unwrap_or(0).max(bytes));
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => std::thread::sleep(Duration::from_millis(2)),
                Err(error) => {
                    eprintln!("gears-measure: cannot wait for command: {error}");
                    return ExitCode::FAILURE;
                }
            }
        }
    } else {
        match child.wait() {
            Ok(status) => status,
            Err(error) => {
                eprintln!("gears-measure: cannot wait for command: {error}");
                return ExitCode::FAILURE;
            }
        }
    };

    println!("elapsed_us={}", started.elapsed().as_micros());
    if sample_memory {
        match peak_memory {
            Some(bytes) => println!("peak_memory_bytes={bytes}"),
            None => println!("peak_memory_bytes=unavailable"),
        }
    }
    status.code().map_or(ExitCode::FAILURE, |code| {
        u8::try_from(code).map_or(ExitCode::FAILURE, ExitCode::from)
    })
}

fn quality_policy(mut args: impl Iterator<Item = String>) -> ExitCode {
    let config = match args.next().as_deref() {
        None => gears::config::Config::parse("version = 1"),
        Some("--config") => match args.next() {
            Some(path) if args.next().is_none() => {
                gears::config::Config::load(Some(std::path::Path::new(&path)))
            }
            _ => {
                eprintln!("usage: gears-measure --quality-policy [--config FILE]");
                return ExitCode::from(2);
            }
        },
        Some(_) => {
            eprintln!("usage: gears-measure --quality-policy [--config FILE]");
            return ExitCode::from(2);
        }
    };
    let config = match config {
        Ok(config) => config,
        Err(error) => {
            eprintln!("gears-measure: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "max_regression_percent={}",
        config.quality.max_regression_percent
    );
    println!("stable_samples={}", config.quality.stable_samples);
    println!(
        "render_queue_depth_events={}",
        gears::agent::EVENT_QUEUE_CAPACITY
    );
    ExitCode::SUCCESS
}

#[cfg(unix)]
fn memory_bytes(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|line| line.starts_with("VmHWM:"))?;
    line.split_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()?
        .checked_mul(1024)
}

#[cfg(not(unix))]
fn memory_bytes(pid: u32) -> Option<u64> {
    let output = Command::new("pstat")
        .arg(pid.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output.status.success().then_some(())?;
    let text = std::str::from_utf8(&output.stdout).ok()?;
    let line = text
        .lines()
        .find(|line| line.split_whitespace().next() == Some("memory_usage"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}
