use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn main() {
    if let Err(error) = run() {
        eprintln!("Motor Lorry cancellation probe: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = env::args_os().collect::<Vec<_>>();
    if env::var_os("LORRY_CANCEL_ROOT").is_some() {
        return wrapper(&args[1..]);
    }
    if args.len() != 3 {
        return Err("usage: cancel-probe LORRY FIXTURE-ROOT".to_owned());
    }
    let lorry = PathBuf::from(&args[1]);
    let root = PathBuf::from(&args[2]);
    if root.exists() {
        fs::remove_dir_all(&root).map_err(|error| error.to_string())?;
    }
    fs::create_dir_all(root.join("src")).map_err(|error| error.to_string())?;
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"cancel-probe-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .map_err(|error| error.to_string())?;
    fs::write(
        root.join("Cargo.lock"),
        "version = 4\n[[package]]\nname = \"cancel-probe-fixture\"\nversion = \"0.1.0\"\n",
    )
    .map_err(|error| error.to_string())?;
    let source = root.join("src/main.rs");
    fs::write(&source, "fn main() {}\n").map_err(|error| error.to_string())?;
    let wrapper = env::current_exe().map_err(|error| error.to_string())?;
    let build = || {
        let mut command = Command::new(&lorry);
        command
            .arg("build")
            .current_dir(&root)
            .env("RUSTC", &wrapper)
            .env("LORRY_CANCEL_ROOT", &root)
            .env("LORRY_CANCEL_REAL_RUSTC", "rustc")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    };
    if !build()
        .status()
        .map_err(|error| error.to_string())?
        .success()
    {
        return Err("baseline Lorry build failed".to_owned());
    }
    fs::write(&source, "fn main() { println!(\"recovered\"); }\n")
        .map_err(|error| error.to_string())?;
    fs::write(root.join("block"), b"").map_err(|error| error.to_string())?;
    let mut interrupted = build().spawn().map_err(|error| error.to_string())?;
    let entered = root.join("entered");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !entered.is_file() {
        if let Some(status) = interrupted.try_wait().map_err(|error| error.to_string())? {
            return Err(format!(
                "Lorry exited before its compiler entered: {status}"
            ));
        }
        if Instant::now() >= deadline {
            interrupted.kill().map_err(|error| error.to_string())?;
            let _ = interrupted.wait();
            return Err("compiler did not enter the controlled build".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let child_pid = fs::read_to_string(root.join("child.pid"))
        .map_err(|error| error.to_string())?
        .trim()
        .parse::<u32>()
        .map_err(|error| error.to_string())?;
    interrupted.kill().map_err(|error| error.to_string())?;
    interrupted.wait().map_err(|error| error.to_string())?;
    let alive = Command::new("/system/bin/rush")
        .args(["-c", &format!("kill -0 {child_pid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| error.to_string())?
        .success();
    fs::write(root.join("release"), b"").map_err(|error| error.to_string())?;
    if alive {
        return Err(format!(
            "compiler child {child_pid} survived its killed Lorry parent"
        ));
    }
    if !build()
        .status()
        .map_err(|error| error.to_string())?
        .success()
    {
        return Err("recovery Lorry build failed".to_owned());
    }
    let output = Command::new(root.join("target/lorry/debug/cancel-probe-fixture"))
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() || output.stdout != b"recovered\n" {
        return Err("recovered executable did not reflect the source edit".to_owned());
    }
    println!("PASS: Motor killed Lorry's compiler child and recovered the build");
    Ok(())
}

fn wrapper(args: &[std::ffi::OsString]) -> Result<(), String> {
    let root =
        PathBuf::from(env::var_os("LORRY_CANCEL_ROOT").ok_or("wrapper has no fixture root")?);
    if args.iter().any(|arg| arg == "--crate-name") && root.join("block").is_file() {
        fs::write(root.join("child.pid"), std::process::id().to_string())
            .map_err(|error| error.to_string())?;
        fs::write(root.join("entered"), b"").map_err(|error| error.to_string())?;
        while !root.join("release").is_file() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let real = env::var_os("LORRY_CANCEL_REAL_RUSTC").ok_or("wrapper has no real rustc")?;
    let status = Command::new(real)
        .args(args)
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("rustc exited with {status}"))
    }
}
