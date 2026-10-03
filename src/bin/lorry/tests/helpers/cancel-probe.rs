use std::env;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn main() {
    if let Err(error) = run() {
        eprintln!("Motor Lorry cancellation probe: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = env::args_os().collect::<Vec<_>>();
    if let Some(root) = env::var_os("LORRY_HOLD_CHILD_ROOT") {
        return hold_child(PathBuf::from(root));
    }
    if let Some(root) = env::var_os("LORRY_HOLD_ROOT") {
        return hold_owner(PathBuf::from(root));
    }
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
    drop(interrupted);
    fs::remove_file(root.join("block")).map_err(|error| error.to_string())?;
    let mut recovery = build().spawn().map_err(|error| error.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while process_alive(child_pid)? {
        if Instant::now() >= deadline {
            fs::write(root.join("release"), b"").map_err(|error| error.to_string())?;
            return Err(format!("compiler child {child_pid} did not terminate"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !wait_success(&mut recovery, deadline)? {
        return Err("recovery Lorry build failed".to_owned());
    }
    let output = Command::new(root.join("target/lorry/debug/cancel-probe-fixture"))
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() || output.stdout != b"recovered\n" {
        return Err("recovered executable did not reflect the source edit".to_owned());
    }
    verify_held_owner(&root, &build, &source)?;
    println!("PASS: Motor waited for killed and held compiler children before recovery");
    Ok(())
}

fn process_alive(pid: u32) -> Result<bool, String> {
    Command::new("/system/bin/rush")
        .args(["-c", &format!("kill -0 {pid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .map_err(|error| error.to_string())
}

fn wait_success(child: &mut Child, deadline: Instant) -> Result<bool, String> {
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            return Err("process did not finish the controlled recovery".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn verify_held_owner(
    root: &Path,
    build: &impl Fn() -> Command,
    source: &Path,
) -> Result<(), String> {
    let helper = env::current_exe().map_err(|error| error.to_string())?;
    let mut holder = Command::new(helper)
        .env("LORRY_HOLD_ROOT", root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while !root.join("hold-ready").is_file() {
        if let Some(status) = holder.try_wait().map_err(|error| error.to_string())? {
            return Err(format!("synthetic owner exited before readiness: {status}"));
        }
        if Instant::now() >= deadline {
            return Err("synthetic owner did not become ready".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let owner = format!("{}\n", holder.id());
    let marker = root.join("target/.lorry-artifacts.owner");
    fs::write(&marker, &owner).map_err(|error| error.to_string())?;
    fs::write(
        source,
        "fn main() { println!(\"held-owner-recovered\"); }\n",
    )
    .map_err(|error| error.to_string())?;
    let mut blocked = build().spawn().map_err(|error| error.to_string())?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("target/.lorry-artifacts.lock"))
        .map_err(|error| error.to_string())?;
    loop {
        match lock.try_lock() {
            Ok(()) => lock.unlock().map_err(|error| error.to_string())?,
            Err(std::fs::TryLockError::WouldBlock) => break,
            Err(error) => return Err(format!("could not query artifact lock: {error}")),
        }
        if let Some(status) = blocked.try_wait().map_err(|error| error.to_string())? {
            return Err(format!(
                "recovery exited before acquiring the lock: {status}"
            ));
        }
        if Instant::now() >= deadline {
            return Err("recovery did not acquire the artifact lock".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(200));
    if blocked
        .try_wait()
        .map_err(|error| error.to_string())?
        .is_some()
        || fs::read_to_string(&marker).map_err(|error| error.to_string())? != owner
    {
        return Err("recovery passed an active prior owner's child".to_owned());
    }
    fs::write(root.join("hold-release"), b"").map_err(|error| error.to_string())?;
    if !wait_success(&mut holder, deadline)? || !wait_success(&mut blocked, deadline)? {
        return Err("recovery did not finish after the prior child exited".to_owned());
    }
    let output = Command::new(root.join("target/lorry/debug/cancel-probe-fixture"))
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() || output.stdout != b"held-owner-recovered\n" {
        return Err("published binary did not reflect the held-owner recovery".to_owned());
    }
    Ok(())
}

fn hold_owner(root: PathBuf) -> Result<(), String> {
    let helper = env::current_exe().map_err(|error| error.to_string())?;
    let status = Command::new(helper)
        .env("LORRY_HOLD_CHILD_ROOT", root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("synthetic child exited with {status}"))
    }
}

fn hold_child(root: PathBuf) -> Result<(), String> {
    fs::write(root.join("hold-ready"), b"").map_err(|error| error.to_string())?;
    while !root.join("hold-release").is_file() {
        std::thread::sleep(Duration::from_millis(10));
    }
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
