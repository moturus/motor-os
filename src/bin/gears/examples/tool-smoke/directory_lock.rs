//! Exercise the directory lock against actual Gears processes on both systems.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use gears::mock::MockServer;

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn smoke(gears: &Path) -> Result<(), String> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let root = std::env::temp_dir().join(format!("gears-lock-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&root).map_err(|error| error.to_string())?;
    let result = check(gears, &root);
    if result.is_ok() {
        std::fs::remove_dir_all(&root).map_err(|error| error.to_string())?;
    } else {
        eprintln!("directory-lock fixtures retained in {}", root.display());
    }
    result
}

fn check(gears: &Path, root: &Path) -> Result<(), String> {
    let server = MockServer::start(vec![]).map_err(|error| error.to_string())?;
    let key = root.join("key");
    std::fs::write(&key, "fixture-lock-key").map_err(|error| error.to_string())?;
    let config = root.join("gears.toml");
    std::fs::write(
        &config,
        format!(
            "version = 1\n[provider]\nbase_url = {:?}\nmodel = 'test/model'\napi_key_file = {:?}\n[net]\negress_allowlist = ['127.0.0.1']\nplain_http_allowlist = ['127.0.0.1']\n",
            server.url("/v1"), key,
        ),
    )
    .map_err(|error| error.to_string())?;
    let command = || {
        let mut command = Command::new(gears);
        command
            .arg("--config")
            .arg(&config)
            .arg("--workspace")
            .arg(root)
            .args(["--ephemeral", "--ui", "line"])
            .env("HOME", root)
            .env(gears::directory::ENV, root.join(".gears"))
            .env_remove("GEARS_LOCK_OWNER")
            .env_remove(gears::provider::KEY_ENV);
        command
    };
    let mut first = Running(
        command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| error.to_string())?,
    );
    let reader = reach_prompt(&mut first.0, "first")?;
    let second = command()
        .args(["-p", "second"])
        .output()
        .map_err(|error| error.to_string())?;
    let expected = format!(
        "Another gears session {} is running. Exiting.",
        first.0.id()
    );
    if second.status.success() || !String::from_utf8_lossy(&second.stderr).contains(&expected) {
        return Err(format!("second Gears replaced a live lock: {second:?}"));
    }
    if !server.requests().is_empty() {
        return Err("a refused Gears requested the model".into());
    }
    first
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"/quit\n")
        .map_err(|error| error.to_string())?;
    if !first.0.wait().map_err(|error| error.to_string())?.success() {
        return Err("first Gears failed to close".into());
    }
    reader
        .join()
        .map_err(|_| "prompt reader panicked")?
        .map_err(|error| error.to_string())?;
    // A killed owner releases the lock with its process; its file stays behind.
    let mut killed = Running(
        command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| error.to_string())?,
    );
    reach_prompt(&mut killed.0, "killed")?;
    drop(killed);
    if !root.join(".gears/gears.lock").is_file() {
        return Err("the lock file disappeared".into());
    }
    let mut next = command()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    next.stdin
        .take()
        .unwrap()
        .write_all(b"/quit\n")
        .map_err(|error| error.to_string())?;
    let next = next.wait_with_output().map_err(|error| error.to_string())?;
    if !next.status.success() {
        return Err(format!("Gears after a killed owner was refused: {next:?}"));
    }
    Ok(())
}

/// Waits for the line UI's prompt, then keeps draining the output.
fn reach_prompt(
    child: &mut Child,
    name: &str,
) -> Result<std::thread::JoinHandle<std::io::Result<u64>>, String> {
    let mut stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut prompt = [0; 7];
        let result = stdout.read_exact(&mut prompt).map(|()| prompt);
        let _ = sender.send(result);
        std::io::copy(&mut stdout, &mut std::io::sink())
    });
    let prompt = receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|error| format!("{name} Gears did not reach its prompt: {error}"))?
        .map_err(|error| error.to_string())?;
    if &prompt != b"gears> " {
        return Err(format!("unexpected {name} Gears prompt: {prompt:?}"));
    }
    Ok(reader)
}
