//! Serve Git smart HTTP from the host's existing object cache, without sockets.
use super::*;
use std::process::{Command, Stdio};

pub fn prepare(cache: &Path, output: &Path, locks: &[std::ffi::OsString]) -> Result<(), String> {
    let mut sources = BTreeSet::new();
    for lock in locks {
        let text = fs::read_to_string(lock).map_err(|e| e.to_string())?;
        for line in text.lines() {
            if let Some(source) = line
                .strip_prefix("source = \"git+")
                .and_then(|s| s.strip_suffix('"'))
            {
                sources.insert(source.to_owned());
            }
        }
    }
    let mut mapping = String::new();
    for (index, source) in sources.iter().enumerate() {
        let (remote, commit) = source.rsplit_once('#').ok_or("Git source has no commit")?;
        let remote = remote.split('?').next().unwrap();
        if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Git fixture commit is invalid".into());
        }
        let mut database = None;
        for path in children(&cache.join("git/db"))? {
            if Command::new("git")
                .arg("--git-dir")
                .arg(&path)
                .args(["cat-file", "-e", &format!("{commit}^{{commit}}")])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|e| e.to_string())?
                .success()
            {
                database = Some(path);
                break;
            }
        }
        let database = database
            .ok_or_else(|| format!("Git commit {commit} is absent from Cargo's local cache"))?;
        let repository = output.join("git").join(index.to_string());
        let status = Command::new("git")
            .args(["clone", "--quiet", "--shared", "--bare"])
            .arg(database)
            .arg(&repository)
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("cannot prepare local Git fixture".into());
        }
        let status = Command::new("git")
            .arg("--git-dir")
            .arg(&repository)
            .args(["update-ref", "refs/heads/lorry-fixture", commit])
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("cannot advertise locked Git fixture commit".into());
        }
        mapping.push_str(&format!("{remote}\t{index}\n"));
    }
    fs::write(output.join("git-urls"), mapping).map_err(|e| e.to_string())
}

pub fn serve(
    root: &Path,
    arguments: &[std::ffi::OsString],
    url: &str,
    write_out: &str,
) -> Result<(), String> {
    let nonce = write_out
        .lines()
        .find_map(|line| line.strip_prefix("LORRY-CURL-GIT-1 "))
        .ok_or("Git control nonce is absent")?;
    let (remote, advertise) =
        if let Some(remote) = url.strip_suffix("/info/refs?service=git-upload-pack") {
            (remote, true)
        } else if let Some(remote) = url.strip_suffix("/git-upload-pack") {
            (remote, false)
        } else {
            return Err(format!("unprepared URL {url}"));
        };
    let mapping = fs::read_to_string(root.join("git-urls")).map_err(|e| e.to_string())?;
    let index = mapping
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .find_map(|(key, value)| (key == remote).then_some(value))
        .ok_or_else(|| format!("unprepared Git remote {remote}"))?;
    safe_relative(index)?;
    let mut command = Command::new("git");
    command.args(["upload-pack", "--stateless-rpc"]);
    if advertise {
        command.arg("--advertise-refs");
    }
    for pair in arguments.windows(2) {
        if pair[0] == "--header"
            && let Some(protocol) = pair[1]
                .to_str()
                .and_then(|s| s.strip_prefix("Git-Protocol: "))
        {
            command.env("GIT_PROTOCOL", protocol);
        }
    }
    let response = command
        .arg(root.join("git").join(index))
        .stdin(if advertise {
            Stdio::null()
        } else {
            Stdio::inherit()
        })
        .output()
        .map_err(|e| e.to_string())?;
    if !response.status.success() {
        return Err(format!(
            "local upload-pack failed: {}",
            String::from_utf8_lossy(&response.stderr)
        ));
    }
    let mut body = Vec::new();
    if advertise {
        body.extend_from_slice(b"001e# service=git-upload-pack\n0000");
    }
    body.extend_from_slice(&response.stdout);
    io::stdout().write_all(&body).map_err(|e| e.to_string())?;
    let kind = if advertise { "advertisement" } else { "result" };
    eprint!(
        "\nLORRY-CURL-GIT-1 {nonce}\nstatus=200\nurl={url}\nredirect=\ntype=application/x-git-upload-pack-{kind}\nsize={}\nEND-LORRY-CURL-GIT-1 {nonce}\n",
        body.len()
    );
    Ok(())
}
