use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

pub(super) struct Remote {
    pub(super) repository: PathBuf,
    pub(super) deadline: Instant,
}

impl Remote {
    fn command(&self, program: &str) -> io::Result<Command> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "native acceptance deadline"))?;
        let mut command = Command::new("timeout");
        command
            .arg(format!("{:.3}", remaining.as_secs_f64()))
            .arg(program);
        command.args([
            "-F",
            "/dev/null",
            if program == "ssh" { "-p" } else { "-P" },
            "2222",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
        ]);
        command.arg("-o").arg(format!(
            "UserKnownHostsFile={}",
            self.repository.join("src/tests/test-known-hosts").display()
        ));
        command
            .arg("-i")
            .arg(self.repository.join("src/tests/test.key"));
        Ok(command)
    }

    pub(super) fn ssh(&self, script: &str) -> io::Result<Command> {
        let mut command = self.command("ssh")?;
        command.arg("motor@192.168.4.2").arg(script);
        Ok(command)
    }

    pub(super) fn run(&self, script: &str) -> io::Result<Output> {
        checked(self.ssh(script)?.output()?)
    }

    pub(super) fn upload(&self, batch: &Path) -> io::Result<()> {
        checked(
            self.command("sftp")?
                .arg("-b")
                .arg(batch)
                .arg("motor@192.168.4.2")
                .output()?,
        )?;
        Ok(())
    }

    pub(super) fn write_text(&self, evidence: &Path, path: &Path, text: &str) -> io::Result<()> {
        let local = evidence.join("saved.rs");
        let batch = evidence.join("save.sftp");
        fs::write(&local, text)?;
        fs::write(
            &batch,
            format!("put {} {}\n", quoted(&local)?, quoted(path)?),
        )?;
        self.upload(&batch)
    }
}

pub(super) fn checked(output: Output) -> io::Result<Output> {
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "remote/transfer command failed: {}; {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(output)
}

pub(super) fn quoted(path: &Path) -> io::Result<String> {
    let path = path
        .to_str()
        .ok_or_else(|| io::Error::other("non-UTF-8 test path"))?;
    if path.contains(['\n', '\r', '"', '\\']) {
        return Err(io::Error::other("unsupported SFTP test path"));
    }
    Ok(format!("\"{path}\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sftp_paths_quote_spaces_and_unicode_but_reject_batch_injection() {
        assert_eq!(
            quoted(Path::new("/some path/café.rs")).unwrap(),
            "\"/some path/café.rs\""
        );
        for path in ["/bad\nput x y", "/bad\r", "/bad\"", "/bad\\"] {
            assert!(quoted(Path::new(path)).is_err());
        }
    }
}
