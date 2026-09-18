use std::{
    io,
    process::{Command, Stdio},
};

use gix::{
    bstr::{BStr, ByteSlice},
    url::{ArgumentSafety, Scheme, Url},
};
use gix_transport::Service;

#[cfg(target_os = "motor")]
const SSH_PROGRAM: &str = "/user/bin/ssh";
#[cfg(not(target_os = "motor"))]
const SSH_PROGRAM: &str = "/usr/bin/ssh";

/// A validated SSH destination and fixed command preparation.
#[derive(Debug)]
pub struct Prepared {
    url: Url,
    destination: String,
    repository: gix::bstr::BString,
    quoted_repository: String,
}

impl Prepared {
    /// Validate an SSH URL before it can reach a child process.
    pub fn new(url: Url) -> crate::Result<Self> {
        if url.scheme != Scheme::Ssh {
            return Err(invalid("only SSH URLs are accepted"));
        }
        if url.password.is_some() {
            return Err(invalid("passwords in SSH URLs are not supported"));
        }
        if url.port == Some(0) {
            return Err(invalid("SSH port must be nonzero"));
        }

        let host = match url.host_as_argument() {
            ArgumentSafety::Usable(host) => host,
            ArgumentSafety::Absent => return Err(invalid("SSH URL has no host")),
            ArgumentSafety::Dangerous(_) => {
                return Err(invalid("SSH host cannot begin with '-'"));
            }
        };
        if host.bytes().any(|byte| b"@[]".contains(&byte)) {
            return Err(invalid(
                "SSH host contains a reserved destination delimiter",
            ));
        }
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        let destination = match url.user_as_argument() {
            ArgumentSafety::Usable(user) => format!("{user}@{host}"),
            ArgumentSafety::Absent => host,
            ArgumentSafety::Dangerous(_) => {
                return Err(invalid("SSH user cannot begin with '-'"));
            }
        };
        if destination.as_bytes().contains(&0) {
            return Err(invalid("SSH destination contains NUL"));
        }

        let path = url.path.as_bstr();
        if path.is_empty() {
            return Err(invalid("SSH URL has no repository path"));
        }
        if path.contains(&0) {
            return Err(invalid("SSH repository path contains NUL"));
        }
        if path.trim().first() == Some(&b'-') {
            return Err(invalid("SSH repository path cannot begin with '-'"));
        }
        path.to_str().map_err(|source| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("SSH repository path is not UTF-8: {source}"),
            )
        })?;
        let repository = gix::url::expand_path::for_shell(url.path.clone());
        let quoted_repository = gix_quote::single(repository.as_bstr())
            .to_str()
            .expect("quoting UTF-8 produces UTF-8")
            .to_owned();

        Ok(Self {
            url,
            destination,
            repository,
            quoted_repository,
        })
    }

    /// Create the fixed SSH child command for one Git service.
    pub fn command(&self, service: Service) -> Command {
        let mut command = Command::new(SSH_PROGRAM);
        command
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .args([
                "-F",
                "/dev/null",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=30",
            ]);
        if let Some(user) = std::env::var_os("USER") {
            command.env("USER", user);
        }
        if let Some(port) = self.url.port {
            command.args(["-p", &port.to_string()]);
        }
        command
            .arg(&self.destination)
            .arg(service.as_str())
            .arg(&self.quoted_repository)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    /// The canonical URL reported to Gitoxide.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The decoded, shell-style repository path used by the process connection.
    pub fn repository(&self) -> &BStr {
        self.repository.as_bstr()
    }
}

fn invalid(message: &'static str) -> Box<dyn std::error::Error + Send + Sync> {
    io::Error::new(io::ErrorKind::InvalidInput, message).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: &str) -> crate::Result<Url> {
        Ok(gix::url::parse(value.as_bytes().as_bstr())?)
    }

    #[test]
    fn fixed_invocation_quotes_paths_and_forwards_only_user() -> crate::Result {
        let prepared = Prepared::new(parse(
            "ssh://alice@[2001:db8::1]:2222/srv/repo%20name's.git",
        )?)?;
        let command = prepared.command(Service::UploadPack);
        assert_eq!(command.get_program(), SSH_PROGRAM);
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "-F",
                "/dev/null",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=30",
                "-p",
                "2222",
                "alice@[2001:db8::1]",
                "git-upload-pack",
                r#"'/srv/repo name'\''s.git'"#,
            ]
        );
        assert!(!args.iter().any(|arg| arg.contains("SendEnv")));
        let inherited = command
            .get_envs()
            .filter_map(|(name, value)| value.map(|value| (name, value)))
            .filter(|(name, _)| *name != "LANG" && *name != "LC_ALL")
            .collect::<Vec<_>>();
        match std::env::var_os("USER") {
            Some(user) => {
                assert_eq!(inherited.len(), 1);
                assert_eq!(inherited[0].0, std::ffi::OsStr::new("USER"));
                assert_eq!(inherited[0].1, user.as_os_str());
            }
            None => assert!(inherited.is_empty()),
        }
        assert_eq!(prepared.repository(), b"/srv/repo name's.git".as_bstr());

        let default_user = Prepared::new(parse("ssh://host/repo")?)?
            .command(Service::ReceivePack)
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            &default_user[default_user.len() - 3..],
            ["host", "git-receive-pack", "'/repo'"]
        );
        Ok(())
    }

    #[test]
    fn rejects_unsafe_or_unsupported_urls() -> crate::Result {
        for value in [
            "https://host/repo",
            "ssh://user:secret@host/repo",
            "ssh://-user@host/repo",
            "ssh://user@-host/repo",
            "ssh://user@ho%40st/repo",
            "ssh://user@%5B%5Bhost%5D%5D/repo",
            "ssh://user@ho%00st/repo",
            "ssh://user@host:0/repo",
            "ssh://host/re%00po",
            "user@host:-repo",
        ] {
            let url = parse(value)?;
            assert!(Prepared::new(url).is_err(), "{value} must be rejected");
        }
        let mut non_utf8 = parse("ssh://host/repo")?;
        non_utf8.path = vec![0xff].into();
        assert!(Prepared::new(non_utf8).is_err());
        Ok(())
    }
}
