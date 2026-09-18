mod input;
mod session;

use std::{
    any::Any,
    borrow::Cow,
    error::Error,
    io::{self, Write},
    process::{ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use crate::cancellation::Cancellation;
use gix::{
    bstr::{BStr, ByteSlice},
    url::{ArgumentSafety, Scheme, Url},
};
use gix_transport::{Service, client};

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

use input::{DISCOVERY_BYTES, Input, SESSION_BYTES};
use session::{InputClosed, Session};

const MAX_SESSIONS: usize = 3;
type Sessions = [Option<Session>; MAX_SESSIONS];
type Connection =
    gix_transport::client::git::blocking_io::Connection<Input<ChildStdout>, ChildStdin>;

pub enum Finish {
    Complete,
    Abort,
}

/// Sole completion owner; factories receive a registrar instead.
pub struct Operation(Arc<Mutex<Group>>);

#[derive(Clone)]
pub struct Registrar {
    group: Arc<Mutex<Group>>,
    cancellation: Cancellation,
}

struct Group {
    accepting: bool,
    sessions: Sessions,
}

impl Operation {
    pub fn new(cancellation: &Cancellation) -> (Self, Registrar) {
        let group = Arc::new(Mutex::new(Group {
            accepting: true,
            sessions: std::array::from_fn(|_| None),
        }));
        (
            Self(group.clone()),
            Registrar {
                group,
                cancellation: cancellation.clone(),
            },
        )
    }

    fn take(&self) -> Sessions {
        let mut group = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        group.accepting = false;
        std::mem::replace(&mut group.sessions, std::array::from_fn(|_| None))
    }

    pub fn finish(self, finish: Finish) -> crate::Result {
        let sessions = self.take();
        let missing_close = matches!(finish, Finish::Complete)
            && sessions
                .iter()
                .flatten()
                .any(|session| !session.is_closed());
        if matches!(finish, Finish::Abort) || missing_close {
            stop_all(&sessions);
        }
        // Finish all children before terminal output can block or fail.
        let expected_stop = matches!(finish, Finish::Abort) || missing_close;
        let results = sessions.map(|session| session.map(|session| session.join(expected_stop)));
        let mut failure: Option<Box<dyn Error + Send + Sync>> = missing_close.then(|| {
            io::Error::other("SSH transport input was not closed before completion").into()
        });
        let mut stderr = io::stderr().lock();
        let mut wrote = false;
        for result in results.into_iter().flatten() {
            let result = result.and_then(|bytes| {
                if !bytes.is_empty() {
                    stderr.write_all(&bytes)?;
                    wrote = true;
                }
                Ok(())
            });
            if let Err(error) = result {
                append_failure(&mut failure, error);
            }
        }
        if wrote && let Err(error) = stderr.flush() {
            append_failure(&mut failure, error.into());
        }
        failure.map_or(Ok(()), Err)
    }
}

fn append_failure(
    failure: &mut Option<Box<dyn Error + Send + Sync>>,
    next: Box<dyn Error + Send + Sync>,
) {
    *failure = Some(match failure.take() {
        None => next,
        Some(previous) => {
            crate::network::Failure::with_secondary("additional SSH failure", previous, next).into()
        }
    });
}

fn stop_all(sessions: &Sessions) {
    for session in sessions.iter().flatten() {
        session.stop();
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        let sessions = self.take();
        stop_all(&sessions);
        // Session's Drop joins its supervisor after all stop flags are set.
        drop(sessions);
    }
}

impl Registrar {
    fn start(&self, command: Command) -> io::Result<(ChildStdout, ChildStdin, InputClosed)> {
        let mut group = self
            .group
            .lock()
            .map_err(|_| io::Error::other("SSH session registry was poisoned"))?;
        if !group.accepting {
            return Err(io::Error::other("SSH session registration is closed"));
        }
        let slot = group
            .sessions
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| io::Error::other("SSH operation exceeded its three-session limit"))?;
        let (session, startup) = Session::launch(command, &self.cancellation)?;
        let closed = session.input_closed();
        *slot = Some(session);
        drop(group);
        let (stdout, stdin) = startup.wait()?;
        Ok((stdout, stdin, closed))
    }
}

/// A fixed SSH connection, started only when Gitoxide selects the service.
pub struct Transport {
    prepared: Prepared,
    registrar: Registrar,
    canonical_url: gix::bstr::BString,
    connection: Option<(Service, Connection, InputClosed)>,
    response_limit: Arc<AtomicU64>,
}

impl Prepared {
    pub fn transport(self, registrar: Registrar) -> Transport {
        Transport {
            canonical_url: self.url.to_bstring(),
            prepared: self,
            registrar,
            connection: None,
            response_limit: Arc::new(AtomicU64::new(DISCOVERY_BYTES)),
        }
    }
}

impl client::TransportWithoutIO for Transport {
    fn to_url(&self) -> Cow<'_, BStr> {
        Cow::Borrowed(self.canonical_url.as_bstr())
    }

    fn connection_persists_across_multiple_requests(&self) -> bool {
        true
    }

    fn configure(&mut self, _config: &dyn Any) -> crate::Result {
        Ok(())
    }
}

impl client::blocking_io::Transport for Transport {
    fn handshake<'a>(
        &mut self,
        service: Service,
        extra_parameters: &'a [(&'a str, Option<&'a str>)],
    ) -> Result<client::blocking_io::SetServiceResponse<'_>, client::Error> {
        if let Some((previous, _, _)) = self.connection.as_ref() {
            if *previous != service {
                return Err(
                    io::Error::other("one SSH transport cannot change Git services").into(),
                );
            }
        } else {
            let (stdout, stdin, closed) = self.registrar.start(self.prepared.command(service))?;
            let connection = Connection::new(
                Input::new(stdout, self.response_limit.clone()),
                stdin,
                gix_transport::Protocol::V1,
                self.prepared.repository.clone(),
                None::<(&str, Option<u16>)>,
                client::git::ConnectMode::Process,
                false,
            )
            .custom_url(Some(self.canonical_url.clone()));
            self.connection = Some((service, connection, closed));
        }
        let response = self
            .connection
            .as_mut()
            .expect("connection initialized")
            .1
            .handshake(service, extra_parameters)?;
        if response.actual_protocol == gix_transport::Protocol::V2 {
            return Err(io::Error::other("SSH supports Git protocol V0/V1 only").into());
        }
        Ok(response)
    }

    fn request(
        &mut self,
        write_mode: client::WriteMode,
        on_into_read: client::MessageKind,
        trace: bool,
    ) -> Result<client::blocking_io::RequestWriter<'_>, client::Error> {
        let (_, connection, _) = self
            .connection
            .as_mut()
            .ok_or(client::Error::MissingHandshake)?;
        // This raises the cumulative ceiling; discovery bytes remain counted.
        self.response_limit.store(SESSION_BYTES, Ordering::Relaxed);
        connection.request(write_mode, on_into_read, trace)
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        if let Some((_, connection, closed)) = self.connection.take() {
            let (stdout, stdin) = connection.into_inner();
            drop(stdin);
            drop(stdout);
            closed.mark();
        }
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
