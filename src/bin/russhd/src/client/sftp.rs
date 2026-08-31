use std::sync::Arc;

use russh_sftp::client::RawSftpSession;
use russh_sftp::client::rawsession::Limits;
use russh_sftp::protocol::Version;

use super::args::{ConnectionOptions, Destination};
use super::{session, transport};
use crate::sftp_extensions::{POSIX_RENAME, POSIX_RENAME_VERSION};

pub struct SftpConnection {
    pub raw: RawSftpSession,
    pub limits: Limits,
    pub posix_rename: bool,
    ssh: russh::client::Handle<transport::Handler>,
}

impl SftpConnection {
    pub async fn connect(
        options: &ConnectionOptions,
        destination: &Destination,
    ) -> Result<Self, Error> {
        let ssh = session::connect_authenticated(options, destination).await?;
        let channel = ssh.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let mut raw = RawSftpSession::new(channel.into_stream());
        raw.set_timeout(u64::MAX).await;
        let version = raw.init().await?;
        let posix_rename = supports_posix_rename(&version);
        let limits = configure_limits(&mut raw, &version).await?;
        Ok(Self {
            raw,
            limits,
            posix_rename,
            ssh,
        })
    }

    pub async fn close(self) -> Result<(), Error> {
        self.raw.close_session()?;
        self.ssh
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await?;
        Ok(())
    }
}

fn supports_posix_rename(version: &Version) -> bool {
    version
        .extensions
        .get(POSIX_RENAME)
        .is_some_and(|value| value == POSIX_RENAME_VERSION)
}

async fn configure_limits(raw: &mut RawSftpSession, version: &Version) -> Result<Limits, Error> {
    if version
        .extensions
        .get(russh_sftp::extensions::LIMITS)
        .is_some_and(|value| value == "1")
    {
        let limits = Limits::from(raw.limits().await?);
        raw.set_limits(Arc::new(limits));
        return Ok(limits);
    }
    Ok(Limits::default())
}

#[derive(Debug)]
pub enum Error {
    Ssh(russh::Error),
    Sftp(russh_sftp::client::error::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ssh(error) => error.fmt(f),
            Self::Sftp(error) => error.fmt(f),
        }
    }
}

impl From<russh::Error> for Error {
    fn from(error: russh::Error) -> Self {
        Self::Ssh(error)
    }
}

impl From<russh_sftp::client::error::Error> for Error {
    fn from(error: russh_sftp::client::error::Error) -> Self {
        Self::Sftp(error)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn posix_rename_requires_the_documented_version() {
        let mut version = Version::new();
        assert!(!supports_posix_rename(&version));
        version
            .extensions
            .insert(POSIX_RENAME.to_owned(), "2".to_owned());
        assert!(!supports_posix_rename(&version));
        version
            .extensions
            .insert(POSIX_RENAME.to_owned(), POSIX_RENAME_VERSION.to_owned());
        assert!(supports_posix_rename(&version));
    }

    #[tokio::test(start_paused = true)]
    async fn maximum_timeout_does_not_expire_at_ten_seconds() {
        let (client, mut server) = tokio::io::duplex(64);
        let raw = RawSftpSession::new(client);
        raw.set_timeout(u64::MAX).await;
        let (request_seen_tx, request_seen_rx) = tokio::sync::oneshot::channel();
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut init = [0_u8; 9];
            server.read_exact(&mut init).await.unwrap();
            assert_eq!(init, [0, 0, 0, 5, 1, 0, 0, 0, 3]);
            request_seen_tx.send(()).unwrap();
            reply_rx.await.unwrap();
            server
                .write_all(&[0, 0, 0, 5, 2, 0, 0, 0, 3])
                .await
                .unwrap();
        });

        let init = raw.init();
        tokio::pin!(init);
        tokio::select! {
            result = &mut init => panic!("init completed before a reply: {result:?}"),
            result = request_seen_rx => result.unwrap(),
        }
        tokio::time::advance(std::time::Duration::from_secs(11)).await;
        reply_tx.send(()).unwrap();
        assert_eq!(init.await.unwrap().version, 3);
    }
}
