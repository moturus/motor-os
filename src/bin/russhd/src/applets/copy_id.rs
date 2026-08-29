use std::path::PathBuf;

use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};

use super::{AppletError, CopyIdArgs};
use crate::client::sftp::SftpConnection;
use crate::client::transfer;

pub(super) async fn run(args: CopyIdArgs) -> Result<i32, AppletError> {
    let key_path = args.public_key.unwrap_or_else(default_public_key);
    let text = std::fs::read_to_string(&key_path)?;
    if text.lines().count() != 1 {
        return Err(AppletError::Message(format!(
            "'{}' must contain exactly one public key",
            key_path.display()
        )));
    }
    let key = russh::keys::PublicKey::from_openssh(text.trim())?;
    let encoded = key.to_openssh()?;
    let wanted = key_fields(&encoded)
        .ok_or_else(|| AppletError::Message("invalid public key encoding".to_owned()))?;

    let connection = SftpConnection::connect(&args.connection, &args.destination).await?;
    let result = install(&connection, &encoded, wanted).await;
    let close = connection.close().await;
    result?;
    close?;
    println!("Key installed for {}", args.destination.user);
    Ok(0)
}

async fn install(
    connection: &SftpConnection,
    encoded: &str,
    wanted: (&str, &str),
) -> Result<(), AppletError> {
    let home = connection.raw.realpath(".").await.map_err(sftp_error)?;
    let home = &home
        .files
        .first()
        .ok_or_else(|| AppletError::Message("SFTP realpath returned no path".to_owned()))?
        .filename;
    let ssh_dir = transfer::remote_join(home, ".ssh");
    match connection.raw.stat(ssh_dir.clone()).await {
        Ok(attrs) if !attrs.attrs.is_dir() => {
            return Err(AppletError::Message(
                "remote .ssh path is not a directory".to_owned(),
            ));
        }
        Ok(_) => {
            connection
                .raw
                .setstat(ssh_dir.clone(), attributes(0o700, true))
                .await
                .map_err(sftp_error)?;
        }
        Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => {
            connection
                .raw
                .mkdir(ssh_dir.clone(), attributes(0o700, true))
                .await
                .map_err(sftp_error)?;
        }
        Err(error) => return Err(sftp_error(error)),
    }

    let authorized = transfer::remote_join(&ssh_dir, "authorized_keys");
    let scan = scan_authorized(connection, &authorized, wanted).await?;
    if scan.duplicate {
        return Ok(());
    }
    let handle = connection
        .raw
        .open(
            authorized,
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::APPEND,
            attributes(0o600, false),
        )
        .await
        .map_err(sftp_error)?
        .handle;
    let result = async {
        let mut line = Vec::new();
        if scan.has_content && !scan.ends_in_newline {
            line.push(b'\n');
        }
        line.extend_from_slice(encoded.as_bytes());
        line.push(b'\n');
        connection
            .raw
            .write(handle.clone(), scan.size, line)
            .await
            .map_err(sftp_error)?;
        connection
            .raw
            .fsetstat(handle.clone(), attributes(0o600, false))
            .await
            .map_err(sftp_error)?;
        Ok::<(), AppletError>(())
    }
    .await;
    let close = connection.raw.close(handle).await.map_err(sftp_error);
    result?;
    close?;
    Ok(())
}

struct Scan {
    duplicate: bool,
    has_content: bool,
    ends_in_newline: bool,
    size: u64,
}

async fn scan_authorized(
    connection: &SftpConnection,
    path: &str,
    wanted: (&str, &str),
) -> Result<Scan, AppletError> {
    let handle = match connection
        .raw
        .open(path, OpenFlags::READ, FileAttributes::empty())
        .await
    {
        Ok(handle) => handle.handle,
        Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => {
            return Ok(Scan {
                duplicate: false,
                has_content: false,
                ends_in_newline: false,
                size: 0,
            });
        }
        Err(error) => return Err(sftp_error(error)),
    };
    let result = async {
        let mut offset = 0_u64;
        let mut pending = Vec::new();
        let mut duplicate = false;
        let chunk = connection
            .limits
            .read_len
            .unwrap_or(32 * 1024)
            .clamp(1, 32 * 1024) as u32;
        loop {
            match connection.raw.read(handle.clone(), offset, chunk).await {
                Ok(data) => {
                    if data.data.is_empty() {
                        return Err(AppletError::Message(
                            "remote returned an empty data packet".to_owned(),
                        ));
                    }
                    offset = offset
                        .checked_add(data.data.len() as u64)
                        .ok_or_else(|| AppletError::Message("file offset overflow".to_owned()))?;
                    pending.extend_from_slice(&data.data);
                    if pending.len() > 1024 * 1024 {
                        return Err(AppletError::Message(
                            "authorized_keys contains a line larger than 1 MiB".to_owned(),
                        ));
                    }
                    while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
                        let line = pending.drain(..=newline).collect::<Vec<_>>();
                        duplicate |= same_key(&line[..line.len() - 1], wanted);
                    }
                }
                Err(SftpError::Status(status)) if status.status_code == StatusCode::Eof => break,
                Err(error) => return Err(sftp_error(error)),
            }
        }
        duplicate |= same_key(&pending, wanted);
        Ok(Scan {
            duplicate,
            has_content: offset != 0,
            ends_in_newline: offset != 0 && pending.is_empty(),
            size: offset,
        })
    }
    .await;
    let close = connection.raw.close(handle).await.map_err(sftp_error);
    let scan = result?;
    close?;
    Ok(scan)
}

fn same_key(line: &[u8], wanted: (&str, &str)) -> bool {
    let Ok(line) = std::str::from_utf8(line) else {
        return false;
    };
    key_fields(line).is_some_and(|fields| fields == wanted)
}

fn key_fields(line: &str) -> Option<(&str, &str)> {
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    fields.windows(2).find_map(|fields| {
        let key_type = fields[0];
        (key_type.starts_with("ssh-")
            || key_type.starts_with("ecdsa-")
            || key_type.starts_with("sk-"))
        .then_some((key_type, fields[1]))
    })
}

fn attributes(mode: u32, directory: bool) -> FileAttributes {
    let mut attrs = FileAttributes::empty();
    attrs.permissions = Some(mode);
    if directory {
        attrs.set_dir(true);
    } else {
        attrs.set_regular(true);
    }
    attrs
}

fn sftp_error(error: SftpError) -> AppletError {
    transfer::Error::from(error).into()
}

fn default_public_key() -> PathBuf {
    #[cfg(target_os = "motor")]
    return PathBuf::from("/user/cfg/ssh/id_ed25519.pub");
    #[cfg(not(target_os = "motor"))]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".ssh/id_ed25519.pub")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_type_and_blob_while_ignoring_comments() {
        let wanted = ("ssh-ed25519", "AAAA");
        assert!(same_key(b"ssh-ed25519 AAAA old comment", wanted));
        assert!(same_key(
            b"command=\"echo no\" ssh-ed25519 AAAA restricted",
            wanted
        ));
        assert!(!same_key(b"ssh-ed25519 BBBB", wanted));
        assert!(!same_key(b"not a key", wanted));
    }
}
