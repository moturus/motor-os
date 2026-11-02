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
    let wanted = key_fields(encoded.as_bytes())
        .ok_or_else(|| AppletError::Message("invalid public key encoding".to_owned()))?;

    let connection = SftpConnection::connect(&args.connection, &args.destination).await?;
    let result = install(&connection, &encoded, wanted, args.target.as_deref()).await;
    let close = connection.close().await;
    result?;
    close?;
    println!("Key installed for {}", args.destination.user);
    Ok(0)
}

/// Installs into `target`, whose parent must exist, or else into the OpenSSH
/// default `.ssh/authorized_keys`.
async fn install(
    connection: &SftpConnection,
    encoded: &str,
    wanted: Key<'_>,
    target: Option<&str>,
) -> Result<(), AppletError> {
    let authorized = match target {
        Some(target) if target.starts_with('/') => target.to_owned(),
        Some(target) => transfer::remote_join(&start_directory(connection).await?, target),
        None => default_target(connection).await?,
    };
    let scan = scan_authorized(connection, &authorized, wanted).await?;
    match scan.listed {
        Listing::Plain => return Ok(()),
        Listing::Restricted => {
            return Err(AppletError::Message(format!(
                "'{authorized}' mentions this key, but not as a plain record; \
                 not adding an unrestricted copy"
            )));
        }
        Listing::Absent => {}
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

async fn start_directory(connection: &SftpConnection) -> Result<String, AppletError> {
    let home = connection.raw.realpath(".").await.map_err(sftp_error)?;
    home.files
        .into_iter()
        .next()
        .map(|file| file.filename)
        .ok_or_else(|| AppletError::Message("SFTP realpath returned no path".to_owned()))
}

/// Makes sure of `.ssh`, as mode 0700, under the SFTP start directory.
async fn default_target(connection: &SftpConnection) -> Result<String, AppletError> {
    let home = start_directory(connection).await?;
    let ssh_dir = transfer::remote_join(&home, ".ssh");
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
    Ok(transfer::remote_join(&ssh_dir, "authorized_keys"))
}

/// How a key list holds the key being installed, the strongest record winning.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Listing {
    Absent,
    Restricted,
    Plain,
}

struct Scan {
    listed: Listing,
    has_content: bool,
    ends_in_newline: bool,
    size: u64,
}

async fn scan_authorized(
    connection: &SftpConnection,
    path: &str,
    wanted: Key<'_>,
) -> Result<Scan, AppletError> {
    let handle = match connection
        .raw
        .open(path, OpenFlags::READ, FileAttributes::empty())
        .await
    {
        Ok(handle) => handle.handle,
        Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => {
            return Ok(Scan {
                listed: Listing::Absent,
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
        let mut listed = Listing::Absent;
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
                        listed = listed.max(listing(&line[..line.len() - 1], wanted));
                    }
                }
                Err(SftpError::Status(status)) if status.status_code == StatusCode::Eof => break,
                Err(error) => return Err(sftp_error(error)),
            }
        }
        listed = listed.max(listing(&pending, wanted));
        Ok(Scan {
            listed,
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

/// A key's type and base64, as the bytes of a line.
type Key<'a> = (&'a [u8], &'a [u8]);

/// How one line holds `wanted`. Only an exact `TYPE BASE64 [COMMENT]` record is
/// plain. OpenSSH accepts more around a key than this reads, in options, type
/// names and comments of any encoding, and a copy would lift a restriction, so
/// any other line that shows the base64 counts as restricted. That misses only a
/// blob built by hand to encode the same key differently. A comment holds
/// nothing, however much it looks like a key.
fn listing(line: &[u8], wanted: Key<'_>) -> Listing {
    let line = line.trim_ascii();
    if line.is_empty() || line.starts_with(b"#") {
        return Listing::Absent;
    }
    if key_fields(line) == Some(wanted) {
        return Listing::Plain;
    }
    // Fields end at a space or a tab; OpenSSH's base64 decoder skips the rest.
    let text: Vec<u8> = line
        .iter()
        .copied()
        .filter(|byte| !matches!(byte, b'\r' | b'\x0b' | b'\x0c'))
        .collect();
    if text.windows(wanted.1.len()).any(|bytes| bytes == wanted.1) {
        Listing::Restricted
    } else {
        Listing::Absent
    }
}

/// The first two fields of `line`, split as OpenSSH splits them.
fn key_fields(line: &[u8]) -> Option<Key<'_>> {
    let mut fields = line
        .split(|byte| matches!(byte, b' ' | b'\t'))
        .filter(|field| !field.is_empty());
    Some((fields.next()?, fields.next()?))
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

    const WANTED: Key<'_> = (b"ssh-ed25519", b"AAAA");

    #[test]
    fn compares_type_and_blob_while_ignoring_comments() {
        for line in [
            &b"ssh-ed25519 AAAA old comment"[..],
            b"  ssh-ed25519\tAAAA\r",
            b"ssh-ed25519 AAAA caf\xe9",
        ] {
            assert_eq!(listing(line, WANTED), Listing::Plain);
        }
        for line in [
            &b"ssh-ed25519 BBBB"[..],
            b"ssh-ed25519 BBBB caf\xe9",
            b"not a key",
            b"# ssh-ed25519 AAAA",
            b"  # from=\"10.0.0.1\" ssh-ed25519 AAAA",
            b"command=\"unterminated",
            b"",
        ] {
            assert_eq!(listing(line, WANTED), Listing::Absent);
        }
    }

    #[test]
    fn any_other_line_that_shows_the_key_is_restricted() {
        for line in [
            &b"restrict ssh-ed25519 AAAA"[..],
            b"from=\"10.0.0.1\" ssh-ed25519 AAAA comment",
            b"command=\"echo no\" ssh-ed25519 AAAA restricted",
            b"command=\"say \\\"hi there\\\"\",restrict\tssh-ed25519 AAAA",
            b"cert-authority ssh-ed25519 AAAA",
            b"command=\"a\\\\\" b\" ssh-ed25519 AAAA",
            // OpenSSH takes any bytes in a comment or an option's value.
            b"from=\"10.0.0.1\" ssh-ed25519 AAAA caf\xe9",
            b"from=\"10.0.0.1\",environment=\"A=caf\xe9\" ssh-ed25519 AAAA",
            // It takes other names for a type, and whitespace inside base64.
            b"from=\"10.0.0.1\" rsa-sha2-256 AAAA",
            b"rsa-sha2-512 AAAA",
            b"from=\"10.0.0.1\" ssh-ed25519 AA\rAA",
            b"from=\"10.0.0.1\" ssh-ed25519 A\x0bA\x0cAA",
            // A record of another key that only quotes this one is refused too:
            // wrongly refusing is safe, and wrongly appending is not.
            b"command=\"echo ssh-ed25519 AAAA\" ssh-ed25519 BBBB",
        ] {
            assert_eq!(listing(line, WANTED), Listing::Restricted, "{line:?}");
        }
    }

    #[test]
    fn a_plain_record_outranks_a_restricted_one() {
        assert_eq!(Listing::Restricted.max(Listing::Plain), Listing::Plain);
        assert_eq!(
            Listing::Absent.max(Listing::Restricted),
            Listing::Restricted
        );
    }
}
