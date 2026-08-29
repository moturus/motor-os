use std::path::Path;

use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::StatusCode;

use super::{AppletError, CopyEndpoint, ScpArgs};
use crate::client::sftp::SftpConnection;
use crate::client::transfer;

pub(super) async fn run(args: ScpArgs) -> Result<i32, AppletError> {
    if let CopyEndpoint::Remote { destination, path } = &args.target {
        upload(&args, destination, path).await?;
    } else {
        download(&args).await?;
    }
    Ok(0)
}

async fn upload(
    args: &ScpArgs,
    destination: &crate::client::args::Destination,
    remote_target: &str,
) -> Result<(), AppletError> {
    let connection = SftpConnection::connect(&args.connection, destination).await?;
    let result = async {
        let target_is_dir = remote_is_dir(&connection.raw, remote_target).await?;
        if args.sources.len() > 1 && !target_is_dir {
            return Err(AppletError::Message(
                "multiple scp sources require a remote directory target".to_owned(),
            ));
        }
        for source in &args.sources {
            let CopyEndpoint::Local(source) = source else {
                unreachable!("the parser rejects remote-to-remote copies")
            };
            let target = target_name(remote_target, target_is_dir, local_basename(source)?)?;
            let metadata = source.symlink_metadata()?;
            if metadata.file_type().is_symlink() {
                return Err(AppletError::Message(
                    "scp does not support symbolic links".to_owned(),
                ));
            }
            if metadata.is_dir() {
                if !args.recursive {
                    return Err(AppletError::Message(
                        "scp directory source requires -r".to_owned(),
                    ));
                }
                transfer::upload_tree(
                    &connection.raw,
                    source,
                    &target,
                    connection.limits.write_len,
                )
                .await?;
            } else {
                transfer::upload_file(
                    &connection.raw,
                    source,
                    &target,
                    connection.limits.write_len,
                )
                .await?;
            }
        }
        Ok::<(), AppletError>(())
    }
    .await;
    let close = connection.close().await;
    result?;
    close?;
    Ok(())
}

async fn download(args: &ScpArgs) -> Result<(), AppletError> {
    let CopyEndpoint::Remote {
        destination,
        path: remote_source,
    } = &args.sources[0]
    else {
        unreachable!("the parser requires a remote download source")
    };
    let CopyEndpoint::Local(local_target) = &args.target else {
        unreachable!()
    };
    let connection = SftpConnection::connect(&args.connection, destination).await?;
    let result = async {
        let attrs = connection
            .raw
            .lstat(remote_source)
            .await
            .map_err(transfer::Error::from)?
            .attrs;
        let target = if local_target.is_dir() {
            local_target.join(transfer::basename(remote_source)?)
        } else {
            local_target.clone()
        };
        if attrs.is_dir() {
            if !args.recursive {
                Err(AppletError::Message(
                    "scp directory source requires -r".to_owned(),
                ))
            } else {
                transfer::download_tree(
                    &connection.raw,
                    remote_source,
                    &target,
                    connection.limits.read_len,
                )
                .await
                .map_err(Into::into)
            }
        } else {
            transfer::download_file(
                &connection.raw,
                remote_source,
                &target,
                connection.limits.read_len,
            )
            .await
            .map_err(Into::into)
        }
    }
    .await;
    let close = connection.close().await;
    result?;
    close?;
    Ok(())
}

async fn remote_is_dir(
    sftp: &russh_sftp::client::RawSftpSession,
    path: &str,
) -> Result<bool, AppletError> {
    match sftp.stat(path).await {
        Ok(attrs) => Ok(attrs.attrs.is_dir()),
        Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => Ok(false),
        Err(error) => Err(crate::client::transfer::Error::from(error).into()),
    }
}

fn target_name(target: &str, target_is_dir: bool, basename: &str) -> Result<String, AppletError> {
    if target_is_dir {
        Ok(transfer::remote_join(target, basename))
    } else {
        Ok(target.to_owned())
    }
}

fn local_basename(path: &Path) -> Result<&str, AppletError> {
    path.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AppletError::Message("local path has no UTF-8 file name".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_name_only_for_directory_targets() {
        assert_eq!(target_name("dir", true, "file").unwrap(), "dir/file");
        assert_eq!(target_name("renamed", false, "file").unwrap(), "renamed");
    }
}
