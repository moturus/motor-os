use super::*;

impl RootFs {
    /// Publish one snapshot on the filesystem mounted at /system/tmp. The net
    /// runtime serializes calls; readers see either complete file generation.
    pub(crate) async fn publish_dhcp(&self, contents: &str) -> Result<()> {
        let (id, kind) = mounts::stat_path(&self.0, Role::System, "/system/tmp").await?;
        if kind != EntryKind::Directory {
            return Err(ErrorKind::NotADirectory.into());
        }
        let directory = mounts::Resolved::resolve(&self.0, id)?;
        let mut fs = directory.write().await?;
        let mode = RolePermissions::new(
            AccessPermissions::Rwx,
            AccessPermissions::Rx,
            AccessPermissions::None,
        );
        let sys_io = match fs.stat(Role::System, directory.local, "sys-io").await? {
            Some((id, EntryKind::Directory)) => {
                fs.set_all_permissions(Role::System, id, mode).await?;
                id
            }
            Some(_) => return Err(ErrorKind::NotADirectory.into()),
            None => {
                fs.create_entry(
                    Role::System,
                    directory.local,
                    EntryKind::Directory,
                    "sys-io",
                    mode,
                )
                .await?
            }
        };
        directory.check_local(sys_io)?;
        const TEMP: &str = ".dhcp.toml";
        if let Some((stale, _)) = fs.stat(Role::System, sys_io, TEMP).await? {
            directory.check_local(stale)?;
            fs.delete_entry(Role::System, stale).await?;
        }
        let temp = fs
            .create_entry(
                Role::System,
                sys_io,
                EntryKind::File,
                TEMP,
                RolePermissions::new(
                    AccessPermissions::Rw,
                    AccessPermissions::R,
                    AccessPermissions::None,
                ),
            )
            .await?;
        directory.check_local(temp)?;
        let result = async {
            let mut offset = 0;
            while offset < contents.len() {
                let end = ((offset / moto_sdk::async_fs::BLOCK_SIZE + 1)
                    * moto_sdk::async_fs::BLOCK_SIZE)
                    .min(contents.len());
                let written = fs
                    .write(
                        Role::System,
                        temp,
                        offset as u64,
                        &contents.as_bytes()[offset..end],
                    )
                    .await?;
                if written == 0 {
                    return Err(ErrorKind::WriteZero.into());
                }
                offset += written;
            }
            fs.move_entry(Role::System, temp, sys_io, "dhcp.toml").await
        }
        .await;
        if result.is_err() {
            let _ = fs.delete_entry(Role::System, temp).await;
        }
        result
    }
}
