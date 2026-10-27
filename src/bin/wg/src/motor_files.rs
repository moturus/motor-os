//! Secret files are checked and read by entry ID; publication uses a private stage.
use crate::config::{MAX_FILE_BYTES, Result};
use moto_sdk::async_runtime::LocalRuntime;
use moto_sdk::io::fs::{
    AccessPermissions as Access, EntryId, EntryKind, FsClient, RolePermissions,
};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

pub const CONFIG_DIR: &str = "/user/cfg/wireguard";
pub const FILE_PERMISSIONS: RolePermissions =
    RolePermissions::new(Access::Rwx, Access::Rw, Access::None);
const DIR_PERMISSIONS: RolePermissions =
    RolePermissions::new(Access::Rwx, Access::Rwx, Access::None);

pub struct Document {
    pub text: String,
    pub permissions: RolePermissions,
}

pub fn absolute(path: &Path) -> Result<String> {
    let path = std::path::absolute(path).map_err(|_| "cannot resolve configuration path")?;
    let mut normalized = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => (),
            _ => normalized.push(part),
        }
    }
    let path = normalized
        .to_str()
        .ok_or("configuration path must be UTF-8")?;
    if path.len() > 1024 {
        return Err("configuration path exceeds the filesystem's length limit");
    }
    for part in path.split('/').filter(|part| !part.is_empty()) {
        moto_sdk::async_fs::validate_filename(part)
            .map_err(|_| "invalid configuration path component")?;
    }
    if normalized.extension().and_then(|ext| ext.to_str()) != Some("toml") {
        return Err("configuration filename must end in .toml");
    }
    Ok(path.to_owned())
}

async fn directory(fs: &Rc<FsClient>, path: &Path) -> Result<(EntryId, RolePermissions)> {
    let mut result = None;
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        let (id, kind) = fs
            .stat(prefix.to_str().unwrap())
            .await
            .map_err(|_| "cannot inspect configuration directory")?;
        if kind != EntryKind::Directory {
            return Err("configuration parent is not a directory");
        }
        let permissions = fs
            .metadata(id)
            .await
            .map_err(|_| "cannot inspect directory permissions")?
            .permissions()
            .map_err(|_| "invalid directory permissions")?;
        if permissions.none.can_write() {
            return Err("configuration ancestry must not be writable by the None role");
        }
        if prefix == Path::new(CONFIG_DIR) && permissions.none != Access::None {
            return Err("default configuration directory must exclude the None role");
        }
        result = Some((id, permissions));
    }
    result.ok_or("configuration parent is missing")
}

pub fn read(path: &Path) -> Result<Document> {
    read_until(path, None)
}

pub fn read_until(path: &Path, deadline: Option<moto_sdk::rt::time::Instant>) -> Result<Document> {
    let path = absolute(path)?;
    LocalRuntime::new().block_on(crate::motor_ipc::until(
        async {
            let fs = FsClient::connect().map_err(|_| "cannot connect to filesystem service")?;
            directory(&fs, Path::new(&path).parent().unwrap()).await?;
            let (entry, kind) = fs
                .stat(&path)
                .await
                .map_err(|_| "cannot find configuration file")?;
            let metadata = fs
                .metadata(entry)
                .await
                .map_err(|_| "cannot inspect configuration file")?;
            let permissions = metadata
                .permissions()
                .map_err(|_| "invalid file permissions")?;
            crate::files::check_metadata(
                kind == EntryKind::File,
                metadata.size,
                permissions.none.can_read(),
            )?;
            // Reuse the checked ID for every read, including the overflow byte.
            let mut bytes = vec![0; MAX_FILE_BYTES + 1];
            let count = fs
                .read(entry, 0, &mut bytes)
                .await
                .map_err(|_| "cannot read configuration file")?;
            bytes.truncate(count);
            Ok(Document {
                text: crate::files::decode(bytes)?,
                permissions,
            })
        },
        deadline,
    ))
}

pub struct Destination {
    parent: EntryId,
    name: String,
    permissions: RolePermissions,
    replace: bool,
    create_directory: bool,
}

impl Destination {
    pub fn prepare(path: &str, existing: Option<RolePermissions>) -> Result<Self> {
        let path = Path::new(path);
        let parent_path = path.parent().ok_or("configuration parent is missing")?;
        if parent_path.as_os_str().len() + 41 > 1024 {
            return Err("configuration directory leaves no room for a staging filename");
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("invalid configuration filename")?
            .to_owned();
        let permissions = existing.unwrap_or(FILE_PERMISSIONS);
        if !permissions.interactive.can_write() {
            return Err("configuration is read-only");
        }
        if permissions.system != Access::Rwx {
            return Err("cannot preserve restricted System permissions in a replacement file");
        }
        LocalRuntime::new().block_on(async {
            let fs = FsClient::connect().map_err(|_| "cannot connect to filesystem service")?;
            let create_directory = parent_path == Path::new(CONFIG_DIR)
                && matches!(
                    fs.stat(CONFIG_DIR).await,
                    Err(moto_sdk::rt::Error::NotFound)
                );
            let (parent, access) = directory(
                &fs,
                if create_directory {
                    parent_path.parent().unwrap()
                } else {
                    parent_path
                },
            )
            .await?;
            if !access.interactive.can_write() {
                return Err("configuration parent is read-only");
            }
            if existing.is_none() && !create_directory {
                match fs.stat(path.to_str().unwrap()).await {
                    Ok(_) => return Err("configuration destination already exists"),
                    Err(moto_sdk::rt::Error::NotFound) => (),
                    Err(_) => return Err("cannot inspect configuration destination"),
                }
            }
            Ok(Self {
                parent,
                name,
                permissions,
                replace: existing.is_some(),
                create_directory,
            })
        })
    }

    pub fn publish(self, text: &str) -> Result<()> {
        let permissions = self.permissions;
        self.publish_stage(text, permissions)
    }

    #[cfg(feature = "native-tests")]
    pub(crate) fn fail_write_for_test(self, text: &str) -> Result<()> {
        let mut permissions = self.permissions;
        permissions.interactive = Access::R;
        self.publish_stage(text, permissions)
    }

    fn publish_stage(self, text: &str, permissions: RolePermissions) -> Result<()> {
        if text.len() > MAX_FILE_BYTES {
            return Err("configuration is limited to 64 KiB");
        }
        LocalRuntime::new().block_on(async {
            let fs = FsClient::connect().map_err(|_| "cannot connect to filesystem service")?;
            let parent = if self.create_directory {
                fs.create_entry_with_permissions(
                    self.parent,
                    EntryKind::Directory,
                    "wireguard",
                    DIR_PERMISSIONS,
                )
                .await
                .map_err(|_| "cannot create private configuration directory")?
            } else {
                self.parent
            };
            let mut nonce = [0u8; 16];
            moto_sdk::rt::fill_random_bytes(&mut nonce);
            let name = format!(
                ".wg-{}.tmp",
                nonce
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            let stage = fs
                .create_entry_with_permissions(parent, EntryKind::File, &name, permissions)
                .await
                .map_err(|_| "cannot create private staging file")?;
            let result = async {
                let mut offset = 0;
                while offset < text.len() {
                    let count = fs
                        .write(stage, offset as u64, &text.as_bytes()[offset..])
                        .await
                        .map_err(|_| "cannot write staging file")?;
                    if count == 0 {
                        return Err("short write to staging file");
                    }
                    offset += count;
                }
                fs.flush().await.map_err(|_| "cannot flush staging file")?;
                if self.replace {
                    fs.move_entry(stage, parent, &self.name).await
                } else {
                    fs.move_noreplace(stage, parent, &self.name).await
                }
                .map_err(|_| "cannot publish configuration")
            }
            .await;
            if let Err(error) = result {
                fs.delete_entry(stage).await.map_err(
                    |_| "configuration write failed; private staging cleanup also failed",
                )?;
                return Err(error);
            }
            fs.flush()
                .await
                .map_err(|_| "configuration was published, but durability is unconfirmed")
        })
    }
}

pub fn saved_names() -> std::result::Result<Vec<String>, String> {
    let entries = match std::fs::read_dir(CONFIG_DIR) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(format!("{CONFIG_DIR}: cannot list saved configurations")),
    };
    let mut names = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|_| format!("{CONFIG_DIR}: cannot inspect saved configuration entry"))?
            .path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
            names.push(stem.to_owned());
        }
        let config = crate::config::Config::load(&path).map_err(|error| {
            format!("{}: {error}", crate::tool::escaped(&path.to_string_lossy()))
        })?;
        names.push(config.name);
    }
    Ok(names)
}
