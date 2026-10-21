//! Bounded boot configuration, fully validated before applying any mount.
use super::{FS, admission, mounts};
use async_fs::{AccessPermissions, EntryKind, FileSystem, ROOT_ID, Role, RolePermissions};
use serde::Deserialize;
use std::cell::RefCell;
use std::io::{ErrorKind, Result};
use std::rc::Rc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    // Tables first, so that errors in an entry can name it.
    #[serde(default)]
    mount: Vec<toml::Table>,
}

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum MountConfig {
    #[serde(rename = "memfs")]
    MemFs {
        path: String,
        max_size: Option<Size>,
        mode: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Size {
    Bytes(u64),
    Text(String),
}

struct ValidatedMount {
    path: String,
    max_size: Option<u64>,
    mode: Option<RolePermissions>,
}

fn invalid(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> std::io::Error {
    std::io::Error::new(ErrorKind::InvalidInput, message)
}

fn size(size: Size) -> Result<u64> {
    match size {
        Size::Bytes(bytes) => Ok(bytes),
        Size::Text(text) => {
            let (number, scale) = match text.as_bytes().last() {
                Some(b'K') => (&text[..text.len() - 1], 1u64 << 10),
                Some(b'M') => (&text[..text.len() - 1], 1u64 << 20),
                Some(b'G') => (&text[..text.len() - 1], 1u64 << 30),
                _ => (text.as_str(), 1),
            };
            if number.is_empty() || !number.bytes().all(|ch| ch.is_ascii_digit()) {
                return Err(invalid(
                    "max_size must be bytes or an integer with K/M/G suffix",
                ));
            }
            number
                .parse::<u64>()
                .ok()
                .and_then(|value| value.checked_mul(scale))
                .ok_or_else(|| invalid("max_size overflow"))
        }
    }
}

fn mode(text: &str) -> Result<RolePermissions> {
    let triplet = |bytes: &[u8]| match bytes {
        b"rwx" => Ok(AccessPermissions::Rwx),
        b"r-x" => Ok(AccessPermissions::Rx),
        b"rw-" => Ok(AccessPermissions::Rw),
        b"r--" => Ok(AccessPermissions::R),
        b"---" => Ok(AccessPermissions::None),
        _ => Err(invalid("invalid permission triplet")),
    };
    let bytes = text.as_bytes();
    if bytes.len() != 9 {
        return Err(invalid("mode must contain nine permission characters"));
    }
    let permissions = RolePermissions::new(
        triplet(&bytes[..3])?,
        triplet(&bytes[3..6])?,
        triplet(&bytes[6..])?,
    );
    if !async_fs::perms_monotonic(permissions) {
        return Err(invalid("non-monotonic mode"));
    }
    Ok(permissions)
}

fn ancestor(parent: &str, child: &str) -> bool {
    child
        .strip_prefix(parent)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn parse(text: &str) -> Result<Vec<ValidatedMount>> {
    let config: Config = toml::from_str(text).map_err(|err| invalid(err.to_string()))?;
    if config.mount.len() > 255 {
        return Err(invalid("more than 255 mounts"));
    }
    let mut mounts: Vec<ValidatedMount> = Vec::with_capacity(config.mount.len());
    for (index, table) in config.mount.into_iter().enumerate() {
        let name = match table.get("path") {
            Some(toml::Value::String(path)) => path.clone(),
            _ => format!("#{}", index + 1),
        };
        let named = |err: &dyn std::fmt::Display| invalid(format!("mount {name}: {err}"));
        let MountConfig::MemFs {
            path,
            max_size,
            mode: root_mode,
        } = toml::Value::Table(table)
            .try_into()
            .map_err(|err| named(&err))?;
        if !path.starts_with('/')
            || path.len() > moto_rt::fs::MAX_PATH_LEN
            || path[1..]
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(invalid(format!("mount path is not canonical: {path:?}")));
        }
        if path == "/system/cfg" || ancestor("/system/cfg", &path) || ancestor(&path, "/system/cfg")
        {
            return Err(invalid(format!("mount hides system configuration: {path}")));
        }
        if mounts
            .iter()
            .any(|earlier| earlier.path == path || ancestor(&path, &earlier.path))
        {
            return Err(invalid(format!("mount hides an earlier mount: {path}")));
        }
        mounts.push(ValidatedMount {
            max_size: max_size.map(size).transpose().map_err(|err| named(&err))?,
            mode: root_mode
                .as_deref()
                .map(mode)
                .transpose()
                .map_err(|err| named(&err))?,
            path,
        });
    }
    Ok(mounts)
}

/// Internal config reads stay on mount zero and use the same quarantine gate.
pub(crate) async fn read_root_file(
    table: &Rc<RefCell<mounts::MountTable>>,
    path: &str,
) -> Result<Option<Vec<u8>>> {
    let root = mounts::Resolved::on_mount(table, 0, ROOT_ID)?;
    let fs = root.read().await?;
    let mut id = ROOT_ID;
    for name in path.split('/').filter(|name| !name.is_empty()) {
        root.healthy()?;
        let Some((next, _)) = fs.stat(Role::System, id, name).await? else {
            return Ok(None);
        };
        id = root.check_local(next)?;
    }
    root.healthy()?;
    let metadata = fs.metadata(Role::System, id).await?;
    if metadata.try_kind()? != EntryKind::File || metadata.size > 64 * 1024 {
        return Err(invalid("configuration must be a file of at most 64 KiB"));
    }
    let mut bytes = vec![0; metadata.size as usize];
    let mut done = 0;
    while done < bytes.len() {
        root.healthy()?;
        let end = (done + async_fs::BLOCK_SIZE - done % async_fs::BLOCK_SIZE).min(bytes.len());
        let count = fs
            .read(Role::System, id, done as u64, &mut bytes[done..end])
            .await?;
        if count == 0 {
            return Err(ErrorKind::UnexpectedEof.into());
        }
        done += count;
    }
    Ok(Some(bytes))
}

async fn mount_one(
    table: &Rc<RefCell<mounts::MountTable>>,
    caches: &admission::FreeCaches,
    config: ValidatedMount,
    role: Role,
) -> Result<()> {
    let (id, kind) = mounts::stat_path(table, role, &config.path).await?;
    if kind != EntryKind::Directory {
        return Err(ErrorKind::NotADirectory.into());
    }
    let point = mounts::Resolved::resolve(table, id)?;
    let (mode, empty) = {
        let fs = point.read().await?;
        let metadata = fs.metadata(role, point.local).await;
        point.healthy()?;
        // Information only. A directory's size is its entry count.
        let empty = match &metadata {
            Ok(metadata) if metadata.size == 0 => "yes",
            Ok(_) => "no",
            Err(_) => "unknown",
        };
        let mode = match config.mode {
            Some(mode) => mode,
            None => metadata?.permissions()?,
        };
        (mode, empty)
    };
    let ram = super::super::guest_ram_mib() << 20;
    let memfs = memfs::MemFs::new(memfs::MemFsConfig {
        max_size: config
            .max_size
            .unwrap_or_else(|| admission::default_capacity(ram)),
        free_cache_cap: admission::cache_capacity(ram),
        root_mode: mode,
    })?;
    let cache = memfs.free_block_cache();
    let cap = memfs.max_size();
    let path = config.path;
    let id = table.borrow_mut().insert(
        FS::MemFs(memfs),
        mounts::MountPoint {
            mount: point.mount,
            shadowed: point.local,
            path: path.clone(),
        },
    )?;
    caches.add(cache);
    log::debug!("mounted memfs {id} at {path}, cap {cap} bytes, shadowed directory empty: {empty}");
    Ok(())
}

pub(super) async fn load(
    table: &Rc<RefCell<mounts::MountTable>>,
    caches: &admission::FreeCaches,
) -> Result<()> {
    let Some(bytes) = read_root_file(table, "/system/cfg/sys-fs.toml").await? else {
        return Ok(());
    };
    let text = std::str::from_utf8(&bytes).map_err(|err| invalid(err.to_string()))?;
    for mount in parse(text)? {
        let path = mount.path.clone();
        mount_one(table, caches, mount, Role::System)
            .await
            .inspect_err(|err| log::error!("Cannot mount memfs at {path}: {err}"))?;
    }
    Ok(())
}

#[cfg(debug_assertions)]
pub(super) mod self_test {
    use super::*;
    use crate::self_test::{st_assert, st_assert_eq};

    pub(in crate::runtime::fs) const TESTS: &[crate::self_test::SelfTest] =
        &[("fs::mount_config", run)];

    fn run() -> std::result::Result<(), String> {
        for path in [
            "/",
            "relative",
            "/a/",
            "//a",
            "/a//b",
            "/a/./b",
            "/a/../b",
            "/system",
            "/system/cfg",
            "/system/cfg/libc",
        ] {
            st_assert!(parse(&format!("[[mount]]\ntype='memfs'\npath='{path}'")).is_err());
        }
        for config in [
            "[[mount]]\ntype='other'\npath='/a'",
            "[[mount]]\ntype='memfs'\npath='/a'\nunknown=1",
            "[[mount]]\ntype='memfs'\npath='/a'\nmax_size=-1",
            "[[mount]]\ntype='memfs'\npath='/a'\nmax_size='18446744073709551615G'",
            "[[mount]]\ntype='memfs'\npath='/a'\nmode='r--rwxrwx'",
            "[[mount]]\ntype='memfs'\npath='/a/b'\n[[mount]]\ntype='memfs'\npath='/a'",
            "[[mount]]\ntype='memfs'\npath='/a'\n[[mount]]\ntype='memfs'\npath='/a'",
        ] {
            st_assert!(parse(config).is_err());
        }
        // Errors in an entry name it.
        for value in [
            "max_size='12X'",
            "mode='rwx'",
            "max_size=-1",
            "mode=123",
            "unknown=1",
        ] {
            st_assert!(
                parse(&format!("[[mount]]\ntype='memfs'\npath='/named'\n{value}"))
                    .is_err_and(|err| err.to_string().contains("/named"))
            );
        }
        st_assert!(
            parse("[[mount]]\ntype='memfs'\npath='/a'\n[[mount]]\ntype='memfs'\npath=5")
                .is_err_and(|err| err.to_string().contains("mount #2:"))
        );
        st_assert!(
            parse(&format!(
                "[[mount]]\ntype='memfs'\npath='/{}'",
                "a".repeat(1024)
            ))
            .is_err()
        );
        let many: String = (0..256)
            .map(|i| format!("[[mount]]\ntype='memfs'\npath='/m{i}'\n"))
            .collect();
        st_assert!(parse(&many).is_err());
        st_assert!(parse(&many[..many.rfind("[[mount]]").unwrap()]).is_ok());
        let valid =
            parse("[[mount]]\ntype='memfs'\npath='/system/cfg2'\nmax_size='64M'\nmode='rwxr-x---'")
                .map_err(|err| err.to_string())?;
        st_assert_eq!(valid[0].max_size, Some(64 << 20));
        for (value, expected) in [("1024", 1024), ("2K", 2048), ("3G", 3 << 30)] {
            st_assert_eq!(size(Size::Text(value.into())).unwrap(), expected);
        }
        st_assert!(
            parse("[[mount]]\ntype='memfs'\npath='/a'\n[[mount]]\ntype='memfs'\npath='/a/b'")
                .is_ok()
        );
        st_assert!(
            parse("[[mount]]\ntype='memfs'\npath='/ab'\n[[mount]]\ntype='memfs'\npath='/a'")
                .is_ok()
        );

        moto_async::LocalRuntime::new().block_on(async {
            let runtime = super::super::self_test::runtime().map_err(|err| err.to_string())?;
            load(&runtime.mounts, &runtime.free_caches)
                .await
                .map_err(|err| err.to_string())?;
            st_assert_eq!(runtime.mounts.borrow().iter().count(), 1);
            let root = runtime.root().map_err(|err| err.to_string())?;
            let parent_mode = RolePermissions::new(
                AccessPermissions::Rwx,
                AccessPermissions::Rx,
                AccessPermissions::R,
            );
            let point = root
                .write()
                .await
                .map_err(|err| err.to_string())?
                .create_entry(
                    Role::System,
                    ROOT_ID,
                    EntryKind::Directory,
                    "a",
                    parent_mode,
                )
                .await
                .map_err(|err| err.to_string())?;
            root.check_local(point).map_err(|err| err.to_string())?;
            root.write()
                .await
                .map_err(|err| err.to_string())?
                .create_entry(Role::System, point, EntryKind::Directory, "b", parent_mode)
                .await
                .map_err(|err| err.to_string())?;
            mount_one(
                &runtime.mounts,
                &runtime.free_caches,
                ValidatedMount {
                    path: "/a".into(),
                    max_size: Some(4096),
                    mode: None,
                },
                Role::System,
            )
            .await
            .map_err(|err| err.to_string())?;
            let point = runtime.resolve(point).map_err(|err| err.to_string())?;
            st_assert_eq!(
                point
                    .read()
                    .await
                    .unwrap()
                    .metadata(Role::System, point.local)
                    .await
                    .unwrap()
                    .permissions()
                    .unwrap(),
                parent_mode
            );
            st_assert_eq!(
                mount_one(
                    &runtime.mounts,
                    &runtime.free_caches,
                    ValidatedMount {
                        path: "/a/b".into(),
                        max_size: None,
                        mode: None
                    },
                    Role::System
                )
                .await
                .unwrap_err()
                .kind(),
                ErrorKind::NotFound
            );

            // Mounting needs no `x` on the directory, and a configured mode
            // replaces the shadowed directory's.
            let closed = root
                .write()
                .await
                .map_err(|err| err.to_string())?
                .create_entry(
                    Role::System,
                    ROOT_ID,
                    EntryKind::Directory,
                    "closed",
                    RolePermissions::all(AccessPermissions::Rw),
                )
                .await
                .map_err(|err| err.to_string())?;
            let configured = RolePermissions::all(AccessPermissions::Rwx);
            mount_one(
                &runtime.mounts,
                &runtime.free_caches,
                ValidatedMount {
                    path: "/closed".into(),
                    max_size: Some(4096),
                    mode: Some(configured),
                },
                Role::System,
            )
            .await
            .map_err(|err| err.to_string())?;
            let closed = runtime.resolve(closed).map_err(|err| err.to_string())?;
            let mounted = closed
                .read()
                .await
                .map_err(|err| err.to_string())?
                .metadata(Role::System, closed.local)
                .await
                .map_err(|err| err.to_string())?;
            st_assert_eq!(
                mounted.permissions().map_err(|err| err.to_string())?,
                configured
            );
            Ok(())
        })
    }
}
