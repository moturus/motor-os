//! Bounded boot configuration, fully validated before applying any mount.
use super::{FS, devices::Devices, memory, mounts};
use moto_sdk::async_fs::{
    AccessPermissions, EntryKind, FileSystem, ROOT_ID, Role, RolePermissions,
};
use moto_sdk::sys_io::api_fs::MountBlockSource;
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
    #[serde(default)]
    root: RootConfig,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootConfig {
    #[serde(default)]
    read_only: bool,
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
    #[serde(rename = "motor-fs")]
    MotorFs {
        path: String,
        device: u32,
        partition: Option<u8>,
        cache_mb: Option<u64>,
        #[serde(default)]
        read_only: bool,
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
    backend: Backend,
}

#[derive(Clone, Copy)]
enum Backend {
    MemFs {
        max_size: Option<u64>,
        mode: Option<RolePermissions>,
    },
    MotorFs {
        source: MountBlockSource,
        cache_blocks: usize,
        read_only: bool,
    },
}

struct ValidatedConfig {
    root_read_only: bool,
    mounts: Vec<ValidatedMount>,
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
    if !moto_sdk::async_fs::perms_monotonic(permissions) {
        return Err(invalid("non-monotonic mode"));
    }
    Ok(permissions)
}

fn ancestor(parent: &str, child: &str) -> bool {
    child
        .strip_prefix(parent)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

fn parse(
    text: &str,
    root_source: Option<MountBlockSource>,
    budget: usize,
) -> Result<ValidatedConfig> {
    let config: Config = toml::from_str(text).map_err(|err| invalid(err.to_string()))?;
    if config.mount.len() > 255 {
        return Err(invalid("more than 255 mounts"));
    }
    let mut mounts: Vec<ValidatedMount> = Vec::with_capacity(config.mount.len());
    let disk_count = config
        .mount
        .iter()
        .filter(|table| table.get("type").and_then(toml::Value::as_str) == Some("motor-fs"))
        .count();
    let default_cache = budget.checked_div(disk_count).unwrap_or(0);
    let mut sources: Vec<_> = root_source.into_iter().collect();
    for (index, table) in config.mount.into_iter().enumerate() {
        let name = match table.get("path") {
            Some(toml::Value::String(path)) => path.clone(),
            _ => format!("#{}", index + 1),
        };
        let source_name = if table.get("type").and_then(toml::Value::as_str) == Some("motor-fs") {
            format!(
                "device {}, partition {}",
                table
                    .get("device")
                    .map_or_else(|| "missing".into(), ToString::to_string),
                table
                    .get("partition")
                    .map_or_else(|| "whole device".into(), ToString::to_string)
            )
        } else {
            table
                .get("type")
                .and_then(toml::Value::as_str)
                .unwrap_or("unknown filesystem")
                .into()
        };
        let named = |err: &dyn std::fmt::Display| {
            invalid(format!(
                "mount {name}: entry {}, {source_name}: {err}",
                index + 1
            ))
        };
        let mount: MountConfig = toml::Value::Table(table)
            .try_into()
            .map_err(|err| named(&err))?;
        let (path, backend) = match mount {
            MountConfig::MemFs {
                path,
                max_size,
                mode: root_mode,
            } => (
                path,
                Backend::MemFs {
                    max_size: max_size.map(size).transpose().map_err(|err| named(&err))?,
                    mode: root_mode
                        .as_deref()
                        .map(mode)
                        .transpose()
                        .map_err(|err| named(&err))?,
                },
            ),
            MountConfig::MotorFs {
                path,
                device,
                partition,
                cache_mb,
                read_only,
            } => {
                let cache_blocks = match cache_mb {
                    Some(mb) => usize::try_from(mb)
                        .ok()
                        .and_then(|mb| mb.checked_mul(256))
                        .ok_or_else(|| named(&"cache_mb overflow"))?,
                    None => default_cache,
                };
                (
                    path,
                    Backend::MotorFs {
                        source: MountBlockSource { device, partition },
                        cache_blocks,
                        read_only,
                    },
                )
            }
        };
        if let Backend::MotorFs {
            source,
            cache_blocks,
            ..
        } = &backend
        {
            let error = if source
                .partition
                .is_some_and(|slot| !(1..=4).contains(&slot))
            {
                Some("partition must be an MBR slot from 1 through 4")
            } else if *cache_blocks < 256 {
                Some("cache must contain at least 1 MiB")
            } else if sources.iter().any(|earlier| {
                earlier.device == source.device
                    && (earlier.partition == source.partition
                        || earlier.partition.is_none()
                        || source.partition.is_none())
            }) {
                Some("repeated source or whole-device/partition conflict")
            } else {
                None
            };
            if let Some(error) = error {
                return Err(named(&format!("{source:?}: {error}")));
            }
            sources.push(*source);
        }
        if !path.starts_with('/')
            || path.len() > moto_rt::fs::MAX_PATH_LEN
            || path[1..]
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(named(&"mount path is not canonical"));
        }
        if path == "/system/cfg" || ancestor("/system/cfg", &path) || ancestor(&path, "/system/cfg")
        {
            return Err(named(&"mount hides system configuration"));
        }
        if mounts
            .iter()
            .any(|earlier| earlier.path == path || ancestor(&path, &earlier.path))
        {
            return Err(named(&"mount hides an earlier mount"));
        }
        mounts.push(ValidatedMount { path, backend });
    }
    if config.root.read_only
        && !mounts.iter().any(|mount| {
            mount.path == "/system/logs"
                && matches!(
                    mount.backend,
                    Backend::MemFs { .. }
                        | Backend::MotorFs {
                            read_only: false,
                            ..
                        }
                )
        })
    {
        return Err(invalid(
            "read-only root requires a writable mount at exactly /system/logs",
        ));
    }
    Ok(ValidatedConfig {
        root_read_only: config.root.read_only,
        mounts,
    })
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
        let end = (done + moto_sdk::async_fs::BLOCK_SIZE - done % moto_sdk::async_fs::BLOCK_SIZE)
            .min(bytes.len());
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
    caches: &memory::FreeCaches,
    config: ValidatedMount,
    role: Role,
) -> Result<()> {
    let Backend::MemFs {
        max_size,
        mode: root_mode,
    } = config.backend
    else {
        return Err(ErrorKind::Unsupported.into());
    };
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
        let mode = match root_mode {
            Some(mode) => mode,
            None => metadata?.permissions()?,
        };
        (mode, empty)
    };
    let ram = super::super::guest_ram_mib() << 20;
    let memfs = memfs::MemFs::new(memfs::MemFsConfig {
        max_size: max_size.unwrap_or_else(|| memory::default_capacity(ram)),
        free_cache_cap: memory::cache_capacity(ram),
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

async fn mount_motor(
    table: &Rc<RefCell<mounts::MountTable>>,
    devices: &mut Devices,
    path: String,
    source: super::devices::Source,
    cache_blocks: usize,
    read_only: bool,
) -> Result<()> {
    let (id, kind) = mounts::stat_path(table, Role::System, &path).await?;
    if kind != EntryKind::Directory {
        return Err(ErrorKind::NotADirectory.into());
    }
    let point = mounts::Resolved::resolve(table, id)?;
    let fs = devices.open(source, cache_blocks).await?;
    let mut mounts = table.borrow_mut();
    let id = mounts.insert(
        fs,
        mounts::MountPoint {
            mount: point.mount,
            shadowed: point.local,
            path: path.clone(),
        },
    )?;
    let mount = mounts.find_mut(id).unwrap();
    mount.source = Some(source.identity);
    mount.read_only = read_only;
    let state = if read_only { "ro" } else { "rw" };
    log::info!(
        "mounted motor-fs {id} at {path}, {:?}, {state}, cache {cache_blocks} blocks",
        source.identity
    );
    Ok(())
}

pub(super) async fn load(
    table: &Rc<RefCell<mounts::MountTable>>,
    caches: &memory::FreeCaches,
    devices: &mut Devices,
) -> Result<()> {
    let bytes = read_root_file(table, "/system/cfg/sys-fs.toml")
        .await?
        .unwrap_or_default();
    let text = std::str::from_utf8(&bytes).map_err(|err| invalid(err.to_string()))?;
    let source = table.borrow().find(0).and_then(|mount| mount.source);
    let config = parse(text, source, super::block_cache_blocks())?;
    if let Some(source) = source
        && devices.read_only(source)?
        && !config.root_read_only
    {
        return Err(invalid(format!(
            "root /, {source:?}: writable mount on read-only device"
        )));
    }
    let mut resolved = Vec::with_capacity(config.mounts.len());
    for (index, mount) in config.mounts.iter().enumerate() {
        if let Backend::MotorFs {
            source, read_only, ..
        } = mount.backend
        {
            let extent = devices.resolve(source).await.map_err(|error| {
                invalid(format!(
                    "mount {} at {:?}, {source:?}: {error}",
                    index + 1,
                    mount.path
                ))
            })?;
            if devices.read_only(source)? && !read_only {
                return Err(invalid(format!(
                    "mount {} at {:?}, {source:?}: writable mount on read-only device",
                    index + 1,
                    mount.path
                )));
            }
            resolved.push(Some(extent));
        } else {
            resolved.push(None);
        }
    }
    for (index, (mount, source)) in config.mounts.into_iter().zip(resolved).enumerate() {
        let context = format!(
            "entry {}, path {:?}, source {}",
            index + 1,
            mount.path,
            source.map_or_else(|| "memfs".into(), |source| format!("{:?}", source.identity))
        );
        let result = match mount.backend {
            Backend::MemFs { .. } => mount_one(table, caches, mount, Role::System).await,
            Backend::MotorFs {
                cache_blocks,
                read_only,
                ..
            } => {
                mount_motor(
                    table,
                    devices,
                    mount.path,
                    source.unwrap(),
                    cache_blocks,
                    read_only,
                )
                .await
            }
        };
        result.map_err(|error| invalid(format!("{context}: {error}")))?;
    }
    table.borrow_mut().find_mut(0).unwrap().read_only = config.root_read_only;
    log::info!(
        "mounted root 0 at /, {}",
        if config.root_read_only { "ro" } else { "rw" }
    );
    Ok(())
}

#[cfg(debug_assertions)]
pub(super) mod self_test {
    use super::*;
    use crate::self_test::{st_assert, st_assert_eq};

    pub(in crate::runtime::fs) const TESTS: &[crate::self_test::SelfTest] = &[
        ("fs::mount_config", run),
        ("fs::disk_mount_config", disk_config),
    ];

    fn parse(text: &str) -> Result<Vec<ValidatedMount>> {
        super::parse(
            text,
            Some(MountBlockSource {
                device: 0,
                partition: Some(3),
            }),
            4096,
        )
        .map(|config| config.mounts)
    }

    fn disk_config() -> std::result::Result<(), String> {
        let entry = |path: &str, device: u32, fields: &str| {
            format!("[[mount]]\ntype='motor-fs'\npath='{path}'\ndevice={device}\n{fields}\n")
        };
        for fields in [
            "partition=0",
            "partition=5",
            "partition=-1",
            "partition=1.0",
            "cache_mb=0",
            "cache_mb=-1",
            "cache_mb='1'",
            "cache_mb=1.0",
            "cache_mb=9223372036854775807",
            "read_only=1",
            "max_size='1M'",
            "mode='rwxrwxrwx'",
            "unknown=1",
        ] {
            st_assert!(
                parse(&entry("/named", 1, fields))
                    .is_err_and(|error| error.to_string().contains("/named"))
            );
        }
        for config in [
            "[[mount]]\ntype='motor-fs'\npath='/a'",
            "[[mount]]\ntype='motor-fs'\npath='/a'\ndevice=-1",
            "[[mount]]\ntype='memfs'\npath='/a'\ndevice=1",
            "[[mount]]\ntype='memfs'\npath='/a'\ncache_mb=1",
            "[[mount]]\ntype='memfs'\npath='/a'\nread_only=false",
            "[root]\nunknown=true",
            "[root]\nread_only='true'",
            "[root]\ncache_mb=1",
        ] {
            st_assert!(parse(config).is_err());
        }
        for pair in [
            entry("/a", 0, "partition=3"),
            entry("/a", 0, ""),
            entry("/a", 1, "partition=1") + &entry("/b", 1, "partition=1"),
            entry("/a", 1, "") + &entry("/b", 1, "partition=1"),
            entry("/a", 1, "partition=1") + &entry("/b", 1, ""),
        ] {
            st_assert!(parse(&pair).is_err());
        }
        st_assert!(parse(&(entry("/a", 0, "partition=4") + &entry("/a/b", 1, ""))).is_ok());
        let bare_root = Some(MountBlockSource {
            device: 0,
            partition: None,
        });
        st_assert!(super::parse(&entry("/a", 0, "partition=1"), bare_root, 4096).is_err());

        let two = entry("/a", 1, "") + &entry("/b", 2, "partition=4");
        for budget in [1024, 4096] {
            let mounts = super::parse(&two, None, budget).unwrap().mounts;
            for mount in mounts {
                st_assert!(
                    matches!(mount.backend, Backend::MotorFs { cache_blocks, .. } if cache_blocks == budget / 2)
                );
            }
        }
        let overridden = entry("/a", 1, "cache_mb=32") + &entry("/b", 2, "");
        let mounts = parse(&overridden).unwrap();
        st_assert!(matches!(
            mounts[0].backend,
            Backend::MotorFs {
                cache_blocks: 8192,
                ..
            }
        ));
        st_assert!(matches!(
            mounts[1].backend,
            Backend::MotorFs {
                cache_blocks: 2048,
                ..
            }
        ));
        let four: String = (1..=4)
            .map(|device| entry(&format!("/m{device}"), device, ""))
            .collect();
        st_assert!(super::parse(&four, None, 1024).is_ok());
        st_assert!(super::parse(&(four + &entry("/fifth", 5, "")), None, 1024).is_err());

        let root = "[root]\nread_only=true\n";
        st_assert!(parse(root).is_err());
        for bad in [
            entry("/system/logs/child", 1, ""),
            entry("/system/logs", 1, "read_only=true"),
        ] {
            st_assert!(parse(&(root.to_owned() + &bad)).is_err());
        }
        for logs in [
            "[[mount]]\ntype='memfs'\npath='/system/logs'\n".to_owned(),
            entry("/system/logs", 1, ""),
        ] {
            st_assert!(
                super::parse(&(root.to_owned() + &logs), None, 4096)
                    .unwrap()
                    .root_read_only
            );
        }
        Ok(())
    }

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
        st_assert!(
            matches!(valid[0].backend, Backend::MemFs { max_size: Some(cap), .. } if cap == 64 << 20)
        );
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

        moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
            let runtime = super::super::self_test::runtime().map_err(|err| err.to_string())?;
            let mut devices = Devices::new(Vec::new(), runtime.fs_stats.clone());
            load(&runtime.mounts, &runtime.free_caches, &mut devices)
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
                    backend: Backend::MemFs {
                        max_size: Some(4096),
                        mode: None,
                    },
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
                        backend: Backend::MemFs {
                            max_size: None,
                            mode: None
                        },
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
                    backend: Backend::MemFs {
                        max_size: Some(4096),
                        mode: Some(configured),
                    },
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
