//! Internal mount-qualified identities. No table borrow survives a lock await.

use super::FS;
use async_fs::{EntryId, EntryKind, FileSystem, ROOT_ID, Role};
use moto_async::{LocalRwLock, LocalRwLockReadGuard, LocalRwLockWriteGuard};
use moto_sys_io::api_fs::{MountInfo, MountKind};
use std::cell::RefCell;
use std::io::{ErrorKind, Result};
use std::rc::Rc;

pub(super) type MountId = u32;
const MAX_MOUNT_ID: MountId = (1 << 24) - 1;
const LOCAL_MASK: u128 =
    (async_fs::MAX_FS_BLOCKS - 1) as u128 | (((async_fs::MAX_FS_GENERATIONS - 1) as u128) << 64);

pub(super) fn split(id: EntryId) -> (MountId, EntryId) {
    (
        (((id >> 112) | ((id >> 40) & 0xff0000)) as u32),
        id & LOCAL_MASK,
    )
}

pub(super) fn join(mount: MountId, local: EntryId) -> EntryId {
    local | (((mount & 0xffff) as u128) << 112) | (((mount >> 16) as u128) << 56)
}

pub(super) struct Mount {
    pub id: MountId,
    fs: Rc<LocalRwLock<FS>>,
    pub kind: MountKind,
    pub parent: Option<MountPoint>,
    pub corrupted: bool,
}

pub(super) struct MountPoint {
    pub mount: MountId,
    pub shadowed: EntryId,
    pub path: String,
}

impl Mount {
    pub fn path(&self) -> &str {
        self.parent
            .as_ref()
            .map_or("/", |parent| parent.path.as_str())
    }
}

pub(crate) struct MountTable {
    mounts: Vec<Mount>,
    next_id: MountId,
}

impl MountTable {
    pub fn new(root: FS) -> Self {
        let kind = match &root {
            FS::MotorFs(_) => MountKind::MotorFs,
            FS::MemFs(_) => MountKind::MemFs,
        };
        Self {
            mounts: vec![Mount {
                id: 0,
                fs: Rc::new(LocalRwLock::new(root)),
                kind,
                parent: None,
                corrupted: false,
            }],
            next_id: 1,
        }
    }

    pub(super) fn find(&self, id: MountId) -> Option<&Mount> {
        self.mounts.iter().find(|mount| mount.id == id)
    }

    pub(super) fn find_by_mount_point(&self, parent: MountId, shadowed: EntryId) -> Option<&Mount> {
        self.iter().find(|mount| {
            mount
                .parent
                .as_ref()
                .is_some_and(|point| point.mount == parent && point.shadowed == shadowed)
        })
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &Mount> {
        self.mounts.iter()
    }

    pub(super) fn insert(
        &mut self,
        fs: FS,
        kind: MountKind,
        parent: MountPoint,
    ) -> Result<MountId> {
        if self.next_id > MAX_MOUNT_ID {
            return Err(ErrorKind::StorageFull.into());
        }
        self.healthy(parent.mount)?;
        if self
            .find_by_mount_point(parent.mount, parent.shadowed)
            .is_some()
        {
            return Err(ErrorKind::AlreadyExists.into());
        }
        let id = self.next_id;
        self.mounts.push(Mount {
            id,
            fs: Rc::new(LocalRwLock::new(fs)),
            kind,
            parent: Some(parent),
            corrupted: false,
        });
        self.next_id += 1;
        Ok(id)
    }

    fn mark_corrupted(&mut self, id: MountId, local: EntryId) {
        if let Some(mount) = self.mounts.iter_mut().find(|mount| mount.id == id)
            && !mount.corrupted
        {
            log::error!(
                "FS mount {} ({:?}, {}) returned invalid local ID {local:x}; quarantined until reboot",
                mount.id,
                mount.kind,
                mount.path()
            );
            mount.corrupted = true;
        }
    }

    fn healthy(&self, id: MountId) -> Result<&Mount> {
        let mount = self.find(id).ok_or(ErrorKind::InvalidInput)?;
        if mount.corrupted {
            Err(ErrorKind::InvalidData.into())
        } else {
            Ok(mount)
        }
    }
}

/// A resolved entry owns the lock handle, so its guards never borrow the table.
/// `id` is canonical internal identity; only `local` is passed to the backend.
pub(crate) struct Resolved {
    pub mount: MountId,
    pub local: EntryId,
    pub id: EntryId,
    pub kind: MountKind,
    fs: Rc<LocalRwLock<FS>>,
    table: Rc<RefCell<MountTable>>,
    /// Aliasing/forwarding must also recheck the originating mount after waits.
    origin: Option<MountId>,
}

impl Resolved {
    /// Explicit mount access, also used for root-FS internals and forwarding.
    pub fn on_mount(
        table: &Rc<RefCell<MountTable>>,
        mount: MountId,
        local: EntryId,
    ) -> Result<Self> {
        let mounts = table.borrow();
        let found = mounts.healthy(mount)?;
        Ok(Self {
            mount,
            local,
            id: join(mount, local),
            kind: found.kind,
            fs: found.fs.clone(),
            table: table.clone(),
            origin: None,
        })
    }

    pub fn resolve(table: &Rc<RefCell<MountTable>>, internal: EntryId) -> Result<Self> {
        let (mut mount, mut local) = split(internal);
        let origin = mount;
        {
            let mounts = table.borrow();
            mounts.healthy(mount)?;
            if let Some(alias) = mounts.find_by_mount_point(mount, local) {
                mount = alias.id;
                local = ROOT_ID;
            }
        }
        let mut resolved = Self::on_mount(table, mount, local)?;
        resolved.origin = (mount != origin).then_some(origin);
        Ok(resolved)
    }

    pub fn healthy(&self) -> Result<()> {
        let mounts = self.table.borrow();
        mounts.healthy(self.mount)?;
        if let Some(origin) = self.origin {
            mounts.healthy(origin)?;
        }
        Ok(())
    }

    pub async fn read(&self) -> Result<LocalRwLockReadGuard<'_, FS>> {
        self.healthy()?;
        let guard = self.fs.read().await;
        self.healthy()?;
        Ok(guard)
    }

    pub async fn write(&self) -> Result<LocalRwLockWriteGuard<'_, FS>> {
        self.healthy()?;
        let guard = self.fs.write().await;
        self.healthy()?;
        Ok(guard)
    }

    /// Backend output validation; never apply this check to a client ID.
    pub fn check_local(&self, local: EntryId) -> Result<EntryId> {
        self.healthy()?;
        if local & !LOCAL_MASK != 0 {
            self.table.borrow_mut().mark_corrupted(self.mount, local);
            return Err(ErrorKind::InvalidData.into());
        }
        Ok(local)
    }

    pub fn export(&self, local: EntryId) -> Result<EntryId> {
        self.check_local(local)?;
        Ok(Self::resolve(&self.table, join(self.mount, local))?.id)
    }

    pub fn is_mount_root(&self) -> bool {
        self.mount != 0 && self.local == ROOT_ID
    }

    pub fn protect_root(&self) -> Result<()> {
        if self.is_mount_root() {
            Err(super::map_native_error(moto_rt::Error::NotAllowed))
        } else {
            Ok(())
        }
    }

    /// Name/sibling requests on a mounted root refer to the shadowed entry.
    pub fn namespace_entry(self) -> Result<Self> {
        if !self.is_mount_root() {
            return Ok(self);
        }
        self.healthy()?;
        let (mount, local) = {
            let mounts = self.table.borrow();
            let point = mounts
                .healthy(self.mount)?
                .parent
                .as_ref()
                .ok_or(ErrorKind::InvalidData)?;
            (point.mount, point.shadowed)
        };
        let mut forwarded = Self::on_mount(&self.table, mount, local)?;
        forwarded.origin = Some(self.mount);
        Ok(forwarded)
    }
}

pub(super) async fn stat_path(
    table: &Rc<RefCell<MountTable>>,
    role: Role,
    path: &str,
) -> Result<(EntryId, EntryKind)> {
    if !path.starts_with('/') {
        return Err(ErrorKind::InvalidInput.into());
    }
    let (mut id, mut kind) = (ROOT_ID, EntryKind::Directory);
    // Even "/" goes through the root corruption gate.
    Resolved::resolve(table, id)?;
    for name in path.split('/').filter(|name| !name.is_empty()) {
        if kind != EntryKind::Directory {
            return Err(ErrorKind::NotFound.into());
        }
        let entry = Resolved::resolve(table, id)?;
        let fs = entry.read().await?;
        let (local, next_kind) = fs
            .stat(role, entry.local, name)
            .await?
            .ok_or(ErrorKind::NotFound)?;
        id = entry.export(local)?;
        kind = next_kind;
        // The guard drops before resolving the next component.
    }
    Ok((id, kind))
}

pub(super) async fn flush(table: &Rc<RefCell<MountTable>>) -> Result<()> {
    let count = table.borrow().iter().count();
    let mut first_error = None;
    let mut corrupted = false;
    for index in 0..count {
        let id = table.borrow().iter().nth(index).unwrap().id;
        let result = async {
            let entry = Resolved::on_mount(table, id, ROOT_ID)?;
            let mut fs = entry.write().await?;
            fs.flush().await
        }
        .await;
        if let Err(err) = result {
            corrupted |= table.borrow().find(id).is_some_and(|mount| mount.corrupted);
            if first_error.is_none() {
                first_error = Some(err);
            }
        }
    }
    if corrupted {
        Err(ErrorKind::InvalidData.into())
    } else {
        first_error.map_or(Ok(()), Err)
    }
}

pub(super) async fn info(table: &Rc<RefCell<MountTable>>, cursor: u32) -> Result<MountInfo> {
    let mut info = {
        let mounts = table.borrow();
        let mount = mounts
            .iter()
            .nth(cursor as usize)
            .ok_or(ErrorKind::InvalidInput)?;
        MountInfo {
            id: mount.id,
            kind: mount.kind,
            path: mount.path().to_owned(),
            corrupted: mount.corrupted,
            used: None,
            entries: None,
            cap: None,
        }
    };
    if !info.corrupted {
        let result = async {
            let entry = Resolved::on_mount(table, info.id, ROOT_ID)?;
            let fs = entry.read().await?;
            match &*fs {
                FS::MotorFs(fs) => {
                    let blocks = fs.num_blocks();
                    info.used = disk_usage(blocks, fs.empty_blocks().await?);
                    info.cap = Some(blocks * async_fs::BLOCK_SIZE as u64);
                }
                FS::MemFs(fs) => {
                    info.used = Some(fs.used_bytes());
                    info.entries = Some(fs.entry_count());
                    info.cap = Some(fs.max_size());
                }
            }
            entry.healthy()
        }
        .await;
        if let Err(err) = result {
            if !table
                .borrow()
                .find(info.id)
                .is_some_and(|mount| mount.corrupted)
            {
                return Err(err);
            }
            info.corrupted = true;
            info.used = None;
            info.entries = None;
            info.cap = None;
        }
    }
    Ok(info)
}

/// Disk usage from the device's block count and the superblock's free count.
/// A corrupt free count yields unknown usage instead of an underflow.
fn disk_usage(blocks: u64, free: u64) -> Option<u64> {
    blocks
        .checked_sub(free)
        .and_then(|used| used.checked_mul(async_fs::BLOCK_SIZE as u64))
}

#[cfg(debug_assertions)]
pub(super) mod self_test {
    use super::*;
    use crate::self_test::{st_assert, st_assert_eq};
    use std::task::Poll;

    pub(in crate::runtime::fs) const TESTS: &[crate::self_test::SelfTest] = &[("fs::mounts", run)];

    fn run() -> std::result::Result<(), String> {
        moto_async::LocalRuntime::new()
            .block_on(check())
            .map_err(|err| err.to_string())
    }

    async fn check() -> std::result::Result<(), String> {
        st_assert_eq!(disk_usage(10, 4), Some(6 * 4096));
        st_assert_eq!(disk_usage(10, 11), None);
        st_assert_eq!(disk_usage(u64::MAX, 0), None);
        let checked = async {
            for mount in [0, 1, 65535, 65536, MAX_MOUNT_ID] {
                for local in [0, 1, 1 << 64, LOCAL_MASK] {
                    if split(join(mount, local)) != (mount, local) {
                        return Err(std::io::Error::other("mount packing"));
                    }
                }
            }
            let runtime = super::super::self_test::runtime()?;
            let root = runtime.root()?;
            let shadowed = root
                .write()
                .await?
                .create_entry(
                    Role::System,
                    ROOT_ID,
                    EntryKind::Directory,
                    "mounted",
                    async_fs::RolePermissions::all(async_fs::AccessPermissions::Rwx),
                )
                .await?;
            root.check_local(shadowed)?;
            let id = runtime.mounts.borrow_mut().insert(
                super::super::self_test::memfs(1 << 20)?,
                MountKind::MemFs,
                MountPoint {
                    mount: 0,
                    shadowed,
                    path: "/mounted".into(),
                },
            )?;
            let canonical = join(id, ROOT_ID);
            if root.export(shadowed)? != canonical
                || runtime.resolve(shadowed)?.id != canonical
                || stat_path(&runtime.mounts, Role::None, "/mounted").await?.0 != canonical
            {
                return Err(std::io::Error::other("mount aliases"));
            }
            let forwarded = runtime.resolve(canonical)?.namespace_entry()?;
            if forwarded.mount != 0
                || forwarded.local != shadowed
                || forwarded.read().await?.name(Role::None, shadowed).await? != "mounted"
            {
                return Err(std::io::Error::other("name forwarding"));
            }
            Ok((runtime, root, id, shadowed))
        }
        .await
        .map_err(|err: std::io::Error| err.to_string())?;
        let (runtime, root, id, shadowed) = checked;
        st_assert_eq!(
            runtime.resolve(join(id + 1, 0)).err().unwrap().kind(),
            ErrorKind::InvalidInput
        );
        st_assert!(!runtime.mounts.borrow().find(0).unwrap().corrupted);

        // A queued accessor must recheck quarantine after acquiring its guard.
        let entry = runtime
            .resolve(join(id, 0))
            .map_err(|err| err.to_string())?;
        let forwarded = runtime
            .resolve(entry.id)
            .unwrap()
            .namespace_entry()
            .unwrap();
        let writer = entry.write().await.map_err(|err| err.to_string())?;
        let mut pending = core::pin::pin!(entry.read());
        st_assert!(
            core::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx).is_pending())).await
        );
        st_assert_eq!(
            entry.check_local(1 << 112).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        drop(writer);
        st_assert_eq!(pending.await.err().unwrap().kind(), ErrorKind::InvalidData);
        st_assert_eq!(
            forwarded.read().await.err().unwrap().kind(),
            ErrorKind::InvalidData
        );
        super::super::spawn::self_test::quarantined_read(&runtime, entry.id).await?;
        st_assert_eq!(
            root.export(shadowed).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        st_assert_eq!(
            runtime.resolve(shadowed).err().unwrap().kind(),
            ErrorKind::InvalidData
        );
        let record = info(&runtime.mounts, 1)
            .await
            .map_err(|err| err.to_string())?;
        st_assert!(
            record.corrupted
                && record.used.is_none()
                && record.cap.is_none()
                && record.entries.is_none()
        );
        st_assert_eq!(
            flush(&runtime.mounts).await.unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        st_assert!(root.read().await.is_ok());

        // Conversely, a corrupted parent blocks forwarding but leaves already
        // known IDs on another healthy mount usable.
        let healthy = runtime
            .mounts
            .borrow_mut()
            .insert(
                super::super::self_test::memfs(1 << 20).map_err(|err| err.to_string())?,
                MountKind::MemFs,
                MountPoint {
                    mount: 0,
                    shadowed: shadowed + 1,
                    path: "/other".into(),
                },
            )
            .map_err(|err| err.to_string())?;
        let alias = runtime
            .resolve(shadowed + 1)
            .map_err(|err| err.to_string())?;
        st_assert_eq!(
            root.check_local(1 << 56).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        st_assert_eq!(
            alias.read().await.err().unwrap().kind(),
            ErrorKind::InvalidData
        );
        st_assert!(
            runtime
                .resolve(join(healthy, 0))
                .unwrap()
                .read()
                .await
                .is_ok()
        );
        st_assert_eq!(
            runtime
                .resolve(join(healthy, 0))
                .unwrap()
                .namespace_entry()
                .err()
                .unwrap()
                .kind(),
            ErrorKind::InvalidData
        );
        st_assert_eq!(
            runtime
                .read_root_file("/system/cfg/sys-net.toml")
                .await
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
        st_assert!(
            super::super::stats::entries(&runtime)
                .await
                .iter()
                .all(|metric| {
                    ![1000, 1001, 1002, 1003, 1004, 1017, 1028, 1029, 1030].contains(&metric.metric)
                })
        );

        let runtime = super::super::self_test::runtime().map_err(|err| err.to_string())?;
        runtime.mounts.borrow_mut().next_id = MAX_MOUNT_ID + 1;
        st_assert_eq!(
            runtime
                .mounts
                .borrow_mut()
                .insert(
                    super::super::self_test::memfs(1 << 20).map_err(|err| err.to_string())?,
                    MountKind::MemFs,
                    MountPoint {
                        mount: 0,
                        shadowed: 1,
                        path: "/full".into()
                    },
                )
                .unwrap_err()
                .kind(),
            ErrorKind::StorageFull
        );
        Ok(())
    }
}
