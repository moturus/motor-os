//! Memfs physical-memory limit and reactive cache reclamation.
use memfs::FreeBlockCache;
use moto_sdk::sys_io::api_fs::{self, MountKind};
use std::cell::RefCell;
use std::io::{ErrorKind, Result};

#[derive(Default)]
pub(crate) struct FreeCaches(RefCell<Vec<FreeBlockCache>>);

impl FreeCaches {
    pub(super) fn add(&self, cache: FreeBlockCache) {
        self.0.borrow_mut().push(cache);
    }

    pub(crate) fn reclaim(&self) {
        for cache in self.0.borrow().iter() {
            cache.release_free_blocks();
        }
    }

    pub(crate) fn reclaim_if_pressured(&self) {
        if moto_sys::memory_pressure() {
            self.reclaim();
        }
    }

    /// Re-evaluate the relevant signal exactly once after reclaiming. This
    /// runs before an operation, without FS locks, and never replays work.
    fn refused(&self, mut free_pages: impl FnMut() -> u64) -> bool {
        if free_pages() >= MIN_FREE_PAGES {
            return false;
        }
        self.reclaim();
        free_pages() < MIN_FREE_PAGES
    }

    pub(super) fn check(&self, stats: &super::stats::FsStats) -> Result<()> {
        if !self.refused(|| {
            moto_sys::KernelStaticPage::get()
                .free_pages
                .load(std::sync::atomic::Ordering::Relaxed)
        }) {
            return Ok(());
        }
        stats.memory_refused.set(stats.memory_refused.get() + 1);
        Err(ErrorKind::StorageFull.into())
    }
}

const MIN_FREE_PAGES: u64 = 1024; // 4 MiB for every guest size.

pub(super) fn needs_memory(command: u16, destination: MountKind) -> bool {
    destination == MountKind::MemFs
        && matches!(
            command,
            api_fs::CMD_WRITE
                | api_fs::CMD_CREATE_FILE
                | api_fs::CMD_CREATE_DIR
                | api_fs::CMD_CREATE_WITH_PERMISSIONS
                | api_fs::CMD_MOVE_ENTRY
                | api_fs::CMD_MOVE_NOREPLACE
                | api_fs::CMD_COPY_FILE_RANGE
        )
}

pub(super) fn default_capacity(ram: u64) -> u64 {
    (ram & !((1 << 24) - 1))
        .saturating_sub(16 << 20)
        .max(8 << 20)
}

pub(super) fn cache_capacity(ram: u64) -> u64 {
    if ram >= 256 << 20 {
        (ram / 20).max(16 << 20)
    } else if ram >= 128 << 20 {
        8 << 20
    } else if ram >= 64 << 20 {
        4 << 20
    } else {
        2 << 20
    }
}

#[cfg(debug_assertions)]
pub(super) mod self_test {
    use super::*;
    use crate::self_test::{st_assert, st_assert_eq};
    pub(in crate::runtime::fs) const TESTS: &[crate::self_test::SelfTest] =
        &[("fs::memfs_memory", run)];

    fn run() -> std::result::Result<(), String> {
        for command in api_fs::CMD_STAT..=api_fs::CMD_GET_MOUNTS {
            st_assert!(!needs_memory(command, MountKind::MotorFs));
            st_assert_eq!(
                needs_memory(command, MountKind::MemFs),
                [
                    api_fs::CMD_CREATE_FILE,
                    api_fs::CMD_CREATE_DIR,
                    api_fs::CMD_WRITE,
                    api_fs::CMD_MOVE_ENTRY,
                    api_fs::CMD_COPY_FILE_RANGE,
                    api_fs::CMD_MOVE_NOREPLACE,
                    api_fs::CMD_CREATE_WITH_PERMISSIONS,
                ]
                .contains(&command)
            );
        }
        for (ram, cap, cache) in [
            (16, 8, 2),
            (31, 8, 2),
            (32, 16, 2),
            (63, 32, 2),
            (64, 48, 4),
            (128, 112, 8),
            (256, 240, 16),
            (1024, 1008, 51),
        ] {
            st_assert_eq!(default_capacity(ram << 20) >> 20, cap);
            st_assert_eq!(cache_capacity(ram << 20) >> 20, cache);
        }
        let super::super::FS::MemFs(mut fs) =
            super::super::self_test::memfs(1 << 20).map_err(|err| err.to_string())?
        else {
            return Err("memfs fixture".into());
        };
        let entry = fs
            .create_entry_sync(
                moto_sdk::async_fs::Role::None,
                0,
                moto_sdk::async_fs::EntryKind::File,
                "cache",
                moto_sdk::async_fs::RolePermissions::all(
                    moto_sdk::async_fs::AccessPermissions::Rwx,
                ),
            )
            .map_err(|err| err.to_string())?;
        fs.write_sync(moto_sdk::async_fs::Role::None, entry, 0, &[42; 4096])
            .map_err(|err| err.to_string())?;
        fs.delete_entry_sync(moto_sdk::async_fs::Role::None, entry)
            .map_err(|err| err.to_string())?;
        let caches = FreeCaches::default();
        caches.add(fs.free_block_cache());
        st_assert_eq!(fs.cached_free_bytes(), 4096);
        let mut samples = 0;
        st_assert!(!caches.refused(|| {
            samples += 1;
            MIN_FREE_PAGES
        }));
        st_assert_eq!(samples, 1);
        st_assert_eq!(fs.cached_free_bytes(), 4096);
        samples = 0;
        st_assert!(!caches.refused(|| {
            samples += 1;
            MIN_FREE_PAGES - u64::from(fs.cached_free_bytes() != 0)
        }));
        st_assert_eq!(samples, 2);
        st_assert_eq!(fs.cached_free_bytes(), 0);
        st_assert!(caches.refused(|| MIN_FREE_PAGES - 1));
        st_assert!(!caches.refused(|| MIN_FREE_PAGES + 1));
        caches.reclaim(); // Empty and repeated drains free no page twice.
        Ok(())
    }
}
