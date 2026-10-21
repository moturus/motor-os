//! Synchronous, sparse in-memory filesystem with thin async-fs adapters.
//!
//! Capacity measures conservative storage charges, not allocator residency.
//! Callers supply both caps; RAM sizing and memory-pressure policy live outside
//! this crate. Live data pages and cached free pages have separate budgets.
//!
//! Charges are 512 bytes per entry (including the root), 128 per directory
//! link, and 64 per sparse-index slot, plus 4096 per live data block and the
//! byte length of each shared name, charged once. Logical file length and holes
//! are free. Entry counts include the root.

use async_fs::{
    AccessPermissions, EntryId, EntryKind, Metadata, Need, Role, RolePermissions, Timestamp,
};
use async_fs::{check_access, may_set, perms_monotonic, validate_filename};
use std::collections::BTreeMap;
use std::io::{ErrorKind, Result};
use std::ops::Bound::{Excluded, Unbounded};
use std::rc::Rc;

mod blocks;
mod data;
mod filesystem;
use blocks::Block;
pub use blocks::FreeBlockCache;

// Conservative per-item charges include BTreeMap node slack/links. The entry
// charge covers Metadata, the Entry value, its entry-map slot and the name's
// Rc header; directory links and sparse-index slots have separate charges.
// Name bytes are added once, without charging holes or allocator slack.
const ENTRY_CHARGE: u64 = 512;
const DIR_LINK_CHARGE: u64 = 128;
const BLOCK_CHARGE: u64 = async_fs::BLOCK_SIZE as u64 + 64;
const LOW_ID_MASK: u64 = async_fs::MAX_FS_BLOCKS - 1;
const ROLES: [Role; 3] = [Role::None, Role::Interactive, Role::System];

pub struct MemFsConfig {
    /// Maximum charged storage in bytes, including the root's metadata/name.
    pub max_size: u64,
    /// Maximum cached free bytes, rounded down to whole pages; initially empty.
    pub free_cache_cap: u64,
    /// Explicit, monotonic permissions for entry zero, the filesystem root.
    pub root_mode: RolePermissions,
}

pub struct MemFs {
    entries: BTreeMap<u64, Entry>,
    last_id: u64,
    used: u64,
    cap: u64,
    cache: FreeBlockCache,
}

struct Entry {
    metadata: Metadata,
    name: Rc<str>,
    parent: u64,
    contents: Contents,
}

enum Contents {
    Directory(BTreeMap<Rc<str>, u64>),
    File(BTreeMap<u64, Block>),
}

fn encode(id: u64) -> EntryId {
    // Leave bits 56..63 and 112..127 clear for future mount IDs (D7).
    (id & LOW_ID_MASK) as u128 | (((id >> 56) as u128) << 64)
}

fn decode(id: EntryId) -> Result<u64> {
    let counter = (id as u64 & LOW_ID_MASK) | (((id >> 64) as u64 & 255) << 56);
    if encode(counter) != id {
        return Err(ErrorKind::InvalidInput.into());
    }
    Ok(counter)
}

impl Entry {
    fn new(parent: u64, name: Rc<str>, kind: EntryKind, mode: RolePermissions) -> Self {
        let mut metadata = Metadata::zeroed();
        metadata.set_kind(kind);
        metadata.set_permissions(mode);
        metadata.created = Timestamp::now();
        metadata.modified = metadata.created;
        metadata.accessed = metadata.created;
        Self {
            metadata,
            name,
            parent,
            contents: match kind {
                EntryKind::Directory => Contents::Directory(BTreeMap::new()),
                EntryKind::File => Contents::File(BTreeMap::new()),
            },
        }
    }

    fn children(&self) -> Result<&BTreeMap<Rc<str>, u64>> {
        match &self.contents {
            Contents::Directory(children) => Ok(children),
            Contents::File(_) => Err(ErrorKind::NotADirectory.into()),
        }
    }

    fn blocks(&self) -> Result<&BTreeMap<u64, Block>> {
        match &self.contents {
            Contents::File(blocks) => Ok(blocks),
            Contents::Directory(_) => Err(ErrorKind::IsADirectory.into()),
        }
    }

    fn removable(&self) -> Result<()> {
        if let Contents::Directory(children) = &self.contents
            && !children.is_empty()
        {
            return Err(ErrorKind::DirectoryNotEmpty.into());
        }
        Ok(())
    }

    // Used only for non-root entries, each of which has one directory link.
    fn charge(&self) -> u64 {
        ENTRY_CHARGE
            + DIR_LINK_CHARGE
            + self.name.len() as u64
            + match &self.contents {
                Contents::File(blocks) => blocks.len() as u64 * BLOCK_CHARGE,
                Contents::Directory(_) => 0,
            }
    }
}

impl MemFs {
    pub fn new(config: MemFsConfig) -> Result<Self> {
        if !perms_monotonic(config.root_mode) {
            return Err(ErrorKind::PermissionDenied.into());
        }
        let root = Entry::new(0, "/".into(), EntryKind::Directory, config.root_mode);
        let used = ENTRY_CHARGE + root.name.len() as u64;
        if used > config.max_size {
            return Err(ErrorKind::StorageFull.into());
        }
        Ok(Self {
            entries: BTreeMap::from([(0, root)]),
            last_id: 0,
            used,
            cap: config.max_size,
            cache: FreeBlockCache::new(config.free_cache_cap),
        })
    }

    pub fn used_bytes(&self) -> u64 {
        self.used
    }
    pub fn entry_count(&self) -> u64 {
        self.entries.len() as u64
    }
    pub fn max_size(&self) -> u64 {
        self.cap
    }
    pub fn num_blocks(&self) -> u64 {
        self.cap / async_fs::BLOCK_SIZE as u64
    }
    pub fn empty_blocks_sync(&self) -> Result<u64> {
        Ok((self.cap - self.used) / async_fs::BLOCK_SIZE as u64)
    }
    pub fn cached_free_bytes(&self) -> u64 {
        self.cache.cached_free_bytes()
    }
    pub fn free_block_cache(&self) -> FreeBlockCache {
        self.cache.clone()
    }
    pub fn release_free_blocks(&self) {
        self.cache.release_free_blocks();
    }
    pub fn flush_sync(&mut self) -> Result<()> {
        Ok(())
    }

    fn entry(&self, id: EntryId) -> Result<(u64, &Entry)> {
        let id = decode(id)?;
        self.entries
            .get(&id)
            .map(|entry| (id, entry))
            .ok_or_else(|| ErrorKind::InvalidInput.into())
    }

    fn changed_usage(&self, removed: u64, added: u64) -> Result<u64> {
        let used = (self.used - removed)
            .checked_add(added)
            .ok_or(ErrorKind::StorageFull)?;
        if used > self.cap {
            return Err(ErrorKind::StorageFull.into());
        }
        Ok(used)
    }

    fn children_mut(&mut self, parent: u64) -> &mut BTreeMap<Rc<str>, u64> {
        let entry = self.entries.get_mut(&parent).unwrap();
        match &mut entry.contents {
            Contents::Directory(children) => children,
            Contents::File(_) => unreachable!("validated parent"),
        }
    }

    fn changed_directory(&mut self, parent: u64) {
        let entry = self.entries.get_mut(&parent).unwrap();
        entry.metadata.size = entry.children().unwrap().len() as u64;
        entry.metadata.modified = Timestamp::now();
    }

    pub fn stat_sync(
        &self,
        role: Role,
        parent: EntryId,
        name: &str,
    ) -> Result<Option<(EntryId, EntryKind)>> {
        validate_filename(name)?;
        let (_, entry) = self.entry(parent)?;
        let children = entry.children()?;
        check_access(&entry.metadata, role, Need::Execute)?;
        Ok(children
            .get(name)
            .map(|id| (encode(*id), self.entries[id].metadata.kind())))
    }

    /// `stat_sync` without the traverse check. A replacing move needs only `w`
    /// on the directory, so sys-io protects mount points and running
    /// executables from replacement with this lookup; never answer a client
    /// with it.
    pub fn lookup_unchecked(
        &self,
        parent: EntryId,
        name: &str,
    ) -> Result<Option<(EntryId, EntryKind)>> {
        validate_filename(name)?;
        let (_, entry) = self.entry(parent)?;
        Ok(entry
            .children()?
            .get(name)
            .map(|id| (encode(*id), self.entries[id].metadata.kind())))
    }

    pub fn create_entry_sync(
        &mut self,
        role: Role,
        parent: EntryId,
        kind: EntryKind,
        name: &str,
        mode: RolePermissions,
    ) -> Result<EntryId> {
        validate_filename(name)?;
        if !perms_monotonic(mode)
            || ROLES.iter().any(|&target| {
                (target as u8) > role as u8 && mode.get(target) != AccessPermissions::Rwx
            })
        {
            return Err(ErrorKind::PermissionDenied.into());
        }
        let (parent, parent_entry) = self.entry(parent)?;
        check_access(&parent_entry.metadata, role, Need::Write)?;
        if parent_entry.children()?.contains_key(name) {
            return Err(ErrorKind::AlreadyExists.into());
        }
        let id = self.last_id.checked_add(1).ok_or(ErrorKind::StorageFull)?;
        let used = self.changed_usage(0, ENTRY_CHARGE + DIR_LINK_CHARGE + name.len() as u64)?;
        let name: Rc<str> = name.into();
        let entry = Entry::new(parent, Rc::clone(&name), kind, mode);
        self.entries.insert(id, entry);
        self.children_mut(parent).insert(name, id);
        self.changed_directory(parent);
        self.last_id = id;
        self.used = used;
        Ok(encode(id))
    }

    pub fn get_first_entry_sync(&self, role: Role, parent: EntryId) -> Result<Option<EntryId>> {
        let (_, entry) = self.entry(parent)?;
        let children = entry.children()?;
        check_access(&entry.metadata, role, Need::Execute)?;
        Ok(children.first_key_value().map(|(_, id)| encode(*id)))
    }

    pub fn get_next_entry_sync(&self, role: Role, id: EntryId) -> Result<Option<EntryId>> {
        let (id, entry) = self.entry(id)?;
        if id == 0 {
            return Ok(None);
        }
        let parent = &self.entries[&entry.parent];
        check_access(&parent.metadata, role, Need::Execute)?;
        Ok(parent
            .children()?
            .range::<str, _>((Excluded(entry.name.as_ref()), Unbounded))
            .next()
            .map(|(_, id)| encode(*id)))
    }

    pub fn get_parent_sync(&self, _role: Role, id: EntryId) -> Result<Option<EntryId>> {
        let (id, entry) = self.entry(id)?;
        Ok((id != 0).then(|| encode(entry.parent)))
    }
    pub fn name_sync(&self, _role: Role, id: EntryId) -> Result<String> {
        Ok(self.entry(id)?.1.name.to_string())
    }
    pub fn metadata_sync(&self, _role: Role, id: EntryId) -> Result<Metadata> {
        Ok(self.entry(id)?.1.metadata)
    }

    fn chmod_entry(&self, caller: Role, id: EntryId) -> Result<u64> {
        // Permission changes depend on parent write access, even for a no-op.
        let (id, entry) = self.entry(id)?;
        if id == 0 {
            if caller != Role::System {
                return Err(ErrorKind::PermissionDenied.into());
            }
        } else {
            check_access(&self.entries[&entry.parent].metadata, caller, Need::Write)?;
        }
        Ok(id)
    }

    pub fn set_permissions_sync(
        &mut self,
        caller: Role,
        id: EntryId,
        target: Role,
        access: AccessPermissions,
    ) -> Result<()> {
        let id = self.chmod_entry(caller, id)?;
        let mut metadata = self.entries[&id].metadata;
        if !may_set(caller, target, metadata.access(target)?, access) {
            return Err(ErrorKind::PermissionDenied.into());
        }
        if let Some(&ceiling) = ROLES.get(target as usize + 1)
            && !metadata.access(ceiling)?.can_narrow_to(access)
        {
            return Err(ErrorKind::PermissionDenied.into());
        }
        metadata.set_access(target, access);
        for &lower in &ROLES[..target as usize] {
            metadata.set_access(lower, metadata.access(lower)?.meet(access));
        }
        metadata.modified = Timestamp::now();
        self.entries.get_mut(&id).unwrap().metadata = metadata;
        Ok(())
    }

    pub fn set_all_permissions_sync(
        &mut self,
        caller: Role,
        id: EntryId,
        mode: RolePermissions,
    ) -> Result<()> {
        let id = self.chmod_entry(caller, id)?;
        let mut metadata = self.entries[&id].metadata;
        for role in ROLES {
            let old = metadata.access(role)?;
            if old != mode.get(role) && !may_set(caller, role, old, mode.get(role)) {
                return Err(ErrorKind::PermissionDenied.into());
            }
        }
        if !perms_monotonic(mode) {
            return Err(ErrorKind::PermissionDenied.into());
        }
        metadata.set_permissions(mode);
        metadata.modified = Timestamp::now();
        self.entries.get_mut(&id).unwrap().metadata = metadata;
        Ok(())
    }

    // All validation precedes removal. Iterating the owned map allocates nothing.
    fn remove(&mut self, id: u64) {
        let entry = self.entries.remove(&id).unwrap();
        self.used -= entry.charge();
        self.children_mut(entry.parent).remove(&entry.name);
        self.changed_directory(entry.parent);
        if let Contents::File(blocks) = entry.contents {
            for (_, block) in blocks {
                self.cache.put(block);
            }
        }
    }

    pub fn delete_entry_sync(&mut self, role: Role, id: EntryId) -> Result<()> {
        let (id, entry) = self.entry(id)?;
        if id == 0 {
            return Err(ErrorKind::InvalidInput.into());
        }
        check_access(&self.entries[&entry.parent].metadata, role, Need::Write)?;
        entry.removable()?;
        self.remove(id);
        Ok(())
    }

    pub fn move_entry_sync(
        &mut self,
        role: Role,
        id: EntryId,
        parent: EntryId,
        name: &str,
    ) -> Result<()> {
        self.move_inner(role, id, parent, name, true)
    }
    pub fn move_noreplace_sync(
        &mut self,
        role: Role,
        id: EntryId,
        parent: EntryId,
        name: &str,
    ) -> Result<()> {
        self.move_inner(role, id, parent, name, false)
    }

    fn move_inner(
        &mut self,
        role: Role,
        id: EntryId,
        parent: EntryId,
        name: &str,
        replace: bool,
    ) -> Result<()> {
        let (id, entry) = self.entry(id)?;
        let (parent, parent_entry) = self.entry(parent)?;
        if id == 0 || id == parent {
            return Err(ErrorKind::InvalidInput.into());
        }
        validate_filename(name)?;
        let old_parent = entry.parent;
        let mut ancestor = parent;
        while ancestor != 0 {
            if ancestor == id {
                return Err(ErrorKind::InvalidInput.into());
            }
            ancestor = self.entries[&ancestor].parent;
        }
        check_access(&self.entries[&old_parent].metadata, role, Need::Write)?;
        check_access(&parent_entry.metadata, role, Need::Write)?;
        let target = parent_entry.children()?.get(name).copied();
        let mut removed = entry.name.len() as u64;
        if let Some(target) = target {
            if !replace {
                return Err(ErrorKind::AlreadyExists.into());
            }
            if target == id {
                return Err(ErrorKind::InvalidInput.into());
            }
            self.entries[&target].removable()?;
            removed += self.entries[&target].charge();
        }
        let used = self.changed_usage(removed, name.len() as u64)?;
        let name: Rc<str> = name.into();
        // Commit: no returned errors beyond this point, including replacement.
        if let Some(target) = target {
            self.remove(target);
        }
        let entry = self.entries.get_mut(&id).unwrap();
        let old_name = std::mem::replace(&mut entry.name, Rc::clone(&name));
        entry.parent = parent;
        entry.metadata.modified = Timestamp::now();
        self.children_mut(old_parent).remove(&old_name);
        self.children_mut(parent).insert(name, id);
        self.changed_directory(old_parent);
        self.changed_directory(parent);
        self.used = used;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
