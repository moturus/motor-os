use super::*;
use moto_sdk::async_fs::FileSystem;

#[async_trait::async_trait(?Send)]
impl FileSystem for MemFs {
    async fn stat(
        &self,
        role: Role,
        parent: EntryId,
        name: &str,
    ) -> Result<Option<(EntryId, EntryKind)>> {
        self.stat_sync(role, parent, name)
    }

    async fn create_entry(
        &mut self,
        role: Role,
        parent: EntryId,
        kind: EntryKind,
        name: &str,
        mode: RolePermissions,
    ) -> Result<EntryId> {
        self.create_entry_sync(role, parent, kind, name, mode)
    }

    async fn set_permissions(
        &mut self,
        caller: Role,
        id: EntryId,
        target: Role,
        access: AccessPermissions,
    ) -> Result<()> {
        self.set_permissions_sync(caller, id, target, access)
    }

    async fn set_all_permissions(
        &mut self,
        caller: Role,
        id: EntryId,
        mode: RolePermissions,
    ) -> Result<()> {
        self.set_all_permissions_sync(caller, id, mode)
    }

    async fn delete_entry(&mut self, role: Role, id: EntryId) -> Result<()> {
        self.delete_entry_sync(role, id)
    }

    async fn move_entry(
        &mut self,
        role: Role,
        id: EntryId,
        parent: EntryId,
        name: &str,
    ) -> Result<()> {
        self.move_entry_sync(role, id, parent, name)
    }

    async fn move_noreplace(
        &mut self,
        role: Role,
        id: EntryId,
        parent: EntryId,
        name: &str,
    ) -> Result<()> {
        self.move_noreplace_sync(role, id, parent, name)
    }

    async fn get_first_entry(&self, role: Role, parent: EntryId) -> Result<Option<EntryId>> {
        self.get_first_entry_sync(role, parent)
    }

    async fn get_next_entry(&self, role: Role, id: EntryId) -> Result<Option<EntryId>> {
        self.get_next_entry_sync(role, id)
    }

    async fn get_parent(&self, role: Role, id: EntryId) -> Result<Option<EntryId>> {
        self.get_parent_sync(role, id)
    }

    async fn name(&self, role: Role, id: EntryId) -> Result<String> {
        self.name_sync(role, id)
    }

    async fn metadata(&self, role: Role, id: EntryId) -> Result<Metadata> {
        self.metadata_sync(role, id)
    }

    async fn read(&self, role: Role, id: EntryId, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.read_sync(role, id, offset, buf)
    }

    async fn write(&mut self, role: Role, id: EntryId, offset: u64, buf: &[u8]) -> Result<usize> {
        self.write_sync(role, id, offset, buf)
    }

    async fn resize(&mut self, role: Role, id: EntryId, size: u64) -> Result<()> {
        self.resize_sync(role, id, size)
    }

    async fn empty_blocks(&self) -> Result<u64> {
        self.empty_blocks_sync()
    }

    async fn copy_file_range(
        &mut self,
        role: Role,
        from: EntryId,
        from_offset: u64,
        to: EntryId,
        to_offset: u64,
        size: u64,
    ) -> Result<u64> {
        self.copy_file_range_sync(role, from, from_offset, to, to_offset, size)
    }

    async fn flush(&mut self) -> Result<()> {
        self.flush_sync()
    }
    fn num_blocks(&self) -> u64 {
        MemFs::num_blocks(self)
    }
}
