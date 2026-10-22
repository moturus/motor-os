use super::*;
use moto_sdk::async_fs::BLOCK_SIZE;
const BLOCK_BYTES: u64 = BLOCK_SIZE as u64;

fn end_offset(offset: u64, len: u64) -> Result<u64> {
    offset
        .checked_add(len)
        .ok_or_else(|| ErrorKind::InvalidInput.into())
}

fn block_end(offset: u64, len: usize) -> Result<u64> {
    let end = end_offset(offset, len as u64)?;
    if len as u64 > BLOCK_BYTES - offset % BLOCK_BYTES {
        return Err(ErrorKind::InvalidInput.into());
    }
    Ok(end)
}

impl MemFs {
    fn file(&self, role: Role, id: EntryId, need: Need) -> Result<(u64, &Entry)> {
        let (id, entry) = self.entry(id)?;
        check_access(&entry.metadata, role, need)?;
        entry.blocks()?;
        Ok((id, entry))
    }

    pub fn read_sync(&self, role: Role, id: EntryId, offset: u64, buf: &mut [u8]) -> Result<usize> {
        block_end(offset, buf.len())?;
        let (_, entry) = self.file(role, id, Need::Read)?;
        let len = (entry.metadata.size.saturating_sub(offset)).min(buf.len() as u64) as usize;
        let start = (offset % BLOCK_BYTES) as usize;
        match entry.blocks()?.get(&(offset / BLOCK_BYTES)) {
            Some(block) => buf[..len].copy_from_slice(&block.bytes()[start..start + len]),
            None => buf[..len].fill(0),
        }
        Ok(len)
    }

    pub fn write_sync(
        &mut self,
        role: Role,
        id: EntryId,
        offset: u64,
        buf: &[u8],
    ) -> Result<usize> {
        let end = block_end(offset, buf.len())?;
        let (id, entry) = self.file(role, id, Need::Write)?;
        if buf.is_empty() {
            return Ok(0);
        }
        let key = offset / BLOCK_BYTES;
        // Obtain quota and a page before modifying bytes, size or accounting.
        let new_block = if !entry.blocks()?.contains_key(&key) {
            self.changed_usage(0, BLOCK_CHARGE)?;
            Some(self.cache.take()?)
        } else {
            None
        };
        let entry = self.entries.get_mut(&id).unwrap();
        let Contents::File(blocks) = &mut entry.contents else {
            unreachable!()
        };
        if let Some(block) = new_block {
            blocks.insert(key, block);
            self.used += BLOCK_CHARGE;
        }
        let start = (offset % BLOCK_BYTES) as usize;
        blocks.get_mut(&key).unwrap().bytes_mut()[start..start + buf.len()].copy_from_slice(buf);
        entry.metadata.size = entry.metadata.size.max(end);
        entry.metadata.modified = Timestamp::now();
        Ok(buf.len())
    }

    pub fn resize_sync(&mut self, role: Role, id: EntryId, size: u64) -> Result<()> {
        let (id, _) = self.file(role, id, Need::Write)?;
        let entry = self.entries.get_mut(&id).unwrap();
        let Contents::File(blocks) = &mut entry.contents else {
            unreachable!()
        };
        if size < entry.metadata.size {
            let first_removed = size.div_ceil(BLOCK_BYTES);
            while blocks
                .last_key_value()
                .is_some_and(|(&key, _)| key >= first_removed)
            {
                let (_, block) = blocks.pop_last().unwrap();
                self.used -= BLOCK_CHARGE;
                self.cache.put(block);
            }
            if !size.is_multiple_of(BLOCK_BYTES)
                && let Some(block) = blocks.get_mut(&(size / BLOCK_BYTES))
            {
                block.bytes_mut()[(size % BLOCK_BYTES) as usize..].fill(0);
            }
        }
        entry.metadata.size = size;
        entry.metadata.modified = Timestamp::now();
        Ok(())
    }

    pub fn copy_file_range_sync(
        &mut self,
        role: Role,
        from: EntryId,
        from_offset: u64,
        to: EntryId,
        to_offset: u64,
        size: u64,
    ) -> Result<u64> {
        end_offset(from_offset, size)?;
        end_offset(to_offset, size)?;
        self.file(role, from, Need::Read)?;
        self.file(role, to, Need::Write)?;
        let mut buf = [0; BLOCK_SIZE];
        let mut copied = 0;
        while copied < size {
            let src = from_offset + copied;
            let dst = to_offset + copied;
            let chunk = (size - copied)
                .min(BLOCK_BYTES - src % BLOCK_BYTES)
                .min(BLOCK_BYTES - dst % BLOCK_BYTES) as usize;
            // The buffer also supports same-file copies with motor-fs's forward
            // chunk order. A later error reports only fully committed chunks.
            let result = self
                .read_sync(role, from, src, &mut buf[..chunk])
                .and_then(|len| self.write_sync(role, to, dst, &buf[..len]));
            match result {
                Ok(0) => break,
                Ok(len) => copied += len as u64,
                Err(_) if copied != 0 => break,
                Err(err) => return Err(err),
            }
        }
        Ok(copied)
    }
}
