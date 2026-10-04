use super::*;

pub(super) struct Staged {
    record: SparseRecord,
    directory: AtomicDirectory,
}

impl std::fmt::Debug for Staged {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StagedIndex")
            .field("directory", &self.directory)
            .finish()
    }
}

impl RepositorySet {
    /// Index inputs retain a locked identity's resolution data, never source
    /// or execution evidence. Source readers still require verified objects.
    pub(crate) fn lookup_registry_record(&self, checksum: &str) -> Result<Option<SparseRecord>> {
        decode_hex::<32>(checksum)?;
        if let Some(object) = self.lookup_registry(checksum)? {
            return Ok(Some(object.index));
        }
        for repository in &self.layers {
            if !repository.present {
                continue;
            }
            if let Some(record) = read(&repository.root, checksum)? {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }
}

impl RepositoryTransaction {
    pub(crate) fn stage_index_record(&mut self, record: &SparseRecord) -> Result<()> {
        let checksum = hex(&record.checksum);
        if let Some(staged) = self.index_records.get(&checksum) {
            return matching(&staged.record, record);
        }
        if record.exact_bytes.len() > INDEX_RECORD_LIMIT
            || SparseRecord::parse(Path::new("/resolution/index.json"), &record.exact_bytes)?
                != *record
        {
            return Err(Error::failure("invalid sparse resolution record"));
        }
        let directory = AtomicDirectory::new(self.staging.path(), "index")?;
        write_new(
            &directory.path().join(record_filename(record)),
            &record.exact_bytes,
        )?;
        self.index_records.insert(
            checksum,
            Staged {
                record: record.clone(),
                directory,
            },
        );
        Ok(())
    }

    pub(super) fn validate_index_records(&self) -> Result<()> {
        for (checksum, staged) in &self.index_records {
            matching(
                &read_directory(staged.directory.path(), checksum)?,
                &staged.record,
            )?;
            if let Some(existing) = read(&self.writer.root, checksum)? {
                matching(&existing, &staged.record)?;
            }
            persist_object_tree(staged.directory.path(), &self.writer.sync_file)?;
        }
        Ok(())
    }

    pub(super) fn publish_index_records(self) -> Result<()> {
        for (checksum, staged) in self.index_records {
            let mut prefix = self.writer.root.clone();
            for part in ["resolution", "crates-io", "sha256", &checksum[..2]] {
                prefix.push(part);
                ensure_object_prefix(&prefix, &self.writer.sync_file)?;
            }
            let destination = prefix.join(&checksum);
            if move_no_replace(staged.directory.path(), &destination)? {
                sync_directory(&prefix, &self.writer.sync_file)?;
            }
            matching(&read_directory(&destination, &checksum)?, &staged.record)?;
        }
        Ok(())
    }
}

fn matching(left: &SparseRecord, right: &SparseRecord) -> Result<()> {
    if left == right {
        return Ok(());
    }
    Err(Error::failure(format!(
        "conflicting sparse resolution evidence for `{} {}`",
        right.name, right.version
    )))
}

fn record_filename(record: &SparseRecord) -> String {
    let mut hash = Sha256::new();
    hash.update(&record.exact_bytes);
    format!("{}.json", hex(&hash.finish()))
}

fn read(root: &Path, checksum: &str) -> Result<Option<SparseRecord>> {
    let mut path = root.to_owned();
    for part in [
        "resolution",
        "crates-io",
        "sha256",
        &checksum[..2],
        checksum,
    ] {
        path.push(part);
        if !entry_exists(&path)? {
            return Ok(None);
        }
        require_real_directory(&path, "sparse resolution directory")?;
    }
    read_directory(&path, checksum).map(Some)
}

fn read_directory(path: &Path, checksum: &str) -> Result<SparseRecord> {
    require_real_directory(path, "sparse resolution directory")?;
    let mut entries = fs::read_dir(path).map_err(|error| {
        Error::failure(format!(
            "failed to read sparse resolution directory `{}`: {error}",
            path.display(),
        ))
    })?;
    let entry = entries
        .next()
        .transpose()?
        .ok_or_else(|| Error::failure("empty sparse resolution object"))?;
    if entries.next().is_some() {
        return Err(Error::failure("extra files in sparse resolution object"));
    }
    let record = SparseRecord::parse(
        &entry.path(),
        &read_bounded_file(&entry.path(), INDEX_RECORD_LIMIT as u64)?,
    )?;
    if entry.file_name() != record_filename(&record).as_str() || hex(&record.checksum) != checksum {
        return Err(Error::failure(format!(
            "sparse resolution identity or digest mismatch in `{}`",
            path.display()
        )));
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishes_only_resolution_data_and_rejects_changed_or_linked_records() {
        let fixture = AtomicDirectory::new(&std::env::temp_dir(), "lorry-index-record").unwrap();
        let root = fixture.path().join("repository");
        let repositories = Repositories {
            user: Some(root.clone()),
            ..Repositories::default()
        };
        let record = SparseRecord::parse(Path::new("/index.json"), format!(
            "{{\"name\":\"demo\",\"vers\":\"1.2.3\",\"cksum\":\"{}\",\"deps\":[],\"features\":{{}},\"yanked\":false}}\n",
            "1".repeat(64),
        ).as_bytes()).unwrap();
        let writer = RepositoryWriter::open(
            &repositories,
            crate::source_tree::DEFAULT_LIMITS,
            ArchiveLimits::from_policy(&crate::config::PolicyLimits::default()),
        )
        .unwrap();
        let mut transaction = writer.begin().unwrap();
        transaction.stage_index_record(&record).unwrap();
        let set = RepositorySet::open(
            &repositories,
            crate::source_tree::DEFAULT_LIMITS,
            16 * 1024 * 1024,
        )
        .unwrap();
        assert!(
            set.lookup_registry_record(&hex(&record.checksum))
                .unwrap()
                .is_none()
        );
        assert!(transaction.publish().unwrap().is_empty());
        assert_eq!(
            set.lookup_registry_record(&hex(&record.checksum)).unwrap(),
            Some(record.clone())
        );
        assert!(
            set.lookup_registry(&hex(&record.checksum))
                .unwrap()
                .is_none()
        );
        let path = root
            .join("resolution/crates-io/sha256/11")
            .join(hex(&record.checksum))
            .join(record_filename(&record));
        fs::write(
            &path,
            String::from_utf8(record.exact_bytes.clone())
                .unwrap()
                .replace("false", "true"),
        )
        .unwrap();
        assert!(
            set.lookup_registry_record(&hex(&record.checksum))
                .unwrap_err()
                .render()
                .contains("digest mismatch")
        );
        #[cfg(unix)]
        {
            fs::remove_file(&path).unwrap();
            fs::write(root.join("outside.json"), &record.exact_bytes).unwrap();
            std::os::unix::fs::symlink(root.join("outside.json"), &path).unwrap();
            assert!(
                set.lookup_registry_record(&hex(&record.checksum))
                    .unwrap_err()
                    .render()
                    .contains("real regular file")
            );
        }
    }
}
