use std::{ffi::OsStr, fs, io, path::Path};

/// Require the complete SHA-1 object database used by bounded object operations.
pub fn validate_full(repo: &gix::Repository, operation: &str) -> crate::Result {
    if repo.object_hash() != gix::hash::Kind::Sha1 {
        return unsupported(format!("only SHA-1 repositories support {operation}"));
    }
    if repo.namespace().is_some() {
        return unsupported(format!(
            "reference namespaces are unsupported for {operation}"
        ));
    }
    let shallow = repo.git_dir().join("shallow");
    if repo.shallow_file() != shallow {
        return unsupported("repository configuration selected a different shallow file");
    }
    match fs::metadata(&shallow) {
        Ok(metadata) if !metadata.is_file() || metadata.len() != 0 => {
            return unsupported(format!(
                "shallow repositories are unsupported for {operation}"
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let store = repo.objects.store_ref();
    reject_promisor_packs(store.path(), operation)?;
    for object_dir in store.alternate_db_paths()? {
        reject_promisor_packs(&object_dir, operation)?;
    }

    let snapshot = repo.config_snapshot();
    let config = snapshot.plumbing();
    if config
        .sections_by_name("extensions")
        .into_iter()
        .flatten()
        .any(|section| section.contains_value_name("partialClone"))
    {
        return unsupported(format!(
            "partial-clone repositories are unsupported for {operation}"
        ));
    }
    for section in config.sections_by_name("remote").into_iter().flatten() {
        if section.contains_value_name("partialCloneFilter") {
            return unsupported(format!(
                "partial-clone filters are unsupported for {operation}"
            ));
        }
        if section.contains_value_name("promisor")
            && config
                .boolean_by("remote", section.header().subsection_name(), "promisor")?
                .unwrap_or(false)
        {
            return unsupported(format!("promisor remotes are unsupported for {operation}"));
        }
    }
    Ok(())
}

fn reject_promisor_packs(object_dir: &Path, operation: &str) -> crate::Result {
    match fs::read_dir(object_dir.join("pack")) {
        Ok(entries) => {
            for entry in entries {
                if entry?.path().extension() == Some(OsStr::new("promisor")) {
                    return unsupported(format!("promisor packs are unsupported for {operation}"));
                }
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// A checksummed object reader for selection and pack encoding.
pub struct Reader<'repo> {
    repo: &'repo gix::Repository,
    cancellation: &'repo crate::cancellation::Cancellation,
}

impl<'repo> Reader<'repo> {
    /// Create a reader for one cancellable operation.
    pub fn new(
        repo: &'repo gix::Repository,
        cancellation: &'repo crate::cancellation::Cancellation,
    ) -> Self {
        Self { repo, cancellation }
    }

    /// Return the repository supplying objects.
    pub fn repository(&self) -> &'repo gix::Repository {
        self.repo
    }

    /// Return the operation cancellation state.
    pub fn cancellation(&self) -> &crate::cancellation::Cancellation {
        self.cancellation
    }

    /// Load and verify one required object.
    pub fn load(&self, id: gix::ObjectId) -> crate::Result<gix::Object<'repo>> {
        self.cancellation.check()?;
        let header = self.repo.find_header(id)?;
        self.load_after_header(id, header)
    }

    /// Load and verify an object if it exists locally.
    pub fn try_load(&self, id: gix::ObjectId) -> crate::Result<Option<gix::Object<'repo>>> {
        self.cancellation.check()?;
        let Some(header) = self.repo.try_find_header(id)? else {
            return Ok(None);
        };
        self.load_after_header(id, header).map(Some)
    }

    /// Load and verify a required object of the expected kind.
    pub fn load_kind(
        &self,
        id: gix::ObjectId,
        expected: gix::objs::Kind,
    ) -> crate::Result<gix::Object<'repo>> {
        let object = self.load(id)?;
        if object.kind != expected {
            return Err(invalid(format!(
                "object {id} is {:?}, expected {expected:?}",
                object.kind
            ))
            .into());
        }
        Ok(object)
    }

    fn load_after_header(
        &self,
        id: gix::ObjectId,
        header: gix::odb::find::Header,
    ) -> crate::Result<gix::Object<'repo>> {
        self.cancellation.check()?;
        let object = self.repo.find_object(id)?;
        let size = u64::try_from(object.data.len())?;
        if header.kind() != object.kind || header.size() != size {
            return Err(invalid(format!("object {id} changed while it was read")).into());
        }
        gix::objs::Data {
            kind: object.kind,
            object_hash: id.kind(),
            data: &object.data,
        }
        .verify_checksum(&id)?;
        self.cancellation.check()?;
        Ok(object)
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn unsupported(message: impl Into<String>) -> crate::Result {
    Err(io::Error::new(io::ErrorKind::Unsupported, message.into()).into())
}
