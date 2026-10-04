use super::*;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Identity {
    name: String,
    version: Version,
    source: Option<String>,
}

impl Identity {
    fn from_locked(package: &crate::manifest::LockedPackage) -> Result<Self> {
        Ok(Self {
            name: package.name.clone(),
            version: Version::parse(&package.version.original).map_err(|error| {
                Error::failure(format!("invalid locked package version: {error}"))
            })?,
            source: package.source.clone(),
        })
    }

    pub(super) fn from_key(key: &PackageKey) -> Self {
        Self {
            name: key.name.clone(),
            version: key.version.clone(),
            source: match &key.source {
                PackageSourceKey::CratesIo => {
                    Some("registry+https://github.com/rust-lang/crates.io-index".to_owned())
                }
                PackageSourceKey::Git(source) => Some(source.clone()),
                PackageSourceKey::Path(_) => None,
            },
        }
    }
}

pub(super) struct Edges(BTreeMap<Identity, BTreeSet<Identity>>);

impl Edges {
    pub(super) fn new(lock: &Lockfile) -> Result<Self> {
        let mut edges = BTreeMap::new();
        for package in &lock.packages {
            let dependencies = package
                .dependencies
                .iter()
                .map(|reference| {
                    let package = crate::offline::resolve_lock_reference(
                        reference,
                        &lock.packages,
                        lock.format,
                    )?;
                    Identity::from_locked(package)
                })
                .collect::<Result<BTreeSet<_>>>()?;
            edges.insert(Identity::from_locked(package)?, dependencies);
        }
        Ok(Self(edges))
    }

    pub(super) fn dependencies(
        &self,
        parent: &PackageKey,
    ) -> std::result::Result<&BTreeSet<Identity>, Failure> {
        self.0.get(&Identity::from_key(parent)).ok_or_else(|| {
            Failure::fatal(format!(
                "Cargo.lock has no dependency parent `{} {}`",
                parent.name, parent.version
            ))
        })
    }
}
