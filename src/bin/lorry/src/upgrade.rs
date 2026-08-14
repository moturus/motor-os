use semver::Version;

use crate::diagnostic::{Error, Result};
use crate::manifest::{DependencySource, Manifest};

#[derive(Debug)]
pub struct Selection {
    name: String,
    old: Version,
    requested: Version,
}

impl Selection {
    pub fn as_resolver_input(&self) -> (&str, Option<&Version>, &Version) {
        (&self.name, Some(&self.old), &self.requested)
    }
}

pub fn transitive_selection(
    manifest: &Manifest,
    selector: &str,
    version: &str,
) -> Result<Selection> {
    let requested = Version::parse(version).map_err(|error| {
        Error::usage(
            format!("upgrade version `{version}` is not a complete semantic version: {error}"),
            "use `--to MAJOR.MINOR.PATCH` with optional semantic prerelease/build components",
        )
    })?;
    let (name, old_version) = parse_selector(selector)?;
    reject_direct(manifest, name)?;
    let lock = manifest.lock.as_ref().ok_or_else(|| {
        Error::failure(format!(
            "transitive upgrade package `{name}` requires Cargo.lock"
        ))
    })?;
    let mut versions = lock
        .packages
        .iter()
        .filter(|package| {
            package.name == name
                && package.source.as_deref()
                    == Some("registry+https://github.com/rust-lang/crates.io-index")
        })
        .map(|package| package.version.original.clone())
        .collect::<Vec<_>>();
    versions.sort_unstable();
    versions.dedup();
    if versions.is_empty() {
        return Err(Error::failure(format!(
            "upgrade package `{name}` is not a locked transitive crates.io package"
        )));
    }
    let old = if let Some(old) = old_version {
        if !versions.iter().any(|version| version == old) {
            return Err(Error::failure(format!(
                "Cargo.lock does not contain `{name} {old}`"
            )));
        }
        old
    } else if versions.len() != 1 {
        return Err(Error::usage(
            format!(
                "locked package `{name}` is ambiguous because Cargo.lock contains versions {}",
                versions.join(", ")
            ),
            format!("select one with `{name}@OLD_VERSION`"),
        ));
    } else {
        &versions[0]
    };
    let old = Version::parse(old).map_err(|error| {
        Error::failure(format!("locked package `{name} {old}` is invalid: {error}"))
    })?;
    Ok(Selection {
        name: name.to_owned(),
        old,
        requested,
    })
}

fn parse_selector(selector: &str) -> Result<(&str, Option<&str>)> {
    let Some((name, old)) = selector.rsplit_once('@') else {
        return Ok((selector, None));
    };
    if name.is_empty() || Version::parse(old).is_err() {
        return Err(Error::usage(
            format!("invalid upgrade package selector `{selector}`"),
            "use PACKAGE or PACKAGE@OLD_VERSION",
        ));
    }
    Ok((name, Some(old)))
}

fn reject_direct(manifest: &Manifest, selector: &str) -> Result<()> {
    let by_alias = manifest
        .dependencies
        .iter()
        .filter(|dependency| dependency.alias == selector)
        .collect::<Vec<_>>();
    let matches = if by_alias.is_empty() {
        manifest
            .dependencies
            .iter()
            .filter(|dependency| dependency.package == selector)
            .collect::<Vec<_>>()
    } else {
        by_alias
    };
    if matches
        .iter()
        .any(|dependency| dependency.source != DependencySource::CratesIo)
    {
        return Err(Error::failure(format!(
            "direct dependency `{selector}` is not a crates.io dependency"
        ))
        .with_help("only direct crates.io version declarations can be upgraded"));
    }
    let matches = matches
        .into_iter()
        .filter(|dependency| dependency.source == DependencySource::CratesIo)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(()),
        [_] => Err(Error::usage(
            format!("`{selector}` is a direct dependency"),
            "edit its version requirement in Cargo.toml, then run `lorry vendor`",
        )),
        _ => Err(Error::usage(
            format!("direct dependency selector `{selector}` is ambiguous"),
            "use a unique dependency alias; target-conditioned declarations may need distinct aliases",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(manifest: &str) -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "lorry-upgrade-manifest-{}-{id}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("src")).unwrap();
            fs::write(root.join("src/lib.rs"), "pub fn root() {}\n").unwrap();
            fs::write(root.join("Cargo.toml"), manifest).unwrap();
            Self(root)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn directs_manifest_dependencies_to_ordinary_vendoring() {
        let fixture = Fixture::new(
            "[package]\nname='root'\nversion='0.1.0'\n[dependencies]\na={package='libc',version='0.2'}\nb={package='libc',version='0.2'}\n",
        );
        let manifest = Manifest::load_for_vendor(&fixture.0).unwrap();
        assert!(
            transitive_selection(&manifest, "libc", "0.2.2")
                .unwrap_err()
                .render()
                .contains("ambiguous")
        );
        let error = transitive_selection(&manifest, "a", "0.2.2").unwrap_err();
        assert!(error.render().contains("edit its version requirement"));
    }

    #[test]
    fn selects_one_locked_transitive_identity() {
        let fixture = Fixture::new("[package]\nname='root'\nversion='0.1.0'\n");
        fs::write(
            fixture.0.join("Cargo.lock"),
            format!(
                "version = 4\n\n\
                 [[package]]\nname = \"root\"\nversion = \"0.1.0\"\n\n\
                 [[package]]\nname = \"demo\"\nversion = \"1.2.3\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{}\"\n\n\
                 [[package]]\nname = \"demo\"\nversion = \"2.0.0\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{}\"\n",
                "1".repeat(64),
                "2".repeat(64),
            ),
        )
        .unwrap();
        let manifest = Manifest::load_for_vendor(&fixture.0).unwrap();
        assert!(
            transitive_selection(&manifest, "demo", "1.2.4")
                .unwrap_err()
                .render()
                .contains("ambiguous")
        );
        let selection = transitive_selection(&manifest, "demo@1.2.3", "1.2.4").unwrap();
        let (name, old, requested) = selection.as_resolver_input();
        assert_eq!(name, "demo");
        assert_eq!(old.unwrap(), &Version::parse("1.2.3").unwrap());
        assert_eq!(requested, &Version::parse("1.2.4").unwrap());
    }
}
