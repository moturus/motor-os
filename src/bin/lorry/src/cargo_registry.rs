#![allow(dead_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use semver::Version;

use crate::archive::{ExtractedArchive, Limits as ArchiveLimits, extract_crate};
use crate::config::PolicyLimits;
use crate::diagnostic::{Error, Result};
use crate::hash::decode_hex;
use crate::manifest::{DependencySource, Manifest};
use crate::policy::PackageEvidence;
use crate::source_tree::{Exclusions, Limits as TreeLimits, Tree};
use crate::sparse::{Dependency, Record, RustVersion};

const CARGO_MARKER: &[u8] = b"{\"v\":1}";

#[derive(Clone, Debug)]
pub struct CargoRegistry {
    home: PathBuf,
    registries: Vec<String>,
    staging_parent: PathBuf,
    archive_limits: ArchiveLimits,
    tree_limits: TreeLimits,
}

#[derive(Debug)]
pub struct Package {
    pub manifest: Manifest,
    pub evidence: PackageEvidence,
    pub checksum: [u8; 32],
    _extracted: ExtractedArchive,
}

impl CargoRegistry {
    pub fn discover(staging_parent: &Path, limits: &PolicyLimits) -> Result<Self> {
        let home = match env::var_os("CARGO_HOME") {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            _ => env::var_os("HOME")
                .filter(|path| !path.is_empty())
                .map(PathBuf::from)
                .map(|home| home.join(".cargo"))
                .ok_or_else(|| {
                    Error::failure(
                        "--use-cargo-registry needs CARGO_HOME or HOME to locate Cargo's cache",
                    )
                })?,
        };
        let home = if home.is_absolute() {
            home
        } else {
            env::current_dir()
                .map_err(|error| {
                    Error::failure(format!("failed to resolve relative CARGO_HOME: {error}"))
                })?
                .join(home)
        };
        Self::open(&home, staging_parent, limits)
    }

    pub fn open(home: &Path, staging_parent: &Path, limits: &PolicyLimits) -> Result<Self> {
        let source_root = home.join("registry/src");
        let cache_root = home.join("registry/cache");
        let mut registries = real_directory_names(&source_root, "Cargo registry source root")?;
        let cached = real_directory_names(&cache_root, "Cargo registry archive root")?;
        registries.retain(|registry| cached.binary_search(registry).is_ok());
        Ok(Self {
            home: home.to_owned(),
            registries,
            staging_parent: staging_parent.to_owned(),
            archive_limits: ArchiveLimits::from_policy(limits),
            tree_limits: TreeLimits {
                max_entries: usize::try_from(limits.max_package_files.saturating_mul(2))
                    .unwrap_or(usize::MAX),
                max_path_bytes: crate::source_tree::DEFAULT_LIMITS.max_path_bytes,
                max_file_bytes: limits.max_extracted_package_bytes,
                max_tree_bytes: limits.max_extracted_package_bytes,
            },
        })
    }

    pub fn load(&self, name: &str, version: &Version, checksum: &str) -> Result<Package> {
        let checksum = decode_hex::<32>(checksum).map_err(|error| {
            Error::failure(format!(
                "Cargo.lock checksum for `{name} {version}` is invalid: {error}"
            ))
        })?;
        let leaf = format!("{name}-{version}");
        let mut candidates = Vec::new();
        let mut partial = Vec::new();
        for registry in &self.registries {
            let source = self.home.join("registry/src").join(registry).join(&leaf);
            let archive = self
                .home
                .join("registry/cache")
                .join(registry)
                .join(format!("{leaf}.crate"));
            let source_present = entry_exists(&source)?;
            let archive_present = entry_exists(&archive)?;
            if source_present && archive_present {
                require_real_directory(&source, "Cargo registry package source")?;
                require_real_file(&archive, "Cargo registry package archive")?;
                candidates.push((registry, source, archive));
            } else if source_present || archive_present {
                partial.push((registry, source_present, archive_present));
            }
        }
        if candidates.len() > 1 {
            let paths = candidates
                .iter()
                .map(|(_, source, _)| source.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::failure(format!(
                "Cargo registry package `{name} {version}` is ambiguous across: {paths}"
            )));
        }
        let Some((registry, source, archive)) = candidates.pop() else {
            let detail = partial
                .iter()
                .map(|(registry, source, archive)| {
                    format!(
                        "{registry} (source {}, archive {})",
                        present(*source),
                        present(*archive)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let detail = if detail.is_empty() {
                String::new()
            } else {
                format!("; incomplete entries: {detail}")
            };
            return Err(Error::failure(format!(
                "Cargo registry cache does not contain both the archive and extracted source for `{name} {version}`{detail}"
            ))
            .with_help("run Cargo for this locked package first; Lorry does not fetch or repair Cargo's cache"));
        };

        verify_marker(&source.join(".cargo-ok"))?;
        let extracted = extract_crate(
            &archive,
            checksum,
            &self.staging_parent,
            name,
            version,
            self.archive_limits,
        )?;
        let cargo_tree = Tree::scan(&source, self.tree_limits, Exclusions::CargoRegistryMarker)?;
        if cargo_tree != *extracted.tree() {
            return Err(Error::failure(format!(
                "Cargo registry source `{}` does not match its checksum-verified archive `{}`",
                source.display(),
                archive.display()
            )));
        }
        let manifest = Manifest::load_path_dependency(&source)?;
        let manifest_version = Version::parse(&manifest.version.original).map_err(|error| {
            Error::failure(format!(
                "Cargo registry manifest has invalid version `{} {}`: {error}",
                manifest.name, manifest.version.original
            ))
        })?;
        if manifest.name != name || manifest_version != *version {
            return Err(Error::failure(format!(
                "Cargo registry source in `{registry}` identifies `{} {manifest_version}`, expected `{name} {version}`",
                manifest.name
            )));
        }
        let archive_bytes = fs::metadata(&archive)
            .map_err(|error| {
                Error::failure(format!(
                    "failed to inspect Cargo registry archive `{}`: {error}",
                    archive.display()
                ))
            })?
            .len();
        let evidence = PackageEvidence {
            license: manifest.metadata.license.clone(),
            build_script: manifest.build_script.is_some(),
            newly_acquired: false,
            archive_bytes: Some(archive_bytes),
            extracted_bytes: cargo_tree.total_bytes,
            file_count: cargo_tree.file_count as u64,
            source_tree_sha256: cargo_tree.sha256,
        };
        Ok(Package {
            manifest,
            evidence,
            checksum,
            _extracted: extracted,
        })
    }
}

impl Package {
    pub fn into_parts(self) -> (Manifest, PackageEvidence) {
        (self.manifest, self.evidence)
    }

    pub fn record(&self) -> Result<Record> {
        let version = Version::parse(&self.manifest.version.original).map_err(|error| {
            Error::failure(format!(
                "Cargo registry manifest has invalid version `{} {}`: {error}",
                self.manifest.name, self.manifest.version.original
            ))
        })?;
        let dependencies = self
            .manifest
            .dependencies
            .iter()
            .map(|dependency| {
                if dependency.source != DependencySource::CratesIo {
                    return Err(Error::failure(format!(
                        "Cargo registry package `{} {version}` contains path dependency `{}`",
                        self.manifest.name, dependency.alias
                    )));
                }
                Ok(Dependency {
                    alias: dependency.alias.clone(),
                    package: dependency.package.clone(),
                    requirement: dependency.requirement.clone(),
                    features: dependency.features.clone(),
                    optional: dependency.optional,
                    default_features: dependency.default_features,
                    target: dependency.target.clone(),
                    kind: dependency.kind,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let rust_version = if self.manifest.metadata.rust_version.is_empty() {
            None
        } else {
            let original = self.manifest.metadata.rust_version.clone();
            let normalized = match original.split('.').count() {
                1 => format!("{original}.0.0"),
                2 => format!("{original}.0"),
                _ => original.clone(),
            };
            Some(RustVersion {
                original,
                version: Version::parse(&normalized).map_err(|error| {
                    Error::failure(format!(
                        "Cargo registry package `{} {version}` has invalid rust-version: {error}",
                        self.manifest.name
                    ))
                })?,
            })
        };
        Ok(Record {
            name: self.manifest.name.clone(),
            version,
            dependencies,
            checksum: self.checksum,
            features: self.manifest.features.clone(),
            features2: BTreeMap::new(),
            yanked: false,
            links: self.manifest.links.clone(),
            schema: 2,
            rust_version,
            published: None,
            exact_bytes: Vec::new(),
        })
    }
}

fn real_directory_names(root: &Path, description: &str) -> Result<Vec<String>> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(Error::failure(format!(
                "failed to inspect {description} `{}`: {error}",
                root.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::failure(format!(
            "{description} `{}` is not a real directory",
            root.display()
        )));
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(root).map_err(|error| {
        Error::failure(format!(
            "failed to read {description} `{}`: {error}",
            root.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            Error::failure(format!(
                "failed to read an entry in {description} `{}`: {error}",
                root.display()
            ))
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            Error::failure(format!(
                "failed to inspect Cargo registry directory `{}`: {error}",
                entry.path().display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::failure(format!(
                "Cargo registry entry `{}` is not a real directory",
                entry.path().display()
            )));
        }
        let name = entry.file_name().into_string().map_err(|_| {
            Error::failure(format!(
                "Cargo registry directory name is not valid UTF-8 under `{}`",
                root.display()
            ))
        })?;
        names.push(name);
    }
    names.sort();
    Ok(names)
}

fn entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::failure(format!(
            "failed to inspect Cargo registry entry `{}`: {error}",
            path.display()
        ))),
    }
}

fn require_real_directory(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::failure(format!(
            "failed to inspect {description} `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::failure(format!(
            "{description} `{}` is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

fn require_real_file(path: &Path, description: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::failure(format!(
            "failed to inspect {description} `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::failure(format!(
            "{description} `{}` is not a real regular file",
            path.display()
        )));
    }
    Ok(())
}

fn verify_marker(path: &Path) -> Result<()> {
    require_real_file(path, "Cargo registry extraction marker")?;
    let bytes = fs::read(path).map_err(|error| {
        Error::failure(format!(
            "failed to read Cargo registry extraction marker `{}`: {error}",
            path.display()
        ))
    })?;
    if bytes != CARGO_MARKER {
        return Err(Error::failure(format!(
            "Cargo registry extraction marker `{}` is invalid",
            path.display()
        )));
    }
    Ok(())
}

fn present(value: bool) -> &'static str {
    if value { "present" } else { "missing" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, IncompatibleRustVersions, PolicyDefault};
    use crate::dependency;
    use crate::resolver::{Options, TargetSelection};
    use crate::toolchain::CfgSet;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let root =
                env::temp_dir().join(format!("lorry-cargo-registry-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }

        fn package(&self, registry: &str) -> (PathBuf, PathBuf, String) {
            let source = self
                .0
                .join("cargo/registry/src")
                .join(registry)
                .join("demo-1.2.3");
            let cache = self.0.join("cargo/registry/cache").join(registry);
            fs::create_dir_all(source.join("src")).unwrap();
            fs::create_dir_all(&cache).unwrap();
            fs::write(source.join(".cargo-ok"), CARGO_MARKER).unwrap();
            fs::write(
                source.join("Cargo.toml"),
                "[package]\nname = \"demo\"\nversion = \"1.2.3\"\n\
                 edition = \"2021\"\nlicense = \"MIT\"\n",
            )
            .unwrap();
            fs::write(source.join("src/lib.rs"), "pub fn demo() {}\n").unwrap();

            let archive = cache.join("demo-1.2.3.crate");
            write_crate(
                &archive,
                &[
                    (
                        "demo-1.2.3/Cargo.toml",
                        fs::read(source.join("Cargo.toml")).unwrap(),
                    ),
                    (
                        "demo-1.2.3/src/lib.rs",
                        fs::read(source.join("src/lib.rs")).unwrap(),
                    ),
                ],
            );
            let checksum = crate::hash::hex(&crate::hash::sha256_file(&archive).unwrap());
            (source, archive, checksum)
        }

        fn registry(&self) -> CargoRegistry {
            let staging = self.0.join("staging");
            fs::create_dir_all(&staging).unwrap();
            CargoRegistry::open(&self.0.join("cargo"), &staging, &PolicyLimits::default()).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn verifies_and_uses_cargos_exact_source_directory() {
        let fixture = Fixture::new();
        let (source, _, checksum) = fixture.package("index.crates.io-fixture");
        let package = fixture
            .registry()
            .load("demo", &Version::parse("1.2.3").unwrap(), &checksum)
            .unwrap();
        assert_eq!(package.manifest.root, source);
        assert_eq!(package.record().unwrap().checksum, package.checksum);
        assert_eq!(package.evidence.license, "MIT");
    }

    #[test]
    fn prepares_a_locked_graph_without_a_lorry_repository() {
        let fixture = Fixture::new();
        let (source, _, checksum) = fixture.package("index.crates.io-fixture");
        let root = fixture.0.join("project");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\n\
             edition = \"2021\"\n[dependencies]\ndemo = \"=1.2.3\"\n",
        )
        .unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(
            root.join("Cargo.lock"),
            format!(
                "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"1.2.3\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{checksum}\"\n\n[[package]]\nname = \"root\"\n\
                 version = \"0.1.0\"\ndependencies = [\"demo\"]\n"
            ),
        )
        .unwrap();
        let manifest = Manifest::load(&root).unwrap();
        let mut config = Config::default();
        config.policy.default = PolicyDefault::Allow;
        let cfg = CfgSet::parse("unix\n").unwrap();
        let staging = fixture.0.join("graph-staging");
        fs::create_dir(&staging).unwrap();
        let prepared = dependency::prepare_locked_cargo_registry(
            &manifest,
            &config,
            &fixture.registry(),
            &Options {
                resolver: manifest.resolver,
                incompatible_rust_versions: Some(IncompatibleRustVersions::Allow),
                rust_version: Version::parse("1.98.0").unwrap(),
                max_packages: 16,
                max_depth: 8,
            },
            TargetSelection {
                target_triple: "x86_64-unknown-linux-gnu",
                target_cfg: &cfg,
                host_triple: "x86_64-unknown-linux-gnu",
                host_cfg: &cfg,
            },
            &staging,
        )
        .unwrap();
        assert_eq!(prepared.packages.len(), 1);
        assert_eq!(
            prepared.packages.values().next().unwrap().source_root(),
            source
        );
        fs::write(source.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
        let error = prepared
            .revalidate_cargo_registry_sources(crate::source_tree::DEFAULT_LIMITS)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed while it was being built")
        );
    }

    #[test]
    fn rejects_modified_and_ambiguous_cargo_sources() {
        let fixture = Fixture::new();
        let (source, _, checksum) = fixture.package("first-registry");
        fs::write(source.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
        let error = fixture
            .registry()
            .load("demo", &Version::parse("1.2.3").unwrap(), &checksum)
            .unwrap_err();
        assert!(error.to_string().contains("does not match"));

        let fixture = Fixture::new();
        let (_, _, checksum) = fixture.package("first-registry");
        fixture.package("second-registry");
        let error = fixture
            .registry()
            .load("demo", &Version::parse("1.2.3").unwrap(), &checksum)
            .unwrap_err();
        assert!(error.to_string().contains("ambiguous"));
    }

    #[test]
    fn rejects_missing_pairs_bad_checksums_and_markers() {
        let fixture = Fixture::new();
        let (_source, archive, checksum) = fixture.package("index.crates.io-fixture");
        fs::remove_file(&archive).unwrap();
        let error = fixture
            .registry()
            .load("demo", &Version::parse("1.2.3").unwrap(), &checksum)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("both the archive and extracted source")
        );

        let fixture = Fixture::new();
        let (_, _, _) = fixture.package("index.crates.io-fixture");
        let error = fixture
            .registry()
            .load("demo", &Version::parse("1.2.3").unwrap(), &"00".repeat(32))
            .unwrap_err();
        assert!(error.to_string().contains("checksum mismatch"));

        let fixture = Fixture::new();
        let (source, _, checksum) = fixture.package("index.crates.io-fixture");
        fs::write(source.join(".cargo-ok"), b"bad").unwrap();
        let error = fixture
            .registry()
            .load("demo", &Version::parse("1.2.3").unwrap(), &checksum)
            .unwrap_err();
        assert!(error.to_string().contains("marker"));
    }

    fn write_crate(path: &Path, files: &[(&str, Vec<u8>)]) {
        let mut tar = Vec::new();
        for (name, contents) in files {
            append_file(&mut tar, name, contents);
        }
        tar.resize(tar.len() + 1024, 0);
        let file = fs::File::create(path).unwrap();
        let mut encoder = GzEncoder::new(file, Compression::default());
        encoder.write_all(&tar).unwrap();
        encoder.finish().unwrap();
    }

    fn append_file(tar: &mut Vec<u8>, name: &str, contents: &[u8]) {
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        put_octal(&mut header[100..108], 0o644);
        put_octal(&mut header[108..116], 0);
        put_octal(&mut header[116..124], 0);
        put_octal(&mut header[124..136], contents.len() as u64);
        put_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        tar.extend_from_slice(&header);
        tar.extend_from_slice(contents);
        let padding = (512 - contents.len() % 512) % 512;
        tar.resize(tar.len() + padding, 0);
    }

    fn put_octal(field: &mut [u8], value: u64) {
        let text = format!("{value:0width$o}", width = field.len() - 1);
        field[..text.len()].copy_from_slice(text.as_bytes());
        field[text.len()] = 0;
    }
}
