//! Bounded repository metadata discovery. This module never runs project code.

use std::collections::BTreeSet;
use std::path::Path;

use super::{Workspace, fs};
use crate::config::Resources;

#[derive(Debug, PartialEq, Eq)]
pub struct Manifest {
    pub path: String,
    pub kind: &'static str,
    pub language: Option<&'static str>,
    pub toolchain: Option<&'static str>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Excluded {
    pub path: String,
    pub kind: &'static str,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Check {
    pub cwd: String,
    pub program: &'static str,
    pub args: Vec<&'static str>,
    pub source: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Profile {
    pub roots: Vec<String>,
    pub manifests: Vec<Manifest>,
    pub languages: Vec<&'static str>,
    pub excluded: Vec<Excluded>,
    pub checks: Vec<Check>,
    pub rust_backend: Option<&'static str>,
    pub visited_directories: usize,
    pub unreadable_entries: usize,
    pub truncated: bool,
}

pub fn discover(workspace: &Workspace, resources: Resources) -> Result<Profile, String> {
    let limit = resources.search_max_results_per_page;
    let mut manifests = Vec::new();
    let mut excluded = Vec::new();
    let mut stack = vec![workspace.root().to_path_buf()];
    let mut visited = 0usize;
    let mut unreadable = 0usize;
    let mut truncated = false;

    while let Some(directory) = stack.pop() {
        if visited == limit {
            truncated = true;
            break;
        }
        visited += 1;
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if directory == workspace.root() => {
                return Err(format!("repository profile: {error}"));
            }
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        let mut entries: Vec<_> = entries
            .filter_map(|entry| match entry {
                Ok(entry) => Some(entry),
                Err(_) => {
                    unreadable += 1;
                    None
                }
            })
            .collect();
        entries.sort_by_key(|entry| entry.file_name());
        let mut subdirectories = Vec::new();
        for entry in entries {
            let path = entry.path();
            if workspace.is_denied(&path) {
                continue;
            }
            let Ok(kind) = entry.file_type() else {
                unreadable += 1;
                continue;
            };
            if kind.is_symlink() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if kind.is_dir() {
                if fs::SKIPPED.contains(&name.as_str()) {
                    push_limited(
                        &mut excluded,
                        Excluded {
                            path: shown(workspace, &path),
                            kind: exclusion_kind(&name),
                        },
                        limit,
                        &mut truncated,
                    );
                } else {
                    subdirectories.push(path);
                }
            } else if kind.is_file()
                && let Some((manifest_kind, language, toolchain)) = manifest_kind(&name)
            {
                push_limited(
                    &mut manifests,
                    Manifest {
                        path: shown(workspace, &path),
                        kind: manifest_kind,
                        language,
                        toolchain,
                    },
                    limit,
                    &mut truncated,
                );
            }
        }
        subdirectories.reverse();
        stack.extend(subdirectories);
    }

    manifests.sort_by(|left, right| left.path.cmp(&right.path));
    excluded.sort_by(|left, right| left.path.cmp(&right.path));
    let roots = roots(&manifests);
    let languages = manifests
        .iter()
        .filter_map(|manifest| manifest.language)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let (checks, rust_backend) = checks(&manifests);
    Ok(Profile {
        roots,
        manifests,
        languages,
        excluded,
        checks,
        rust_backend,
        visited_directories: visited,
        unreadable_entries: unreadable,
        truncated,
    })
}

fn manifest_kind(name: &str) -> Option<(&'static str, Option<&'static str>, Option<&'static str>)> {
    Some(match name {
        "Cargo.toml" => ("Cargo manifest", Some("Rust"), Some("Cargo")),
        "rust-toolchain" | "rust-toolchain.toml" => {
            ("Rust toolchain", Some("Rust"), Some("rustup"))
        }
        "package.json" => (
            "package manifest",
            Some("JavaScript/TypeScript"),
            Some("npm"),
        ),
        "pyproject.toml" => ("Python project", Some("Python"), Some("Python")),
        "go.mod" => ("Go module", Some("Go"), Some("Go")),
        "CMakeLists.txt" => ("CMake project", Some("C/C++"), Some("CMake")),
        "Makefile" => ("Makefile", None, Some("Make")),
        _ => return None,
    })
}

fn exclusion_kind(name: &str) -> &'static str {
    match name {
        ".git" | ".hg" | ".svn" => "version control",
        ".gears" => "Gears state",
        "generated" => "generated",
        "vendor" | "node_modules" => "vendor/dependency",
        "target" | "build" | "dist" | "out" => "build output",
        _ => "excluded",
    }
}

fn roots(manifests: &[Manifest]) -> Vec<String> {
    let mut roots = BTreeSet::from([".".to_string()]);
    for manifest in manifests {
        let parent = Path::new(&manifest.path).parent().unwrap_or(Path::new(""));
        roots.insert(if parent.as_os_str().is_empty() {
            ".".to_string()
        } else {
            parent.display().to_string()
        });
    }
    roots.into_iter().collect()
}

fn checks(manifests: &[Manifest]) -> (Vec<Check>, Option<&'static str>) {
    let mut checks = BTreeSet::new();
    let mut rust_backend = None;
    for manifest in manifests {
        let cwd = Path::new(&manifest.path)
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .map_or_else(|| ".".to_string(), |path| path.display().to_string());
        let commands: &[(&str, &[&str])] = match manifest.kind {
            "Cargo manifest" if cfg!(target_os = "motor") => {
                rust_backend = Some("lorry");
                &[("lorry", &["build"]), ("lorry", &["test"])]
            }
            "Cargo manifest" => {
                rust_backend = Some("cargo");
                &[
                    ("cargo", &["build"]),
                    ("cargo", &["test"]),
                    ("cargo", &["check"]),
                    ("cargo", &["clippy", "--all-targets"]),
                    ("cargo", &["fmt", "--check"]),
                ]
            }
            "package manifest" => &[("npm", &["test"])],
            "Python project" => &[("python", &["-m", "pytest"])],
            "Go module" => &[("go", &["test", "./..."])],
            "Makefile" => &[("make", &["test"])],
            _ => &[],
        };
        for (program, args) in commands {
            checks.insert(Check {
                cwd: cwd.clone(),
                program,
                args: args.to_vec(),
                source: manifest.path.clone(),
            });
        }
    }
    (checks.into_iter().collect(), rust_backend)
}

fn shown(workspace: &Workspace, path: &Path) -> String {
    let shown = workspace.display(path);
    if shown.is_empty() {
        ".".to_string()
    } else {
        shown
    }
}

fn push_limited<T>(values: &mut Vec<T>, value: T, limit: usize, truncated: &mut bool) {
    if values.len() < limit {
        values.push(value);
    } else {
        *truncated = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_is_deterministic_bounded_and_never_enters_exclusions() {
        let base = std::env::temp_dir().join(format!("gears-profile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        for directory in ["crates/a", "web", "target/hidden", "vendor/dependency"] {
            std::fs::create_dir_all(base.join(directory)).unwrap();
        }
        std::fs::write(base.join("Cargo.toml"), "not parsed or executed").unwrap();
        std::fs::write(base.join("Makefile"), "test:\n\tfalse\n").unwrap();
        std::fs::write(base.join("crates/a/Cargo.toml"), "not parsed").unwrap();
        std::fs::write(base.join("web/package.json"), "not parsed").unwrap();
        std::fs::write(base.join("target/hidden/Cargo.toml"), "must not appear").unwrap();
        let workspace = Workspace::new(&base).unwrap();

        let profile = discover(&workspace, Resources::default()).unwrap();
        assert_eq!(profile.roots, [".", "crates/a", "web"]);
        assert_eq!(profile.languages, ["JavaScript/TypeScript", "Rust"]);
        assert_eq!(
            profile.rust_backend,
            Some(if cfg!(target_os = "motor") {
                "lorry"
            } else {
                "cargo"
            })
        );
        assert!(profile.excluded.iter().any(|item| item.path == "target"));
        assert!(profile.excluded.iter().any(|item| item.path == "vendor"));
        assert!(
            !profile
                .manifests
                .iter()
                .any(|item| item.path.contains("hidden"))
        );
        assert!(profile.checks.iter().any(|check| check.args == ["test"]));

        let resources = Resources {
            search_default_results: 1,
            search_max_results_per_page: 1,
            ..Resources::default()
        };
        assert!(discover(&workspace, resources).unwrap().truncated);
        std::fs::remove_dir_all(base).unwrap();
    }
}
