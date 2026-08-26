use async_fs::{AccessPermissions, RolePermissions};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileClass {
    Regular,
    Script,
    Elf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageEntryKind {
    Directory,
    File(FileClass),
}

#[derive(Debug)]
pub struct ImageEntry {
    pub path: PathBuf,
    pub kind: ImageEntryKind,
}

#[derive(Clone, Copy, Debug)]
struct PermissionProfile {
    directory: RolePermissions,
    file: RolePermissions,
    script: RolePermissions,
    elf: RolePermissions,
}

impl PermissionProfile {
    fn file(self, class: FileClass) -> RolePermissions {
        match class {
            FileClass::Regular => self.file,
            FileClass::Script => self.script,
            FileClass::Elf => self.elf,
        }
    }
}

#[derive(Debug)]
struct TreeRule {
    path: PathBuf,
    profile: PermissionProfile,
}

#[derive(Debug)]
pub struct PermissionPolicy {
    source: PathBuf,
    default: PermissionProfile,
    trees: Vec<TreeRule>,
    entries: BTreeMap<PathBuf, RolePermissions>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    default: RawProfile,
    trees: Vec<RawTreeRule>,
    entries: Vec<RawEntryRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    directory: String,
    file: String,
    script: String,
    elf: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTreeRule {
    path: String,
    directory: String,
    file: String,
    script: String,
    elf: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntryRule {
    path: String,
    mode: String,
}

impl PermissionPolicy {
    pub fn load(config_path: &Path, reference: &str) -> Result<Self, String> {
        let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
        let policy_path = parent.join(reference);
        let contents = fs::read_to_string(&policy_path).map_err(|error| {
            format!(
                "image config '{}': cannot read permission policy '{}': {error}",
                config_path.display(),
                policy_path.display()
            )
        })?;
        Self::parse(&contents, policy_path)
            .map_err(|error| format!("image config '{}': {error}", config_path.display()))
    }

    fn parse(contents: &str, source: PathBuf) -> Result<Self, String> {
        let raw: RawPolicy = serde_yaml::from_str(contents)
            .map_err(|error| format!("permission policy '{}': {error}", source.display()))?;
        let default = parse_profile(&raw.default, "default", &source)?;

        let mut tree_paths = BTreeSet::new();
        let mut trees = Vec::with_capacity(raw.trees.len());
        for rule in raw.trees {
            let path = parse_path(&rule.path, "tree", &source)?;
            if !tree_paths.insert(path.clone()) {
                return Err(format!(
                    "permission policy '{}': duplicate tree '{}'",
                    source.display(),
                    path.display()
                ));
            }
            let profile = parse_profile(
                &RawProfile {
                    directory: rule.directory,
                    file: rule.file,
                    script: rule.script,
                    elf: rule.elf,
                },
                &format!("tree '{}'", path.display()),
                &source,
            )?;
            trees.push(TreeRule { path, profile });
        }

        let mut entries = BTreeMap::new();
        for rule in raw.entries {
            let path = parse_path(&rule.path, "entry", &source)?;
            let mode = parse_mode(&rule.mode, &format!("entry '{}'", path.display()), &source)?;
            if entries.insert(path.clone(), mode).is_some() {
                return Err(format!(
                    "permission policy '{}': duplicate entry '{}'",
                    source.display(),
                    path.display()
                ));
            }
        }

        Ok(Self {
            source,
            default,
            trees,
            entries,
        })
    }

    pub fn directory_permissions(&self, path: &Path) -> RolePermissions {
        self.entries
            .get(path)
            .copied()
            .unwrap_or_else(|| self.profile(path).directory)
    }

    pub fn file_permissions(&self, path: &Path, class: FileClass) -> RolePermissions {
        self.entries
            .get(path)
            .copied()
            .unwrap_or_else(|| self.profile(path).file(class))
    }

    pub fn validate_image(&self, image_entries: &[ImageEntry]) -> Result<(), String> {
        let mut entries = BTreeMap::new();
        for entry in image_entries {
            if let Some(previous) = entries.insert(entry.path.clone(), entry.kind) {
                if previous != entry.kind {
                    return Err(format!(
                        "permission policy '{}': image path '{}' is both a file and a directory",
                        self.source.display(),
                        entry.path.display()
                    ));
                }
            }
        }

        for path in self.entries.keys() {
            if !entries.contains_key(path) {
                return Err(format!(
                    "permission policy '{}': exact entry '{}' does not exist in the image",
                    self.source.display(),
                    path.display()
                ));
            }
        }

        for (path, kind) in entries {
            let mode = match kind {
                ImageEntryKind::Directory => self.directory_permissions(&path),
                ImageEntryKind::File(class) => self.file_permissions(&path, class),
            };
            validate_entry_mode(kind, mode).map_err(|reason| {
                format!(
                    "permission policy '{}': '{}' resolves to '{}': {reason}",
                    self.source.display(),
                    path.display(),
                    mode_string(mode)
                )
            })?;

            if path.parent() == Some(Path::new("/system/bin"))
                && matches!(
                    kind,
                    ImageEntryKind::File(FileClass::Script | FileClass::Elf)
                )
                && mode != RolePermissions::all(AccessPermissions::Rx)
            {
                return Err(format!(
                    "permission policy '{}': executable '{}' must resolve to 'r-xr-xr-x'",
                    self.source.display(),
                    path.display()
                ));
            }

            if path.starts_with("/system/logs")
                && matches!(
                    kind,
                    ImageEntryKind::File(FileClass::Script | FileClass::Elf)
                )
            {
                return Err(format!(
                    "permission policy '{}': executable '{}' may not be shipped under /system/logs",
                    self.source.display(),
                    path.display()
                ));
            }
        }
        Ok(())
    }

    fn profile(&self, path: &Path) -> PermissionProfile {
        let mut result = self.default;
        let mut depth = 0;
        for rule in &self.trees {
            let rule_depth = rule.path.components().count();
            if rule_depth > depth && path.starts_with(&rule.path) {
                result = rule.profile;
                depth = rule_depth;
            }
        }
        result
    }
}

pub fn classify_source(source: &Path) -> Result<FileClass, String> {
    let metadata = fs::metadata(source).map_err(|error| {
        format!(
            "cannot read metadata for source '{}': {error}",
            source.display()
        )
    })?;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Ok(FileClass::Regular);
    }

    let mut file = File::open(source).map_err(|error| {
        format!(
            "cannot open executable source '{}': {error}",
            source.display()
        )
    })?;
    let mut prefix = [0_u8; 64];
    let length = file.read(&mut prefix).map_err(|error| {
        format!(
            "cannot read executable source '{}': {error}",
            source.display()
        )
    })?;
    let prefix = &prefix[..length];
    if prefix.starts_with(b"#!") {
        return Ok(FileClass::Script);
    }
    if is_executable_elf(prefix) {
        return Ok(FileClass::Elf);
    }
    Err(format!(
        "host-executable source '{}' is neither a shebang script nor an ET_EXEC/ET_DYN ELF",
        source.display()
    ))
}

fn is_executable_elf(prefix: &[u8]) -> bool {
    if prefix.len() < 18
        || &prefix[..4] != b"\x7fELF"
        || !matches!(prefix[4], 1 | 2)
        || !matches!(prefix[5], 1 | 2)
        || prefix[6] != 1
    {
        return false;
    }
    let elf_type = match prefix[5] {
        1 => u16::from_le_bytes([prefix[16], prefix[17]]),
        2 => u16::from_be_bytes([prefix[16], prefix[17]]),
        _ => unreachable!(),
    };
    matches!(elf_type, 2 | 3)
}

fn parse_profile(
    raw: &RawProfile,
    context: &str,
    source: &Path,
) -> Result<PermissionProfile, String> {
    let profile = PermissionProfile {
        directory: parse_mode(&raw.directory, &format!("{context} directory"), source)?,
        file: parse_mode(&raw.file, &format!("{context} file"), source)?,
        script: parse_mode(&raw.script, &format!("{context} script"), source)?,
        elf: parse_mode(&raw.elf, &format!("{context} elf"), source)?,
    };
    for (kind, mode) in [
        (ImageEntryKind::Directory, profile.directory),
        (ImageEntryKind::File(FileClass::Regular), profile.file),
        (ImageEntryKind::File(FileClass::Script), profile.script),
        (ImageEntryKind::File(FileClass::Elf), profile.elf),
    ] {
        validate_entry_mode(kind, mode).map_err(|reason| {
            format!(
                "permission policy '{}': {context} mode '{}': {reason}",
                source.display(),
                mode_string(mode)
            )
        })?;
    }
    Ok(profile)
}

fn parse_mode(value: &str, context: &str, source: &Path) -> Result<RolePermissions, String> {
    super::chmod::parse_mode(value).ok_or_else(|| {
        format!(
            "permission policy '{}': invalid {context} mode '{value}'",
            source.display()
        )
    })
}

fn parse_path(value: &str, kind: &str, source: &Path) -> Result<PathBuf, String> {
    if !normalized_absolute_path(value) {
        return Err(format!(
            "permission policy '{}': {kind} path '{value}' must be normalized and absolute",
            source.display()
        ));
    }
    Ok(PathBuf::from(value))
}

fn normalized_absolute_path(value: &str) -> bool {
    value == "/"
        || (value.starts_with('/')
            && !value.ends_with('/')
            && value[1..]
                .split('/')
                .all(|component| !component.is_empty() && !matches!(component, "." | "..")))
}

fn validate_entry_mode(kind: ImageEntryKind, mode: RolePermissions) -> Result<(), &'static str> {
    match kind {
        ImageEntryKind::Directory if mode.system != AccessPermissions::Rwx => {
            Err("directory modes must grant System rwx")
        }
        ImageEntryKind::File(FileClass::Regular)
            if [mode.system, mode.interactive, mode.none]
                .into_iter()
                .any(AccessPermissions::can_execute) =>
        {
            Err("regular-file modes may not grant execute")
        }
        ImageEntryKind::File(FileClass::Script) if !mode.system.can_execute() => {
            Err("script modes must grant System execute")
        }
        ImageEntryKind::File(FileClass::Elf)
            if !mode.system.can_execute()
                || [mode.system, mode.interactive, mode.none]
                    .into_iter()
                    .any(AccessPermissions::can_write) =>
        {
            Err("ELF modes must grant System execute and deny write to every role")
        }
        _ => Ok(()),
    }
}

pub fn mode_string(mode: RolePermissions) -> String {
    fn access(value: AccessPermissions) -> &'static str {
        match value {
            AccessPermissions::Rwx => "rwx",
            AccessPermissions::Rx => "r-x",
            AccessPermissions::Rw => "rw-",
            AccessPermissions::R => "r--",
            AccessPermissions::None => "---",
        }
    }
    format!(
        "{}{}{}",
        access(mode.system),
        access(mode.interactive),
        access(mode.none)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create() -> Self {
            loop {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "motor-imager-permissions-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("cannot create test directory: {error}"),
                }
            }
        }

        fn write(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, bytes).unwrap();
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(mode);
            fs::set_permissions(&path, permissions).unwrap();
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn policy(trees: &str, entries: &str) -> String {
        format!(
            r#"default:
  directory: "rwxr-xr-x"
  file: "rw-r--r--"
  script: "rwxr-xr-x"
  elf: "r-xr-xr-x"
trees:
{trees}entries:
{entries}"#
        )
    }

    fn parse(contents: &str) -> Result<PermissionPolicy, String> {
        PermissionPolicy::parse(contents, PathBuf::from("test-policy.yaml"))
    }

    #[test]
    fn production_policy_parses_and_resolves_all_classes() {
        let policy = parse(include_str!("../motor-os-permissions.yaml")).unwrap();
        assert_eq!(
            mode_string(policy.directory_permissions(Path::new("/"))),
            "rwxr-xr-x"
        );
        assert_eq!(
            mode_string(policy.file_permissions(Path::new("/system/bin/sh"), FileClass::Script)),
            "r-xr-xr-x"
        );
        assert_eq!(
            mode_string(policy.file_permissions(Path::new("/user/bin/tool"), FileClass::Script)),
            "rwxrwxr-x"
        );
        assert_eq!(
            mode_string(policy.file_permissions(Path::new("/user/bin/tool"), FileClass::Elf)),
            "r-xr-xr-x"
        );
        assert_eq!(
            mode_string(policy.directory_permissions(Path::new("/user/cfg/private"))),
            "rwxrwx---"
        );
        assert_eq!(
            mode_string(
                policy.file_permissions(Path::new("/system/cfg/sshd.toml"), FileClass::Regular)
            ),
            "rw-r-----"
        );
        assert_eq!(
            mode_string(policy.directory_permissions(Path::new("/system/logs"))),
            "rwxr-x---"
        );
        assert_eq!(
            mode_string(
                policy.file_permissions(Path::new("/system/logs/a.log"), FileClass::Regular)
            ),
            "rw-r-----"
        );
        assert_eq!(
            mode_string(policy.file_permissions(Path::new("/system/logs/a"), FileClass::Script)),
            "r-xr-----"
        );
        assert_eq!(
            mode_string(policy.file_permissions(Path::new("/system/logs/a"), FileClass::Elf)),
            "r-xr-----"
        );
    }

    #[test]
    fn production_policy_rejects_executables_under_logs() {
        let policy = parse(include_str!("../motor-os-permissions.yaml")).unwrap();
        let mut entries = [
            ImageEntry {
                path: PathBuf::from("/system/cfg/sshd.toml"),
                kind: ImageEntryKind::File(FileClass::Regular),
            },
            ImageEntry {
                path: PathBuf::from("/system/cfg/ssl/ssl-key.pem"),
                kind: ImageEntryKind::File(FileClass::Regular),
            },
            ImageEntry {
                path: PathBuf::from("/system/logs/not-a-log"),
                kind: ImageEntryKind::File(FileClass::Script),
            },
        ];
        for class in [FileClass::Script, FileClass::Elf] {
            entries[2].kind = ImageEntryKind::File(class);
            assert!(policy
                .validate_image(&entries)
                .unwrap_err()
                .contains("may not be shipped under /system/logs"));
        }
    }

    #[test]
    fn policy_rejects_bad_modes_rules_and_unknown_fields() {
        let malformed = policy("  []\n", "  []\n").replacen("rw-r--r--", "bad", 1);
        assert!(parse(&malformed)
            .unwrap_err()
            .contains("invalid default file mode"));

        let non_monotonic = policy("  []\n", "  []\n").replacen("rw-r--r--", "r--rw----", 1);
        assert!(parse(&non_monotonic)
            .unwrap_err()
            .contains("invalid default file mode"));

        let writable_elf =
            policy("  []\n", "  []\n").replacen("elf: \"r-xr-xr-x\"", "elf: \"rwxr-xr-x\"", 1);
        assert!(parse(&writable_elf).unwrap_err().contains("ELF modes"));

        let duplicate_tree = policy(
            r#"  - path: "/user"
    directory: "rwxrwxr-x"
    file: "rw-rw-r--"
    script: "rwxrwxr-x"
    elf: "r-xr-xr-x"
  - path: "/user"
    directory: "rwxrwxr-x"
    file: "rw-rw-r--"
    script: "rwxrwxr-x"
    elf: "r-xr-xr-x"
"#,
            "  []\n",
        );
        assert!(parse(&duplicate_tree)
            .unwrap_err()
            .contains("duplicate tree"));

        let duplicate_entry = policy(
            "  []\n",
            r#"  - path: "/secret"
    mode: "rw-------"
  - path: "/secret"
    mode: "rw-------"
"#,
        );
        assert!(parse(&duplicate_entry)
            .unwrap_err()
            .contains("duplicate entry"));

        let non_normalized = policy(
            r#"  - path: "/user/../system"
    directory: "rwxr-xr-x"
    file: "rw-r--r--"
    script: "rwxr-xr-x"
    elf: "r-xr-xr-x"
"#,
            "  []\n",
        );
        assert!(parse(&non_normalized)
            .unwrap_err()
            .contains("normalized and absolute"));

        let unknown =
            policy("  []\n", "  []\n").replacen("default:\n", "default:\n  typo: true\n", 1);
        assert!(parse(&unknown).unwrap_err().contains("unknown field"));
    }

    #[test]
    fn exact_and_longest_component_rules_take_precedence() {
        let contents = policy(
            r#"  - path: "/user"
    directory: "rwxrwxr-x"
    file: "rw-rw-r--"
    script: "rwxrwxr-x"
    elf: "r-xr-xr-x"
  - path: "/user/bin"
    directory: "rwxrwxr-x"
    file: "rw-rw----"
    script: "rwxrwxr-x"
    elf: "r-xr-xr-x"
"#,
            r#"  - path: "/user/bin/exact"
    mode: "r--------"
"#,
        );
        let policy = parse(&contents).unwrap();
        assert_eq!(
            mode_string(policy.file_permissions(Path::new("/user/file"), FileClass::Regular)),
            "rw-rw-r--"
        );
        assert_eq!(
            mode_string(policy.file_permissions(Path::new("/user/bin/file"), FileClass::Regular)),
            "rw-rw----"
        );
        assert_eq!(
            mode_string(policy.file_permissions(Path::new("/user/bin/exact"), FileClass::Regular)),
            "r--------"
        );
        assert_eq!(
            mode_string(policy.file_permissions(Path::new("/username/file"), FileClass::Regular)),
            "rw-r--r--"
        );
    }

    #[test]
    fn exact_entries_must_exist_and_match_their_file_class() {
        let contents = policy(
            "  []\n",
            r#"  - path: "/script"
    mode: "rwxrwxr-x"
"#,
        );
        let policy = parse(&contents).unwrap();
        let root = ImageEntry {
            path: PathBuf::from("/"),
            kind: ImageEntryKind::Directory,
        };
        assert!(policy
            .validate_image(&[root])
            .unwrap_err()
            .contains("does not exist"));

        let entries = [
            ImageEntry {
                path: PathBuf::from("/"),
                kind: ImageEntryKind::Directory,
            },
            ImageEntry {
                path: PathBuf::from("/script"),
                kind: ImageEntryKind::File(FileClass::Regular),
            },
        ];
        assert!(policy
            .validate_image(&entries)
            .unwrap_err()
            .contains("regular-file"));
    }

    #[test]
    fn source_classification_uses_only_host_execute_and_file_headers() {
        let directory = TestDirectory::create();
        let script_minimal = directory.write("minimal", b"#!/system/bin/rush\n", 0o500);
        let script_full = directory.write("full", b"#!/system/bin/rush\n", 0o777);
        let data = directory.write("data", b"plain data\n", 0o666);
        let unknown = directory.write("unknown", b"plain data\n", 0o700);

        let mut executable_elf = [0_u8; 64];
        executable_elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        executable_elf[16..18].copy_from_slice(&3_u16.to_le_bytes());
        let elf = directory.write("elf", &executable_elf, 0o500);

        let mut object_elf = executable_elf;
        object_elf[16..18].copy_from_slice(&1_u16.to_le_bytes());
        let object = directory.write("object", &object_elf, 0o600);

        assert_eq!(classify_source(&script_minimal).unwrap(), FileClass::Script);
        assert_eq!(classify_source(&script_full).unwrap(), FileClass::Script);
        assert_eq!(classify_source(&data).unwrap(), FileClass::Regular);
        assert_eq!(classify_source(&elf).unwrap(), FileClass::Elf);
        assert_eq!(classify_source(&object).unwrap(), FileClass::Regular);
        assert!(classify_source(&unknown).unwrap_err().contains("neither"));

        let policy = parse(&policy("  []\n", "  []\n")).unwrap();
        assert_eq!(
            policy.file_permissions(
                Path::new("/script"),
                classify_source(&script_minimal).unwrap()
            ),
            policy.file_permissions(Path::new("/script"), classify_source(&script_full).unwrap())
        );
    }
}
