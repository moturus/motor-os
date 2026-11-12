//! The same Git tree is materialized on Linux and by both Motor roles.
use super::*;
use crate::atomic::AtomicFile;
use crate::fs_check::set_file_mode;
use gix::objs::tree::{Entry, EntryKind};

const URL: &str = "https://example.invalid/lorry-source-modes";
const COMMIT: &str = "1111111111111111111111111111111111111111";
// Shared with the native run: no caller-dependent permissions enter this hash.
const DIGEST: &str = "f9a50bb51dabc481492564410c0ff4e5e4f6464a40b3ed726a57788e92393fdc";

fn locked() -> LockedSource {
    LockedSource {
        cargo_source: format!("git+{URL}#{COMMIT}"),
        url: URL.into(),
        selector: GitSelector::Head,
        commit: COMMIT.into(),
    }
}

fn directory(path: &Path) {
    crate::fs_check::create_dir_all(path).unwrap();
}

fn write(path: &Path, contents: &[u8]) {
    let mut file = AtomicFile::new(path).unwrap();
    file.write_all(contents).unwrap();
    file.commit().unwrap();
}

fn materialize(workspace: &Path) {
    directory(&workspace.join("src"));
    let repository = gix::init_bare(workspace.join("fixture.git")).unwrap();
    let mut entries = Vec::new();
    for (name, contents, kind) in [
        (
            "Cargo.toml",
            "[package]\nname = \"mode-dependency\"\nversion = \"1.0.0\"\nedition = \"2024\"\n[lib]\npath = \"lib.rs\"\n",
            EntryKind::Blob,
        ),
        ("lib.rs", "pub fn answer() -> u32 { 42 }\n", EntryKind::Blob),
        (
            "run.sh",
            "#!/user/bin/rush\necho executable-source\n",
            EntryKind::BlobExecutable,
        ),
    ] {
        entries.push(Entry {
            mode: kind.into(),
            filename: name.into(),
            oid: repository.write_blob(contents).unwrap().detach(),
        });
    }
    let tree_id = repository
        .write_object(gix::objs::Tree { entries })
        .unwrap();
    let tree = repository.find_tree(tree_id).unwrap();
    let object = object_root(workspace, &locked().cargo_source);
    let source = object.join("source");
    directory(&source);
    extract_tree(
        &repository,
        &tree,
        &source,
        tree_limits(&PolicyLimits::default()).unwrap(),
    )
    .unwrap();
    let scan = Tree::scan(
        &source,
        tree_limits(&PolicyLimits::default()).unwrap(),
        Exclusions::None,
    )
    .unwrap();
    write(
        &object.join("git.toml"),
        provenance(&locked(), &tree_id.to_string(), &scan).as_bytes(),
    );
    write(&workspace.join("Cargo.toml"), format!(
        "[package]\nname = \"role-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[dependencies]\nmode-dependency = {{ git = \"{URL}\" }}\n"
    ).as_bytes());
    write(&workspace.join("Cargo.lock"), format!(
        "version = 4\n[[package]]\nname = \"role-fixture\"\nversion = \"0.1.0\"\ndependencies = [\"mode-dependency\"]\n[[package]]\nname = \"mode-dependency\"\nversion = \"1.0.0\"\nsource = \"git+{URL}#{COMMIT}\"\n"
    ).as_bytes());
    write(&workspace.join("src/main.rs"), br#"
fn check_caps() {
    if let Ok(expected) = std::env::var("LORRY_EXPECT_INTERACTIVE") {
        let path = format!("/user/tmp/lorry-role-probe-{}", std::process::id());
        let result = std::fs::File::create(&path);
        assert_eq!(result.is_ok(), expected == "true");
        if let Ok(file) = result { drop(file); std::fs::remove_file(path).unwrap(); }
    }
}
fn main() { check_caps(); assert_eq!(mode_dependency::answer(), 42); println!("role-fixture PASS"); }
#[test] fn caller_capabilities() { check_caps(); }
"#);
}

fn verify(workspace: &Path) {
    let limits = PolicyLimits::default();
    for validation in [ValidationMode::Strict, ValidationMode::Trusted] {
        let object = load_object(workspace, &locked(), &limits, validation).unwrap();
        assert_eq!(hex(&object.source_tree.sha256), DIGEST);
        assert_eq!(
            object
                .source_tree
                .entries
                .iter()
                .filter(|e| e.executable)
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            ["run.sh"]
        );
    }
}

fn tamper(workspace: &Path) {
    let root = object_root(workspace, &locked().cargo_source);
    let before = fs::read(root.join("git.toml")).unwrap();
    let path = root.join("source/run.sh");
    let file = fs::File::open(&path).unwrap();
    set_file_mode(&file, &path, false).unwrap();
    for validation in [ValidationMode::Strict, ValidationMode::Trusted] {
        let error = load_object(workspace, &locked(), &PolicyLimits::default(), validation)
            .err()
            .unwrap();
        assert!(error.render().contains("changed after approval"));
    }
    assert_eq!(fs::read(root.join("git.toml")).unwrap(), before);
    set_file_mode(&file, &path, true).unwrap();
    verify(workspace);
}

#[test]
fn git_source_modes() {
    let supplied = std::env::var_os("LORRY_MODE_WORKSPACE");
    #[cfg(target_os = "motor")]
    assert!(
        supplied.is_some(),
        "native driver must supply a shared fixture root"
    );
    let workspace = supplied.map(PathBuf::from).unwrap_or_else(|| {
        std::env::temp_dir().join(format!("lorry-source-modes-{}", std::process::id()))
    });
    match std::env::var("LORRY_MODE_ACTION").as_deref() {
        Ok("verify") => verify(&workspace),
        Ok("tamper") => tamper(&workspace),
        _ => {
            materialize(&workspace);
            verify(&workspace);
            #[cfg(not(target_os = "motor"))]
            {
                tamper(&workspace);
                fs::remove_dir_all(workspace).unwrap();
            }
        }
    }
}

#[cfg(target_os = "motor")]
#[test]
fn final_executable_modes() {
    use moto_sdk::io::fs::{AccessPermissions, FsClient, Role};
    let root = PathBuf::from(std::env::var_os("LORRY_MODE_WORKSPACE").unwrap());
    let binary = root.join("target/lorry/debug/role-fixture");
    let mut runtime = moto_sdk::async_runtime::LocalRuntime::new();
    runtime.block_on(async {
        let client = FsClient::connect().unwrap();
        for (path, expected) in [
            (binary, AccessPermissions::Rx),
            (root.join("target"), AccessPermissions::Rwx),
            (root.join("target/lorry"), AccessPermissions::Rwx),
            (root.join("Cargo.lock"), AccessPermissions::Rw),
            (
                root.join(".lorry/dependencies-v2.toml"),
                AccessPermissions::Rw,
            ),
        ] {
            let (id, _) = client.stat(path.to_str().unwrap()).await.unwrap();
            assert_eq!(
                client
                    .metadata(id)
                    .await
                    .unwrap()
                    .access(Role::None)
                    .unwrap(),
                expected,
                "{}",
                path.display()
            );
        }
    });
}
