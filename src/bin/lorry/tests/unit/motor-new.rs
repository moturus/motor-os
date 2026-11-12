use super::*;
use std::path::PathBuf;
use std::process::Command;

fn access(path: &Path) -> Access {
    let path = std::fs::canonicalize(path).unwrap();
    let path = path.to_str().unwrap();
    with_client(async move |client| {
        let (entry, _) = client.stat(path).await?;
        client
            .metadata(entry)
            .await?
            .access(Role::None)
            .map_err(|_| moto_sdk::rt::Error::InvalidData)
    })
    .unwrap()
}

fn set_none_access(path: &Path, access: Access) {
    let path = path.to_str().unwrap();
    with_client(async move |client| {
        let (entry, _) = client.stat(path).await?;
        let mut permissions = client.metadata(entry).await?.permissions().unwrap();
        permissions.none = access;
        client.set_all_permissions(entry, permissions).await
    })
    .unwrap();
}

#[test]
fn build_state_does_not_change_existing_ancestor_modes() {
    let fixture = PathBuf::from(std::env::var_os("LORRY_MODE_WORKSPACE").unwrap());
    let root = fixture.join(format!("ancestor-modes-{}", std::process::id()));
    let a = root.join("a");
    let b = a.join("b");
    let workspace = b.join("workspace");
    create_dir_all(&workspace).unwrap();
    set_none_access(&b, Access::Rx);
    set_none_access(&a, Access::Rx);
    require_workspace(&workspace).unwrap();
    {
        let _lock = crate::artifact_lock::ArtifactLock::acquire(&workspace.join("target")).unwrap();
        let _output =
            crate::atomic::AtomicDirectory::new(&workspace.join("target/new/units"), "test")
                .unwrap();
        assert_eq!(access(&workspace.join("target/new/units")), Access::Rwx);
        assert_eq!(access(&a), Access::Rx);
        assert_eq!(access(&b), Access::Rx);
    }
    set_none_access(&a, Access::Rwx);
    set_none_access(&b, Access::Rwx);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn new_shares_relative_paths_without_sharing_paths_outside_none() {
    let lorry = std::env::var_os("LORRY_NATIVE_LORRY").expect("native driver supplies Lorry");
    let fixture = PathBuf::from(std::env::var_os("LORRY_MODE_WORKSPACE").unwrap());
    let parent = fixture.parent().unwrap();
    let name = format!("relative-{}", std::process::id());
    let workspace = parent.join(&name);
    let run = |directory: &Path, arguments: &[&str]| {
        let output = Command::new(&lorry)
            .current_dir(directory)
            .args(arguments)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run(parent, &["new", &name]);
    assert_eq!(access(&workspace), Access::Rwx);
    assert_eq!(access(&workspace.join("src/main.rs")), Access::Rw);
    run(&workspace, &["run", "--offline"]);
    std::fs::remove_dir_all(&workspace).unwrap();

    if crate::role::Role::current() == crate::role::Role::Interactive {
        let before = access(Path::new("/user/tmp"));
        let outside = PathBuf::from("/none/../user/tmp").join(&name);
        run(parent, &["new", outside.to_str().unwrap()]);
        assert_eq!(access(Path::new("/user/tmp")), before);
        assert_eq!(access(&outside), Access::Rx);
        assert_eq!(access(&outside.join("src/main.rs")), Access::R);
        let output = Command::new(&lorry)
            .current_dir(&outside)
            .arg("build")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be built as None"));
        std::fs::remove_dir_all(outside).unwrap();
    }
}
