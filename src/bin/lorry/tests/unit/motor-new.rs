use super::*;
use std::path::PathBuf;

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

/// Every thread opens its own connection, and more of them start together
/// here than sys-io keeps listeners waiting.
#[test]
fn threads_that_start_together_all_connect() {
    const THREADS: usize = 32;
    for _ in 0..8 {
        let barrier = std::sync::Barrier::new(THREADS);
        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    barrier.wait();
                    with_client(async |client| client.stat("/").await.map(|_| ())).unwrap();
                });
            }
        });
    }
}

#[test]
fn build_state_does_not_change_existing_ancestor_modes() {
    let fixture = PathBuf::from("/none/tmp");
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
