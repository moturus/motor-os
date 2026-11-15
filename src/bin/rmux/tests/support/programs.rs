//! Commands used by the process tests, without depending on host utilities.

#[cfg(not(target_os = "motor"))]
pub fn program(name: &str) -> String {
    name.to_owned()
}

#[cfg(target_os = "motor")]
pub fn program(name: &str) -> String {
    use moto_sdk::io::fs::{AccessPermissions as Access, FsClient};
    use std::path::PathBuf;
    use std::sync::OnceLock;

    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    let root = ROOT.get_or_init(|| {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("pane-programs-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let probe = env!("CARGO_BIN_EXE_rmux-probe").replace('\'', "'\\''");
        for (name, body) in [
            ("true", "exit 0\n".to_owned()),
            ("cat", format!("exec '{probe}' echo\n")),
        ] {
            let path = root.join(name);
            std::fs::write(&path, format!("#!/user/bin/rush\n{body}")).unwrap();
            moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
                let client = FsClient::connect().unwrap();
                let (id, _) = client.stat(path.to_str().unwrap()).await.unwrap();
                // The pane may run as None even when its test is Interactive.
                let mut permissions = client.metadata(id).await.unwrap().permissions().unwrap();
                permissions.none = Access::Rx;
                if moto_sdk::sys::ProcessStaticPage::get().capabilities
                    & moto_sdk::sys::caps::CAP_INTERACTIVE
                    != 0
                {
                    permissions.interactive = Access::Rx;
                }
                client.set_all_permissions(id, permissions).await.unwrap();
            });
        }
        root
    });
    assert!(matches!(name, "true" | "cat"));
    root.join(name).to_str().unwrap().to_owned()
}
