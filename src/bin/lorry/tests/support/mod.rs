#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Project {
    pub root: PathBuf,
    rustc: PathBuf,
}

impl Project {
    pub fn rustc(&self) -> &Path {
        &self.rustc
    }
    pub fn new() -> Self {
        static NEXT_PROJECT: AtomicU64 = AtomicU64::new(0);
        let scratch = if cfg!(target_os = "motor") {
            PathBuf::from("/none/tmp")
        } else {
            std::env::temp_dir()
        };
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Parallel tests can read the same wall-clock time.
        let sequence = NEXT_PROJECT.fetch_add(1, Ordering::Relaxed);
        let root = scratch.join(format!(
            "lorry-test-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        share(&root, true);
        let output = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
            .args(["--print", "sysroot"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let rustc = Path::new(String::from_utf8(output.stdout).unwrap().trim()).join("bin/rustc");
        let project = Self { root, rustc };
        #[cfg(not(target_os = "motor"))]
        project.write(
            "home/.config/lorry/lorry.toml",
            "config-version = 1\nuse-cargo-registry = false\n[policy]\ndefault = \"allow\"\n",
        );
        project
    }

    pub fn write(&self, relative: &str, contents: impl AsRef<[u8]>) {
        let path = self.root.join(relative);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        for directory in parent
            .ancestors()
            .take_while(|path| path.starts_with(&self.root))
        {
            share(directory, true);
        }
        fs::write(&path, contents).unwrap();
        share(&path, false);
    }

    pub fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lorry"));
        command
            .current_dir(&self.root)
            .args(arguments)
            .env("RUSTC", &self.rustc);
        #[cfg(not(target_os = "motor"))]
        command.env("HOME", self.root.join("home"));
        command
    }

    pub fn run(&self, arguments: &[&str]) -> Output {
        self.command(arguments).output().unwrap()
    }

    pub fn success(&self, arguments: &[&str]) -> Output {
        let output = self.run(arguments);
        assert!(output.status.success(), "{arguments:?}: {output:?}");
        output
    }

    pub fn admit(&self) {
        self.success(&[
            "vendor",
            "--locked",
            "--offline",
            "--accept-all",
            "--workspace",
            "--all-features",
        ]);
    }

    pub fn lock(&self, packages: &[(&str, &[&str])]) {
        let mut lock = "version = 4\n".to_owned();
        for (name, dependencies) in packages {
            lock.push_str(&format!("[[package]]\nname = {name:?}\nversion = \"1.0.0\"\ndependencies = {dependencies:?}\n"));
        }
        self.write("Cargo.lock", lock);
    }

    pub fn package(&self, directory: &str, name: &str, extra: &str) {
        self.write(
            &format!("{directory}/Cargo.toml"),
            format!("[package]\nname = {name:?}\nversion = \"1.0.0\"\nedition = \"2024\"\n{extra}"),
        );
    }

    pub fn fails(&self, arguments: &[&str], diagnostic: &str) -> Output {
        let output = self.run(arguments);
        assert!(!output.status.success(), "{arguments:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(diagnostic),
            "{arguments:?}: {output:?}"
        );
        output
    }
}

pub fn artifacts(output: &Output) -> Vec<serde_json::Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event["reason"] == "compiler-artifact")
        .collect()
}

impl Drop for Project {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
}

pub fn share(_path: &Path, _directory: bool) {
    #[cfg(target_os = "motor")]
    if moto_sdk::sys::ProcessStaticPage::get().capabilities & moto_sdk::sys::caps::CAP_INTERACTIVE
        != 0
    {
        use moto_sdk::io::fs::{AccessPermissions, FsClient};
        let path = fs::canonicalize(_path).unwrap();
        moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
            let client = FsClient::connect().unwrap();
            let (id, _) = client
                .stat(path.to_str().unwrap())
                .await
                .unwrap_or_else(|error| panic!("cannot share {_path:?}: {error:?}"));
            let mut permissions = client.metadata(id).await.unwrap().permissions().unwrap();
            permissions.none = if _directory {
                AccessPermissions::Rwx
            } else {
                AccessPermissions::Rw
            };
            client.set_all_permissions(id, permissions).await.unwrap();
        });
    }
}

pub fn executable_permissions(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(target_os = "motor")]
    {
        use moto_sdk::io::fs::{AccessPermissions, FsClient};
        moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
            let client = FsClient::connect().unwrap();
            let (id, _) = client.stat(path.to_str().unwrap()).await.unwrap();
            if moto_sdk::sys::ProcessStaticPage::get().capabilities
                & moto_sdk::sys::caps::CAP_INTERACTIVE
                != 0
            {
                let mut permissions = client.metadata(id).await.unwrap().permissions().unwrap();
                permissions.interactive = AccessPermissions::Rx;
                permissions.none = AccessPermissions::Rx;
                client.set_all_permissions(id, permissions).await.unwrap();
            } else {
                client
                    .set_permissions(id, AccessPermissions::Rx)
                    .await
                    .unwrap();
            }
        });
    }
    Ok(())
}
