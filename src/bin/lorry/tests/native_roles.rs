// Serial because redirect approval temporarily replaces this role's config.
#[cfg(not(target_os = "motor"))]
fn main() {}

#[cfg(target_os = "motor")]
mod support;

#[cfg(target_os = "motor")]
fn main() {
    if std::env::args().any(|argument| argument == "--url") {
        motor::redirect_curl();
        return;
    }
    motor::run_and_test_keep_caller_role();
    motor::new_shares_relative_paths_without_sharing_paths_outside_none();
    motor::acquisition_redirects_read_the_parent_terminal();
}

#[cfg(target_os = "motor")]
mod motor {
    use crate::support::Project;
    use moto_sdk::io::fs::{AccessPermissions as Access, FsClient, Role};
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;

    fn interactive() -> bool {
        moto_sdk::sys::ProcessStaticPage::get().capabilities & moto_sdk::sys::caps::CAP_INTERACTIVE
            != 0
    }

    fn access(path: &Path) -> Access {
        let path = fs::canonicalize(path).unwrap();
        moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
            let client = FsClient::connect().unwrap();
            let (id, _) = client.stat(path.to_str().unwrap()).await.unwrap();
            client
                .metadata(id)
                .await
                .unwrap()
                .access(Role::None)
                .unwrap()
        })
    }

    pub fn run_and_test_keep_caller_role() {
        let p = Project::new();
        p.package(".", "role-probe", "");
        p.write(
            "src/main.rs",
            r#"
fn check() {
    let path = format!("/user/tmp/lorry-role-probe-{}", std::process::id());
    let result = std::fs::File::create(&path);
    assert_eq!(result.is_ok(), std::env::var("LORRY_EXPECT_INTERACTIVE").unwrap() == "true");
    if let Ok(file) = result { drop(file); std::fs::remove_file(path).unwrap(); }
}
fn main() { check(); }
#[test] fn caller_role() { check(); }
"#,
        );
        p.lock(&[("role-probe", &[])]);
        p.admit();
        for arguments in [
            &["run", "--offline"][..],
            &["test", "--offline"],
            &["test", "--offline", "--bundle"],
        ] {
            let output = p
                .command(arguments)
                .env("LORRY_EXPECT_INTERACTIVE", interactive().to_string())
                .output()
                .unwrap();
            assert!(output.status.success(), "{arguments:?}: {output:?}");
        }
        for (path, expected) in [
            ("target/lorry/debug/role-probe", Access::Rx),
            ("target", Access::Rwx),
            ("target/lorry", Access::Rwx),
            ("Cargo.lock", Access::Rw),
            (".lorry/dependencies-v2.toml", Access::Rw),
        ] {
            assert_eq!(access(&p.root.join(path)), expected, "{path}");
        }
    }

    pub fn new_shares_relative_paths_without_sharing_paths_outside_none() {
        let p = Project::new();
        p.success(&["new", "relative"]);
        let root = p.root.join("relative");
        assert_eq!(access(&root), Access::Rwx);
        assert_eq!(access(&root.join("src/main.rs")), Access::Rw);
        let output = p
            .command(&["run", "--offline"])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        if interactive() {
            let before = access(Path::new("/user/tmp"));
            let outside = PathBuf::from("/none/../user/tmp").join(p.root.file_name().unwrap());
            p.success(&["new", outside.to_str().unwrap()]);
            assert_eq!(access(Path::new("/user/tmp")), before);
            assert_eq!(access(&outside), Access::Rx);
            assert_eq!(access(&outside.join("src/main.rs")), Access::R);
            let output = p
                .command(&["build", "--offline"])
                .current_dir(&outside)
                .output()
                .unwrap();
            assert!(!output.status.success());
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("cannot be built as None"),
                "{output:?}"
            );
            fs::remove_dir_all(outside).unwrap();
        }
    }

    pub fn redirect_curl() {
        let arguments = std::env::args().collect::<Vec<_>>();
        let option = |name: &str| {
            let position = arguments.iter().position(|value| value == name).unwrap();
            arguments[position + 1].as_str()
        };
        let url = option("--url");
        let nonce = option("--write-out")
            .split_once("LORRY-CURL-1 ")
            .unwrap()
            .1
            .lines()
            .next()
            .unwrap();
        let (status, redirect) = match url {
            "https://lorry-redirect.invalid/first" => (302, "https://lorry-redirect.invalid/final"),
            "https://lorry-redirect.invalid/final" => (404, ""),
            _ => (302, "https://lorry-redirect.invalid/first"),
        };
        eprint!(
            "\nLORRY-CURL-1 {nonce}\nstatus={status}\nurl={url}\nredirect={redirect}\nsize=0\nEND-LORRY-CURL-1 {nonce}\n"
        );
    }

    pub fn acquisition_redirects_read_the_parent_terminal() {
        fn replace(path: &Path, bytes: &[u8]) {
            let temporary = path.with_extension("native-role-test");
            fs::write(&temporary, bytes).unwrap();
            fs::rename(temporary, path).unwrap();
        }
        struct Restore(PathBuf, Vec<u8>);
        impl Drop for Restore {
            fn drop(&mut self) {
                replace(&self.0, &self.1);
            }
        }
        let config = PathBuf::from(if interactive() {
            "/user/cfg/lorry.toml"
        } else {
            "/none/cfg/lorry.toml"
        });
        let restore = Restore(config.clone(), fs::read(&config).unwrap());
        let original = String::from_utf8(restore.1.clone()).unwrap();
        assert!(
            !original.contains("[network]"),
            "native configuration already sets curl"
        );
        replace(
            &config,
            format!(
                "{original}\n[network]\ncurl = {:?}\n",
                std::env::current_exe().unwrap().to_str().unwrap()
            )
            .as_bytes(),
        );
        let p = Project::new();
        p.package(
            ".",
            "redirect-fixture",
            "[dependencies]\nlorry-redirect-probe=\"=1.0.0\"\n",
        );
        p.write("src/lib.rs", "");
        p.write("Cargo.lock", format!("version=4\n[[package]]\nname=\"redirect-fixture\"\nversion=\"1.0.0\"\ndependencies=[\"lorry-redirect-probe\"]\n[[package]]\nname=\"lorry-redirect-probe\"\nversion=\"1.0.0\"\nsource=\"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum=\"{}\"\n", "0".repeat(64)));
        for verb in ["fetch", "vendor"] {
            for (reply, expected) in [
                ("1\n", "unsupported HTTP status 404"),
                (
                    "3\n",
                    "redirect to site `lorry-redirect.invalid` was denied",
                ),
            ] {
                let mut child = p
                    .command(&[verb, "--locked"])
                    .env(moto_sdk::rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                let mut terminal = child.stdin.take().unwrap();
                terminal.write_all(reply.as_bytes()).unwrap();
                let output = child.wait_with_output().unwrap();
                drop(terminal);
                assert!(!output.status.success());
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(stderr.contains(expected), "{verb}: {stderr}");
                assert_eq!(
                    stderr.matches("Redirect decision [3]:").count(),
                    1,
                    "{verb}: {stderr}"
                );
            }
        }
    }
}
