use super::*;

#[test]
fn acquisition_redirects_read_the_parent_terminal() {
    use crate::atomic::AtomicFile;
    use std::fs;
    use std::path::PathBuf;

    fn replace(path: &Path, bytes: &[u8]) {
        let mut file = AtomicFile::new(path).unwrap();
        file.write_all(bytes).unwrap();
        file.commit().unwrap();
    }
    struct RestoreConfig(PathBuf, Vec<u8>);
    impl Drop for RestoreConfig {
        fn drop(&mut self) {
            replace(&self.0, &self.1);
        }
    }

    let lorry = std::env::var_os("LORRY_NATIVE_LORRY").unwrap();
    let curl = std::env::var("LORRY_REDIRECT_CURL").unwrap();
    let config = crate::role::Role::current().config_file();
    let restore = RestoreConfig(config.clone(), fs::read(&config).unwrap());
    let original = String::from_utf8(restore.1.clone()).unwrap();
    assert!(
        !original.contains("[network]"),
        "native fixture already configures curl"
    );
    replace(
        &config,
        format!("{original}\n[network]\ncurl = {curl:?}\n").as_bytes(),
    );
    let root = PathBuf::from(std::env::var_os("LORRY_MODE_WORKSPACE").unwrap())
        .join(format!("redirects-{}", std::process::id()));
    crate::fs_check::create_dir_all(&root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "").unwrap();
    fs::write(root.join("Cargo.toml"), "[package]\nname = \"redirect-fixture\"\nversion = \"0.1.0\"\n[dependencies]\nlorry-redirect-probe = \"=1.0.0\"\n").unwrap();
    fs::write(root.join("Cargo.lock"), format!(
        "version = 4\n[[package]]\nname = \"redirect-fixture\"\nversion = \"0.1.0\"\ndependencies = [\"lorry-redirect-probe\"]\n[[package]]\nname = \"lorry-redirect-probe\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n", "0".repeat(64)
    )).unwrap();
    for verb in ["fetch", "vendor"] {
        for (reply, expected) in [
            ("1\n", "unsupported HTTP status 404"),
            (
                "3\n",
                "redirect to site `lorry-redirect.invalid` was denied",
            ),
        ] {
            let mut child = Process::new(&lorry)
                .args([verb, "--locked"])
                .current_dir(&root)
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
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{verb}: {stderr}");
            assert!(stderr.contains(expected), "{verb}: {stderr}");
            assert_eq!(
                stderr.matches("Redirect decision [3]:").count(),
                1,
                "{verb}: {stderr}"
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn command_masks_only_retain_authorized_capabilities() {
    let own = caps::CAP_INTERACTIVE
        | caps::CAP_SPAWN
        | caps::CAP_FS_WRITE
        | caps::CAP_NET
        | caps::CAP_SPAWN_DETACHED;
    for command in [
        "build", "check", "clippy", "metadata", "tree", "review", "run", "test",
    ] {
        let cli = Cli::parse(vec![command.into()]).unwrap();
        assert_eq!(
            command_caps(&cli.command, own),
            Some(caps::CAP_SPAWN | caps::CAP_FS_WRITE)
        );
        assert_eq!(
            command_caps(&cli.command, caps::CAP_SPAWN),
            Some(caps::CAP_SPAWN)
        );
    }
    for command in ["fetch", "vendor"] {
        for offline in [false, true] {
            let mut args = vec![command.into()];
            if offline {
                args.push("--offline".into());
            }
            let cli = Cli::parse(args).unwrap();
            let expected =
                own & !caps::CAP_SPAWN_DETACHED & if offline { !caps::CAP_NET } else { u64::MAX };
            assert_eq!(command_caps(&cli.command, own), Some(expected));
        }
    }
}

#[test]
fn private_worker_refuses_a_wrong_mask_before_connecting() {
    let lorry = std::env::var_os("LORRY_NATIVE_LORRY").expect("native driver supplies Lorry");
    let start = Start {
        config: Config::default(),
        parent_pid: std::process::id().into(),
        // Claimed acquisition parent has network, but the actual worker does not.
        parent_caps: own_caps() | caps::CAP_NET,
        endpoint: "never-connect".into(),
        interactive: false,
    };
    let mut child = Process::new(lorry)
        .args([CHILD_ARGUMENT, "fetch"])
        .env("MOTOR_OS_CAPS", format!("{:#x}", build_caps(own_caps())))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&start).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("worker capabilities do not match"));
}

#[test]
fn run_and_test_keep_caller_role() {
    let lorry = std::env::var_os("LORRY_NATIVE_LORRY").expect("native driver supplies Lorry");
    let root = std::env::var_os("LORRY_MODE_WORKSPACE").expect("native driver supplies workspace");
    for arguments in [
        vec!["vendor", "--locked", "--offline", "--accept-all"],
        vec!["run", "--offline"],
        vec!["test", "--offline"],
        vec!["test", "--offline", "--bundle"],
    ] {
        let output = Process::new(&lorry)
            .args(&arguments)
            .current_dir(&root)
            // MOTOR_OS_CAPS is consumed at spawn; probe actual file authority.
            .env(
                "LORRY_EXPECT_INTERACTIVE",
                (own_caps() & caps::CAP_INTERACTIVE != 0).to_string(),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
