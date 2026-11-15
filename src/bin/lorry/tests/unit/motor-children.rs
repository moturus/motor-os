use super::*;

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
    let start = Start {
        config: Config::default(),
        parent_pid: std::process::id().into(),
        // Claimed acquisition parent has network, but the actual worker does not.
        parent_caps: own_caps() | caps::CAP_NET,
        endpoint: "never-connect".into(),
        interactive: false,
    };
    let mut child = Process::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "motor_child::tests::private_worker_child",
            "--nocapture",
        ])
        .env("LORRY_PRIVATE_WORKER_TEST", "1")
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
fn private_worker_child() {
    if std::env::var_os("LORRY_PRIVATE_WORKER_TEST").is_some() {
        std::process::exit(child_main(vec!["fetch".into()]));
    }
}
