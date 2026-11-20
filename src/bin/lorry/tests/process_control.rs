#[cfg(target_os = "motor")]
#[path = "control/cancel.rs"]
mod cancel;
#[path = "control/recovery.rs"]
mod recovery;
#[path = "control/scheduling.rs"]
mod scheduling;
mod support;

fn main() {
    if std::env::var_os("LORRY_SCHEDULING_ROOT").is_some() {
        scheduling::compiler();
        return;
    }
    if std::env::var_os("LORRY_RECOVERY_PROBE_ROOT").is_some() {
        recovery::run(std::env::args_os().collect());
        return;
    }
    #[cfg(target_os = "motor")]
    if [
        "LORRY_HOLD_CHILD_ROOT",
        "LORRY_HOLD_ROOT",
        "LORRY_CANCEL_ROOT",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some())
    {
        cancel::run(std::env::args_os().collect()).unwrap();
        return;
    }
    let p = support::Project::new();
    // This serial harness and its compiler wrappers share one isolated config.
    // All environment changes precede the first child or background thread.
    unsafe {
        #[cfg(not(target_os = "motor"))]
        std::env::set_var("HOME", p.root.join("home"));
        std::env::set_var("RUSTC", p.rustc());
    }
    let arguments = |directory: &str| {
        vec![
            std::env::current_exe().unwrap().into_os_string(),
            env!("CARGO_BIN_EXE_lorry").into(),
            p.root.join(directory).into_os_string(),
        ]
    };
    recovery::run(arguments("recovery"));
    scheduling::run();
    #[cfg(target_os = "motor")]
    cancel::run(arguments("cancellation")).unwrap();

    p.package(".", "nested-lock", "");
    p.lock(&[("nested-lock", &[])]);
    p.write(
        "src/main.rs",
        r#"
fn main() {
    assert!(std::process::Command::new(std::env::var_os("LORRY_NESTED").unwrap())
        .args(["build", "--locked", "--offline"]).status().unwrap().success());
}
"#,
    );
    p.write(
        "tests/nested.rs",
        r#"
#[test] fn nested_build() {
    assert!(std::process::Command::new(std::env::var_os("LORRY_NESTED").unwrap())
        .args(["build", "--locked", "--offline"]).status().unwrap().success());
}
"#,
    );
    p.admit();
    for arguments in [
        &["run", "--offline"][..],
        &["test", "--offline", "--test", "nested"],
    ] {
        let mut child = p
            .command(arguments)
            .env("LORRY_NESTED", env!("CARGO_BIN_EXE_lorry"))
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("nested build blocked on its parent's artifact lock");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    assert!(p.root.join("target/.lorry-artifacts.lock").exists());
    p.success(&["clean"]);
    assert!(p.root.join("target/.lorry-artifacts.lock").exists());
    assert!(!p.root.join("target/lorry").exists());
}
