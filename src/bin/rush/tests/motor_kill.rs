#![cfg(target_os = "motor")]

use std::process::Command;

const RUSH: &str = env!("CARGO_BIN_EXE_rush");

#[test]
fn kill_resolves_to_the_external_wrapper() {
    let output = Command::new(RUSH)
        .args(["-c", "type kill; command -v kill"])
        .env("PATH", "/user/bin")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "kill is /user/bin/kill\n/user/bin/kill\n"
    );
}

#[test]
fn kill_uses_path_and_preserves_arguments() {
    let root = std::env::temp_dir().join(format!("rush-kill-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let wrapper = root.join("kill");
    std::fs::write(
        &wrapper,
        "#!/user/bin/rush\nprintf '<%s>\\n' \"$@\"\nexit 23\n",
    )
    .unwrap();
    // Change only the caller's permissions so this also runs with None authority.
    moto_rt::fs::set_perm(
        wrapper.to_str().unwrap(),
        moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC,
    )
    .unwrap();
    for prefix in ["", "command ", "exec "] {
        let output = Command::new(RUSH)
            .args(["-c", &format!("{prefix}kill 'one two' three")])
            .env("PATH", &root)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(23), "{prefix}: {output:?}");
        assert_eq!(output.stdout, b"<one two>\n<three>\n");
    }
    std::fs::remove_dir_all(root).unwrap();
}
