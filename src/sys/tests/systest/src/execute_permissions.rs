use std::path::Path;
use std::process::Command;

fn assert_success(program: &Path, args: &[&str]) {
    assert_eq!(
        Some(0),
        Command::new(program).args(args).status().unwrap().code()
    );
}

fn assert_denied(program: &Path, args: &[&str]) {
    let error = Command::new(program).args(args).status().unwrap_err();
    assert_eq!(std::io::ErrorKind::PermissionDenied, error.kind());
    assert_eq!(Some(moto_rt::E_NOT_ALLOWED.into()), error.raw_os_error());
}

pub fn run_all_tests() {
    let root = crate::temp_path(&format!(
        "systest-execute-permissions-{}",
        moto_sys::ProcessStaticPage::get().pid
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();

    let interpreter = root.join("rush");
    std::fs::copy("/system/bin/rush", &interpreter).unwrap();

    let script = root.join("script");
    std::fs::write(
        &script,
        format!("#!{}\nexit 0\n", interpreter.to_str().unwrap()),
    )
    .unwrap();
    moto_rt::fs::set_perm(
        script.to_str().unwrap(),
        moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC,
    )
    .unwrap();

    assert_success(&interpreter, &["-c", "exit 0"]);
    assert_success(&script, &[]);

    let mut permissions = std::fs::metadata(&interpreter).unwrap().permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&interpreter, permissions).unwrap();

    assert_denied(&interpreter, &["-c", "exit 0"]);
    assert_denied(&script, &[]);

    std::fs::remove_dir_all(root).unwrap();
    println!("execute_permissions::run_all_tests PASS");
}
