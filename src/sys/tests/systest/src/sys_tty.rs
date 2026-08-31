pub fn run_all_tests() {
    let output = std::process::Command::new("/system/services/sys-tty")
        .arg("--self-test")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "sys-tty self-test failed: status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        b"sys-tty ANSI scanner self-test PASS\nsys-tty config self-test PASS\nsys-tty forwarder self-test PASS\nsys-tty sanitizer self-test PASS\nsys-tty writer self-test PASS\nsys-tty kernel-log self-test PASS\n"
    );
    assert!(output.stderr.is_empty());

    println!("sys_tty::run_all_tests PASS");
}
