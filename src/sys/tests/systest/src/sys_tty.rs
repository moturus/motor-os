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
    assert!(
        output.stderr.is_empty(),
        "unexpected sys-tty self-test stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The native pipe case spawns a child, which emits runtime diagnostics in
    // debug builds. Keep those visible separately from the quiet self-tests.
    let output = std::process::Command::new("/system/services/sys-tty")
        .arg("--pipe-self-test")
        .stderr(std::process::Stdio::inherit())
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"sys-tty pipe self-test PASS\n");

    println!("sys_tty::run_all_tests PASS");
}

/// Fails the way a command-line tool does: an error chain written to unbuffered
/// stderr in small pieces, then an immediate exit. test-system-tty.sh runs this
/// on the console and checks that the shell's next prompt follows the text.
pub fn stderr_burst(id: usize, lines: usize) -> ! {
    use std::io::{Read, Write};

    assert!((1..=1024).contains(&lines));
    // Let the host observe the complete command echo before releasing the
    // burst. All output after this handshake is the error text and next prompt.
    println!("stderr-burst {id} ready");
    let mut release = [0];
    std::io::stdin().read_exact(&mut release).unwrap();
    assert_eq!(release, *b"!");
    let mut stderr = std::io::stderr().lock();
    for line in 1..=lines {
        for piece in ["  caused", " by: ", "stderr-burst "] {
            stderr.write_all(piece.as_bytes()).unwrap();
        }
        writeln!(stderr, "{id} line {line} of {lines} stays whole").unwrap();
    }
    std::process::exit(1)
}
