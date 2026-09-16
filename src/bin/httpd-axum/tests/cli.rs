use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    let binary = std::env::var_os("HTTPD_AXUM_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_httpd-axum").into());
    Command::new(binary).args(args).output().unwrap()
}

fn main() {
    assert!(run(&["--help"]).status.success());
    for value in ["0", "-1", "4294967296", "invalid"] {
        let output = run(&[
            "-a",
            "192.0.2.1:1",
            "-d",
            "/",
            "--max-active-connections",
            value,
        ]);
        assert_eq!(output.status.code(), Some(2), "{value}: {output:?}");
    }
    for (present, missing) in [("--ssl-cert", "--ssl-key"), ("--ssl-key", "--ssl-cert")] {
        // Use an unavailable address too: paired TLS options must fail before bind
        // or filesystem access, without attempting to start a plaintext server.
        let output = run(&["-a", "192.0.2.1:1", "-d", "/", present, "missing.pem"]);
        assert_eq!(output.status.code(), Some(2), "{present}: {:?}", output);
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains(missing), "{error}");
        assert!(!error.contains("panicked"), "{error}");
    }
    println!("httpd-axum CLI tests passed");
}
