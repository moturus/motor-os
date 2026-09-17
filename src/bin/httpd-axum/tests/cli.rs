use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    let binary = std::env::var_os("HTTPD_AXUM_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_httpd-axum").into());
    Command::new(binary).args(args).output().unwrap()
}

fn main() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8(help.stdout)
        .unwrap()
        .contains("--no-request-log"));
    check_redirect_options();
    for flag in [
        "--max-active-connections",
        "--max-header-deadline-sec",
        "--cache-timeout-sec",
        "--cache-size-mb",
    ] {
        for value in ["0", "-1", "4294967296", "invalid"] {
            let output = run(&["-a", "192.0.2.1:1", "-d", "/", flag, value]);
            assert_eq!(output.status.code(), Some(2), "{value}: {output:?}");
        }
    }
    assert_eq!(
        run(&["-a", "192.0.2.1:1", "-d", "/", "--cache=invalid"])
            .status
            .code(),
        Some(2)
    );
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

fn check_redirect_options() {
    for url in [
        "",
        "http://example.com/",
        "/relative",
        "//example.com/",
        "https:///path",
        "https://user:password@example.com/",
        "https://example.com:bad/",
        "https://example.com:65536/",
        "https://example.com:0/",
        "https://example.com:/",
        "https://[invalid]/",
        "https://example.com/with space",
        "https://example.com/\\evil",
        "https://example.com/%zz",
        "https://example.com/%",
        "https://example.com/\r\nInjected: yes",
    ] {
        let output = run(&[
            "-a",
            "192.0.2.1:443",
            "-d",
            "/",
            "--ssl-cert",
            "missing.pem",
            "--ssl-key",
            "missing.pem",
            "--http-redirect-url",
            url,
        ]);
        assert_eq!(output.status.code(), Some(2), "{url:?}: {output:?}");
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("--http-redirect-url"));
    }
    let missing_tls = run(&[
        "-a",
        "192.0.2.1:443",
        "-d",
        "/",
        "--http-redirect-url",
        "https://example.com/",
    ]);
    assert_eq!(missing_tls.status.code(), Some(2), "{missing_tls:?}");
    assert!(String::from_utf8(missing_tls.stderr)
        .unwrap()
        .contains("--ssl-cert"));
    let wrong_port = run(&[
        "-a",
        "192.0.2.1:8443",
        "-d",
        "/",
        "--ssl-cert",
        "missing.pem",
        "--ssl-key",
        "missing.pem",
        "--http-redirect-url",
        "https://example.com/",
    ]);
    assert_eq!(wrong_port.status.code(), Some(2), "{wrong_port:?}");
    assert!(String::from_utf8(wrong_port.stderr)
        .unwrap()
        .contains("port 443"));
}
