#[path = "../src/output.rs"]
mod output;

#[test]
fn fragmented_address_requires_its_newline() {
    let prefix = "Serving HTTP on http://";
    let log = format!("Listening for shutdown on tcp://127.0.0.1:1234\n{prefix}127.0.0.1:5678/\n");
    // Every intermediate snapshot, including a complete-looking port, must wait.
    for end in 0..log.len() {
        assert_eq!(output::complete_output(&log[..end], prefix), None);
    }
    assert_eq!(output::complete_output(&log, prefix), Some(log.as_str()));
}

#[test]
fn complete_snapshot_omits_a_partial_following_line() {
    assert_eq!(
        output::complete_output("out\nunfinished", "out\n"),
        Some("out\n")
    );
    assert_eq!(
        output::complete_output("out\nunfinished", "unfinished"),
        None
    );
    assert_eq!(output::complete_output("out\n", "missing"), None);
}

#[test]
fn exact_stderr_accepts_only_complete_known_runtime_records_on_debug() {
    let fs = "  7:123: DEBUG lib/rt.vdso/src/rt_fs.rs:286: AsyncFsClient created.\n";
    let spawn = " 19:456: DEBUG lib/rt.vdso/src/rt_process.rs:585: spawn /user/bin/dev/wasmi\n";
    let actual = format!("{fs}first\n{spawn}second");
    assert!(output::stderr_matches(&actual, "first\nsecond", true));
    assert!(!output::stderr_matches(&actual, "first\nsecond", false));
    assert!(output::stderr_matches(&actual, &actual, false));
    assert!(output::stderr_matches(fs, fs, true));
    assert!(output::stderr_matches(
        &fs.replace("  7:", "1000:"),
        "",
        true
    ));
    assert!(!output::stderr_matches(fs, "missing\n", true));
    for line in [
        fs.trim_end().to_owned(),
        fs.replace("rt_fs.rs", "command.rs"),
        fs.replace("286:", "unknown:"),
        fs.replace("286:", "0286:"),
        fs.replace("  7:", "7:"),
        fs.replace("  7:", "007:"),
        fs.replace("DEBUG", "INFO"),
        fs.replace("123:", "12:"),
        fs.replace("created.", "failed."),
        spawn.replace("wasmi", "other"),
        "\n".to_owned(),
    ] {
        assert!(!output::stderr_matches(&line, "", true), "{line:?}");
        assert!(output::stderr_matches(&line, &line, true));
    }
}

#[cfg(target_os = "motor")]
#[test]
fn command_debug_lines_survive_capture_and_failure() {
    let parent = std::env::temp_dir();
    let sources = parent.join(format!("wasm-source-{}", std::process::id()));
    std::fs::write(&sources, "test fixture").unwrap();
    let mut suite = wasm_smoke_suite::Suite::new_in(
        "stderr-capture",
        sources.to_str().unwrap(),
        &parent,
        std::io::sink(),
    )
    .unwrap();
    std::fs::remove_file(sources).unwrap();
    let line = "123:456: DEBUG app.rs:19: command diagnostic";
    let command = format!("echo '{line}' >&2");
    let (_, stderr) = suite.command("success", &command, 0).unwrap();
    assert!(stderr.lines().any(|s| s == line), "{stderr}");
    let error = suite.command("failure", &command, 1).unwrap_err();
    assert!(error.to_string().lines().any(|s| s == line), "{error}");
    suite.finish().unwrap();
}
