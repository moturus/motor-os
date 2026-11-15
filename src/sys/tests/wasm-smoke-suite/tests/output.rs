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
