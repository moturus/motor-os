use std::process::Command;

#[test]
fn ssh_help_succeeds_without_a_connection() {
    for option in ["--help", "-h"] {
        let output = Command::new(env!("CARGO_BIN_EXE_ssh"))
            .arg(option)
            .output()
            .unwrap();
        assert!(output.status.success(), "{option}: {output:?}");
        assert!(output.stderr.is_empty(), "{option}: {output:?}");
        let help = String::from_utf8(output.stdout).unwrap();
        for expected in [
            "Usage: ssh",
            "[command [argument ...]]",
            "-o Key=Value",
            "No client config file is read",
            "/user/cfg/ssh/id_ed25519",
            "/user/cfg/ssh/known_hosts",
            "ssh motor@host",
        ] {
            assert!(help.contains(expected), "missing {expected}: {help}");
        }
    }
}
