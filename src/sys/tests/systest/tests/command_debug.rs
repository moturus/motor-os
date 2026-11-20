use std::fmt;
use std::process::Command;

#[test]
fn command_arguments_are_visible_and_escaped() {
    let mut command = Command::new("/path with spaces/工具");
    command.args(["", "a\"b", "line\nnext", "back\\slash"]);
    assert_eq!(
        format!("{command:?}"),
        "\"/path with spaces/工具\" \"\" \"a\\\"b\" \"line\\nnext\" \"back\\\\slash\""
    );
}

#[test]
fn command_cwd_and_explicit_environment_changes_are_visible() {
    let mut command = Command::new("tool");
    command
        .current_dir("/some path")
        .env("SET", "two words")
        .env_remove("REMOVE");
    assert_eq!(
        format!("{command:?}"),
        "cd \"/some path\" && env -u REMOVE SET=\"two words\" \"tool\""
    );
    command.env_clear().env("SET", "value");
    assert_eq!(
        format!("{command:?}"),
        "cd \"/some path\" && env -i SET=\"value\" \"tool\""
    );
}

#[test]
fn alternate_command_format_has_structured_fields() {
    let mut command = Command::new("tool");
    command.arg("argument");
    let plain = format!("{command:#?}");
    assert!(plain.starts_with("Command {\n"));
    assert!(plain.contains("program: \"tool\""));
    assert!(plain.contains("args: [\n"));
    assert!(plain.contains("\"argument\""));
    assert!(!plain.contains("env_clear:"));
    command.env_clear().current_dir("/project");
    let changed = format!("{command:#?}");
    assert!(changed.contains("env_clear: true"));
    assert!(changed.contains("cwd: \"/project\""));
}

#[test]
fn command_formatting_propagates_output_errors() {
    struct Reject;
    impl fmt::Write for Reject {
        fn write_str(&mut self, _: &str) -> fmt::Result {
            Err(fmt::Error)
        }
    }
    let command = Command::new("tool");
    assert!(fmt::write(&mut Reject, format_args!("{command:?}")).is_err());
    assert!(fmt::write(&mut Reject, format_args!("{command:#?}")).is_err());
}
