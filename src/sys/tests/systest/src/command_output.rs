use std::io::{Read, Write};

const CHILD_ARGUMENT: &str = "command-output-child";
const CHILD_EXIT_CODE: i32 = 23;
const OUTPUT_BYTES: usize = 96 * 1024;

pub fn is_child(args: &[String]) -> bool {
    args.get(1).map(String::as_str) == Some(CHILD_ARGUMENT)
}

pub fn run_child(args: &[String]) -> ! {
    assert_eq!(args.len(), 3);
    assert_eq!(args[1], CHILD_ARGUMENT);
    assert_eq!(args[2], "two words");
    assert_eq!(std::env::var("COMMAND_OUTPUT_TEST").unwrap(), "present");

    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    assert!(input.is_empty());

    let stdout = vec![b'o'; OUTPUT_BYTES];
    let stderr = vec![b'e'; OUTPUT_BYTES];
    std::io::stdout().write_all(&stdout).unwrap();
    std::io::stdout().flush().unwrap();
    std::io::stderr().write_all(&stderr).unwrap();
    std::io::stderr().flush().unwrap();
    std::process::exit(CHILD_EXIT_CODE)
}

pub fn run_test() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg(CHILD_ARGUMENT)
        .arg("two words")
        .env("COMMAND_OUTPUT_TEST", "present")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(CHILD_EXIT_CODE));
    assert_eq!(output.stdout, vec![b'o'; OUTPUT_BYTES]);
    assert_eq!(output.stderr, vec![b'e'; OUTPUT_BYTES]);
    println!("command_output::run_test PASS");
}
