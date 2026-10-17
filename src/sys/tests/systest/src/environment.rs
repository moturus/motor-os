//! Environment value limits and inheritance across process generations.

use std::process::Command;

const CHILD: &str = "environment-child";
const KEY: &str = "SYSTEST_ENV_ASCII";
const MAX_VALUE_LEN: usize = 32 * 1024 - 4;

fn value(len: usize) -> String {
    (0..len)
        .map(|idx| char::from(b'a' + (idx % 26) as u8))
        .collect()
}

fn max_values() -> [(&'static str, String); 3] {
    [
        (KEY, value(MAX_VALUE_LEN)),
        // Four UTF-8 bytes per repetition, including a two-byte character.
        ("SYSTEST_ENV_UTF8", "aéz".repeat(MAX_VALUE_LEN / 4)),
        ("SYSTEST_ENV_EMPTY", String::new()),
    ]
}

fn check_value(key: &str, expected: &str) {
    let actual = std::env::var(key).unwrap();
    assert_eq!(actual.len(), expected.len(), "{key}");
    assert!(actual == expected, "getenv corrupted {key}");
    let (_, enumerated) = std::env::vars().find(|(name, _)| name == key).unwrap();
    assert!(
        enumerated == expected,
        "environment enumeration corrupted {key}"
    );
}

fn command(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.arg(CHILD).arg(mode);
    command
}

fn check_success(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}: {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn run_command(args: &[String]) -> bool {
    match args.get(1).map(String::as_str) {
        Some("environment-tests") => {
            assert_eq!(args.len(), 2);
            run_all_tests();
            return true;
        }
        Some(CHILD) => assert_eq!(args.len(), 3),
        _ => return false,
    }

    let setenv: fn(&str, &str) = if args[2].starts_with("std-") {
        // This isolated helper sets its environment before starting any threads.
        |key, value| unsafe { std::env::set_var(key, value) }
    } else {
        moto_rt::process::setenv
    };

    match args[2].as_str() {
        "roundtrip" | "std-roundtrip" => {
            for len in [0, 4092, 4093, 4096, 32763, 32764] {
                let expected = value(len);
                setenv(KEY, &expected);
                check_value(KEY, &expected);
            }
            for (key, expected) in max_values() {
                setenv(key, &expected);
                check_value(key, &expected);
            }
        }
        "inherit" | "std-inherit" => {
            // Only this isolated helper mutates the environment used by descendants.
            for (key, expected) in max_values() {
                setenv(key, &expected);
            }
            check_success(&mut command("child"));
        }
        "child" | "grandchild" => {
            for (key, expected) in max_values() {
                check_value(key, &expected);
            }
            if args[2] == "child" {
                check_success(&mut command("grandchild"));
            }
        }
        "oversized" | "std-oversized" => {
            setenv(KEY, &value(MAX_VALUE_LEN + 1));
            panic!("oversized environment value was accepted");
        }
        mode => panic!("unknown environment test mode: {mode}"),
    }
    true
}

pub fn run_all_tests() {
    for mode in ["roundtrip", "std-roundtrip", "inherit", "std-inherit"] {
        check_success(&mut command(mode));
    }

    let mut explicit = command("grandchild");
    for (key, expected) in max_values() {
        explicit.env(key, expected);
    }
    check_success(&mut explicit);

    // A failure alone could be unrelated to the limit; require its exact assertion.
    for mode in ["oversized", "std-oversized"] {
        let output = command(mode).output().unwrap();
        assert!(!output.status.success(), "{mode}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("assertion failed: val.len() <= MAX_ENV_VAL_LEN"),
            "{mode}: {stderr}"
        );
    }
    println!("environment::run_all_tests PASS");
}
