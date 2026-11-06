use std::process::Command;

#[allow(dead_code)]
#[path = "../../../tools/sysbox/src/commands/findmnt.rs"]
mod command;

fn child(path: &str) -> Command {
    let mut command = Command::new(path);
    command.env(
        moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
        format!("0x{:x}", moto_sys::ProcessStaticPage::get().capabilities),
    );
    command
}

pub fn run_test() {
    let run = |path: &str, args: &[&str]| {
        let output = child(path).args(args).output().unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    let table = run("/system/bin/sysbox", &["findmnt"]);
    let identity = |text: &str| {
        text.lines()
            .skip(1)
            .map(|line| {
                let fields: Vec<_> = line.split_ascii_whitespace().collect();
                assert_eq!(fields.len(), 7, "{line}");
                assert_eq!(fields[3], "rw");
                assert!(fields[4].parse::<u64>().is_ok());
                assert!(fields[5].parse::<u64>().is_ok());
                fields[..4].join(" ")
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        table.lines().next(),
        Some("ID TARGET FSTYPE STATE USED CAP ENTRIES")
    );
    let expected = vec![
        "0 / motor-fs rw",
        "1 /none/tmp memfs rw",
        "2 /system/tmp memfs rw",
        "3 /user/tmp memfs rw",
    ];
    assert_eq!(identity(&table), expected);
    // Usage is sampled and can change between invocations.
    for wrapper in ["/system/bin/findmnt", "/system/bin/df"] {
        assert_eq!(identity(&run(wrapper, &[])), expected);
    }
    for help in ["-h", "--help"] {
        assert!(run("/system/bin/sysbox", &["findmnt", help]).contains("usage: findmnt"));
    }
    for args in [&["findmnt", "bad"][..], &["findmnt", "--help", "bad"]] {
        let output = child("/system/bin/sysbox").args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    use moto_sdk::io::fs::{MountInfo, MountKind};
    let mut mounts = [
        MountInfo {
            id: 7,
            kind: MountKind::MotorFs,
            path: "/a b\n\t\x1b雪\\".into(),
            corrupted: true,
            read_only: true,
            source: None,
            used: None,
            cap: None,
            entries: None,
        },
        MountInfo {
            id: 0,
            kind: MountKind::MotorFs,
            path: "/".into(),
            corrupted: false,
            read_only: true,
            source: None,
            used: Some(0),
            cap: Some(u64::MAX),
            entries: None,
        },
    ];
    let mut output = Vec::new();
    command::write_table(&mut output, &mut mounts).unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        concat!(
            "ID TARGET FSTYPE STATE USED CAP ENTRIES\n",
            "0 / motor-fs ro 0 18446744073709551615 -\n",
            "7 /a\\x20b\\n\\t\\x1b\\xe9\\x9b\\xaa\\\\ motor-fs quarantined - - -\n"
        )
    );
    println!("sysbox_findmnt PASS");
}
