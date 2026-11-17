use std::process::Command;

#[allow(dead_code)]
#[path = "../../src/commands/findmnt.rs"]
mod command;

fn child(path: &str) -> Command {
    let mut command = Command::new(path);
    command.env(
        moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
        format!("0x{:x}", moto_sys::ProcessStaticPage::get().capabilities),
    );
    command
}

fn assert_aligned(table: &str) {
    let mut columns = Vec::new();
    for (row, line) in table.lines().enumerate() {
        assert!(line.is_ascii());
        assert_eq!(line.trim_end(), line);
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        assert_eq!(fields.len(), 8, "{line}");
        let mut offset = 0;
        let positions: Vec<_> = fields
            .iter()
            .enumerate()
            .map(|(column, field)| {
                let start = offset + line[offset..].find(field).unwrap();
                offset = start + field.len();
                if matches!(column, 0 | 5..=7) {
                    offset
                } else {
                    start
                }
            })
            .collect();
        if row == 0 {
            columns = positions;
        } else {
            assert_eq!(positions, columns, "{table}");
        }
    }
}

pub fn run_test(sysbox: &str) {
    let run = |path: &str, args: &[&str]| {
        let output = child(path).args(args).output().unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    let table = run(sysbox, &["findmnt"]);
    let identity = |text: &str, human_friendly: bool| {
        assert_aligned(text);
        text.lines()
            .skip(1)
            .map(|line| {
                let fields: Vec<_> = line.split_ascii_whitespace().collect();
                assert_eq!(fields.len(), 8, "{line}");
                assert_eq!(fields[4], "rw");
                if !human_friendly {
                    assert!(fields[5].parse::<u64>().is_ok());
                    assert!(fields[6].parse::<u64>().is_ok());
                }
                fields[..5].join(" ")
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        table
            .lines()
            .next()
            .unwrap()
            .split_ascii_whitespace()
            .collect::<Vec<_>>(),
        ["ID", "TARGET", "SOURCE", "FSTYPE", "STATE", "USED", "CAP", "ENTRIES"]
    );
    let expected = vec![
        "0 / virtio0p3 motor-fs rw",
        "1 /none/tmp - memfs rw",
        "2 /system/tmp - memfs rw",
        "3 /user/tmp - memfs rw",
    ];
    assert_eq!(identity(&table, false), expected);
    let capacities: Vec<_> = table
        .lines()
        .skip(1)
        .map(|line| {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            assert!(fields[5].parse::<u64>().is_ok());
            crate::format_bytes(fields[6].parse().unwrap())
        })
        .collect();
    // Usage is sampled and can change between invocations.
    for (path, args) in [
        (sysbox, vec!["findmnt"]),
        ("/user/bin/findmnt", vec![]),
        ("/user/bin/df", vec![]),
    ] {
        assert_eq!(identity(&run(path, &args), false), expected);
        let mut args = args;
        args.push("-h");
        let human = run(path, &args);
        assert_eq!(identity(&human, true), expected);
        assert_eq!(
            human
                .lines()
                .skip(1)
                .map(|line| line.split_ascii_whitespace().nth(6).unwrap().to_owned())
                .collect::<Vec<_>>(),
            capacities
        );
        *args.last_mut().unwrap() = "--help";
        assert!(run(path, &args).contains("usage: findmnt [-h]"));
    }
    for args in [
        &["findmnt", "bad"][..],
        &["findmnt", "--help", "bad"],
        &["findmnt", "-h", "bad"],
        &["findmnt", "-x"],
    ] {
        let output = child(sysbox).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    use moto_sdk::io::fs::{MountBlockSource, MountInfo, MountKind};
    let mut mounts = [
        MountInfo {
            id: 700,
            kind: MountKind::MotorFs,
            path: "/a b\n\t\x1b雪\\".into(),
            corrupted: true,
            read_only: true,
            source: Some(MountBlockSource {
                device: u32::MAX,
                partition: Some(4),
            }),
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
            source: Some(MountBlockSource {
                device: 2,
                partition: None,
            }),
            used: Some(0),
            cap: Some(u64::MAX),
            entries: None,
        },
    ];
    let mut output = Vec::new();
    command::write_table(&mut output, &mut mounts, false).unwrap();
    let output = String::from_utf8(output).unwrap();
    assert_aligned(&output);
    assert_eq!(
        output.split_ascii_whitespace().collect::<Vec<_>>(),
        concat!(
            "ID TARGET SOURCE FSTYPE STATE USED CAP ENTRIES\n",
            "0 / virtio2 motor-fs ro 0 18446744073709551615 -\n",
            "700 /a\\x20b\\n\\t\\x1b\\xe9\\x9b\\xaa\\\\ virtio4294967295p4 motor-fs quarantined - - -\n"
        ).split_ascii_whitespace().collect::<Vec<_>>()
    );

    for (bytes, expected) in [
        (0, "0"),
        (1, "1"),
        (1023, "1023"),
        (1024, "1.00K"),
        (1536, "1.50K"),
        (1 << 20, "1.00M"),
        (3 << 19, "1.50M"),
        (1 << 30, "1.00G"),
        (3 << 29, "1.50G"),
        (1 << 40, "1.00T"),
        (u64::MAX, "16777216.00T"),
    ] {
        mounts[0].used = Some(bytes);
        mounts[0].cap = Some(bytes);
        mounts[0].entries = Some(1024);
        let mut output = Vec::new();
        command::write_table(&mut output, &mut mounts, true).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert_aligned(&output);
        let rows: Vec<Vec<_>> = output
            .lines()
            .skip(1)
            .map(|line| line.split_ascii_whitespace().collect())
            .collect();
        assert_eq!(
            rows[0],
            ["0", "/", "virtio2", "motor-fs", "ro", expected, expected, "1024"]
        );
        assert_eq!(
            rows[1],
            [
                "700",
                "/a\\x20b\\n\\t\\x1b\\xe9\\x9b\\xaa\\\\",
                "virtio4294967295p4",
                "motor-fs",
                "quarantined",
                "-",
                "-",
                "-"
            ]
        );
    }
    let mut output = Vec::new();
    command::write_table(&mut output, &mut [], true).unwrap();
    assert_eq!(output, b"ID TARGET SOURCE FSTYPE STATE USED CAP ENTRIES\n");
    println!("sysbox_findmnt PASS");
}
