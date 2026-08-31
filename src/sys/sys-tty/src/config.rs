#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelLogMode {
    Console,
    Strobe,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Config<'a> {
    pub kernel_log: KernelLogMode,
    pub command: &'a str,
}

pub fn parse(input: &str) -> Result<Config<'_>, String> {
    let mut kernel_log = KernelLogMode::Console;
    let mut kernel_log_seen = false;
    let mut command = None;

    for (index, raw_line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if command.is_some() {
            return Err(format!(
                "unexpected line after command at line {line_number}"
            ));
        }

        if let Some(value) = line.strip_prefix("kernel-log:") {
            if kernel_log_seen {
                return Err(format!("duplicate kernel-log option at line {line_number}"));
            }
            kernel_log = match value.trim() {
                "console" => KernelLogMode::Console,
                "strobe" => KernelLogMode::Strobe,
                _ => return Err(format!("invalid kernel-log value at line {line_number}")),
            };
            kernel_log_seen = true;
            continue;
        }

        let first_word = line.split_whitespace().next().unwrap();
        if first_word.contains(':') && !first_word.contains('=') {
            return Err(format!("unknown option at line {line_number}"));
        }
        command = Some(line);
    }

    let command = command.ok_or_else(|| "missing command".to_owned())?;
    Ok(Config {
        kernel_log,
        command,
    })
}

pub fn run_self_tests() {
    assert_eq!(
        parse("ENV=/system/cfg/rush.cfg /system/bin/rush -i"),
        Ok(Config {
            kernel_log: KernelLogMode::Console,
            command: "ENV=/system/cfg/rush.cfg /system/bin/rush -i",
        })
    );
    assert_eq!(
        parse("\n # comment\n kernel-log: strobe\n\n /system/bin/rush -i\n"),
        Ok(Config {
            kernel_log: KernelLogMode::Strobe,
            command: "/system/bin/rush -i",
        })
    );
    assert_eq!(
        parse("kernel-log:console\n/system/bin/rush"),
        Ok(Config {
            kernel_log: KernelLogMode::Console,
            command: "/system/bin/rush",
        })
    );
    assert_eq!(
        parse("URL=tcp://example /system/bin/rush"),
        Ok(Config {
            kernel_log: KernelLogMode::Console,
            command: "URL=tcp://example /system/bin/rush",
        })
    );

    for invalid in [
        "",
        "# no command",
        "kernel-log:strobe",
        "kernel-log:file\n/system/bin/rush",
        "kernel-log:console\nkernel-log:strobe\n/system/bin/rush",
        "unknown:value\n/system/bin/rush",
        "/system/bin/rush\n/system/bin/other",
        "/system/bin/rush\nkernel-log:console",
    ] {
        assert!(parse(invalid).is_err(), "accepted {invalid:?}");
    }

    println!("sys-tty config self-test PASS");
}
