/// A log snapshot can end in the middle of a formatted write, including an address.
pub(super) fn complete_output<'a>(output: &'a str, text: &str) -> Option<&'a str> {
    let end = output.rfind('\n')?;
    let complete = &output[..=end];
    complete.contains(text).then_some(complete)
}

pub(super) fn stderr_matches(actual: &str, expected: &str, debug_image: bool) -> bool {
    if !debug_image {
        return actual == expected;
    }
    let mut expected = expected.split_inclusive('\n').peekable();
    for line in actual.split_inclusive('\n') {
        if expected.next_if_eq(&line).is_none() && !wasm_runtime_record(line) {
            return false;
        }
    }
    expected.next().is_none()
}

// These records come from the debug rt.vdso when a Wasm tool opens its first
// file or rush spawns it. An incomplete line remains part of the command output.
fn wasm_runtime_record(line: &str) -> bool {
    let Some((time, record)) = line
        .strip_suffix('\n')
        .and_then(|s| s.split_once(": DEBUG "))
    else {
        return false;
    };
    let Some((seconds, millis)) = time.split_once(':') else {
        return false;
    };
    let Some((location, message)) = record.split_once(": ") else {
        return false;
    };
    let Some((file, number)) = location.rsplit_once(':') else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let decimal = |s: &str| digits(s) && (s == "0" || !s.starts_with('0'));
    let seconds_digits = seconds.trim_start_matches(' ');
    if seconds.len() != seconds_digits.len().max(3)
        || !decimal(seconds_digits)
        || millis.len() != 3
        || !digits(millis)
        || !decimal(number)
    {
        return false;
    }
    match file {
        "lib/rt.vdso/src/rt_fs.rs" => message == "AsyncFsClient created.",
        "lib/rt.vdso/src/rt_process.rs" => matches!(
            message,
            "spawn /user/bin/dev/wasmi"
                | "spawn /user/bin/dev/wasmtime"
                | "spawn /user/bin/dev/wasmtime-rt"
        ),
        _ => false,
    }
}
