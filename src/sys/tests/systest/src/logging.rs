use std::time::{Duration, Instant};

const LOG_PATH: &str = "/sys/logs/systest.log";

/// Read the log once it holds at least `want` complete lines.
///
/// `moto_log::init()` and each `log!` are synchronous RPCs to strobe, but its
/// RPC thread only queues the record: a separate io thread creates the file and
/// writes it. So both the file's existence and its contents lag the client by an
/// unbounded amount under load, and a fixed sleep here is a race. Requiring a
/// trailing newline keeps a half-written record from being counted as a line.
fn wait_for_lines(want: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let log = std::fs::read_to_string(LOG_PATH).unwrap_or_default();
        if log.ends_with('\n') {
            let lines: Vec<String> = log.lines().map(str::to_owned).collect();
            if lines.len() >= want {
                return lines;
            }
        }
        assert!(
            Instant::now() < deadline,
            "{LOG_PATH}: want {want} lines, have {:?}",
            log.lines().count()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn basic() {
    let _ = std::fs::remove_file(LOG_PATH);

    moto_log::init("systest").unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    let lines = wait_for_lines(1);
    assert_eq!(1, lines.len());
    assert!(lines[0].contains(":I - started log for 'systest'"));

    // Anchor the expected `target:line` suffixes to where the calls actually
    // are, so editing this file cannot silently break the assertions below.
    let info_line = line!() + 1;
    log::info!("foo");
    log::warn!("bar");
    log::debug!("another debug string");
    log::trace!("baz"); // should flush.

    let lines = wait_for_lines(5);
    assert_eq!(5, lines.len());
    assert!(lines[0].ends_with(":I - started log for 'systest'"));
    assert!(lines[1].ends_with(&format!(":I - systest::logging:{info_line} - foo")));
    assert!(lines[2].ends_with(&format!(":W - systest::logging:{} - bar", info_line + 1)));
    assert!(lines[3].ends_with(&format!(
        ":D - systest::logging:{} - another debug string",
        info_line + 2
    )));
    assert!(lines[4].ends_with(&format!(":T - systest::logging:{} - baz", info_line + 3)));

    println!("logging::basic test PASS");
}

pub fn run_all_tests() {
    basic();
}
