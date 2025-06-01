fn basic() {
    moto_log::init("systest").unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    std::thread::sleep(std::time::Duration::from_millis(30));

    let log = std::fs::read_to_string("/sys/logs/systest.log").unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(1, lines.len());
    assert!(lines[0].contains(":I - started log for 'systest'"));

    log::info!("foo");
    log::warn!("bar");
    log::debug!("another debug string");
    log::trace!("baz"); // should flush.

    std::thread::sleep(std::time::Duration::from_millis(30));

    let log = std::fs::read_to_string("/sys/logs/systest.log").unwrap();
    let lines: Vec<&str> = log.lines().collect();

    assert_eq!(5, lines.len());
    assert!(lines[0].ends_with(":I - started log for 'systest'"));
    assert!(lines[1].ends_with(":I - systest::logging:12 - foo"));
    assert!(lines[2].ends_with(":W - systest::logging:13 - bar"));
    assert!(lines[3].ends_with(":D - systest::logging:14 - another debug string"));
    assert!(lines[4].ends_with(":T - systest::logging:15 - baz"));

    println!("logging::basic test PASS");
}

pub fn run_all_tests() {
    basic();
}
