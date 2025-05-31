fn basic() {
    moto_log::init("systest").unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    let timestamp_1 = moto_rt::time::Instant::now();
    log::info!("foo");
    log::warn!("bar");
    log::error!("baz");
    let timestamp_2 = moto_rt::time::Instant::now();

    let log_entries = moto_log::get_tail_entries().unwrap();
    assert_eq!(3, log_entries.len());

    let e1 = &log_entries[0];
    assert_eq!(e1.level(), log::Level::Info);
    assert_eq!(e1.tag.as_str(), "systest");
    assert!(e1.msg.contains("foo"));
    assert!(e1.timestamp >= timestamp_1);
    assert!(e1.timestamp <= timestamp_2);

    let e2 = &log_entries[1];
    assert_eq!(e2.level(), log::Level::Warn);
    assert_eq!(e2.tag.as_str(), "systest");
    assert!(e2.msg.contains("bar"));
    assert!(e2.timestamp >= timestamp_1);
    assert!(e2.timestamp <= timestamp_2);

    let e3 = &log_entries[2];
    assert_eq!(e3.level(), log::Level::Error);
    assert_eq!(e3.tag.as_str(), "systest");
    assert!(e3.msg.contains("baz"));
    assert!(e3.timestamp >= timestamp_1);
    assert!(e3.timestamp <= timestamp_2);

    println!("logging::basic test PASS");
}

pub fn run_all_tests() {
    basic();
}
