pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "date");

    let now = time::OffsetDateTime::now_utc();
    println!(
        "{}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} UTC",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond(),
    );

    if args.len() > 1 {
        std::process::exit(1);
    }
}
