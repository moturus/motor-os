pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "uptime");

    let uptime = moto_sys::time::since_system_start();
    let days = uptime.as_secs() / 86400;
    let hours = uptime.as_secs() / 3600 % 24;
    let minutes = uptime.as_secs() / 60 % 60;
    let seconds = uptime.as_secs() % 60;
    let now = time::OffsetDateTime::now_utc();

    println!(
        "{}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} UTC up {} days {:02}:{:02}:{:02}.{:03}",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond(),
        days,
        hours,
        minutes,
        seconds,
        uptime.as_millis() % 1000
    );

    if args.len() > 1 {
        std::process::exit(1);
    }
}
