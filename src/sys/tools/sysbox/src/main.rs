#![feature(io_error_more)]

mod commands;

fn print_usage_and_exit(exit_code: i32) -> ! {
    println!("sysbox commands:");
    println!("\tsysbox cat");
    println!("\tsysbox chmod");
    println!("\tsysbox cp");
    println!("\tsysbox date");
    println!("\tsysbox find");
    println!("\tsysbox free");
    println!("\tsysbox help");
    println!("\tsysbox less");
    println!("\tsysbox loop");
    println!("\tsysbox ls");
    println!("\tsysbox mkdir");
    println!("\tsysbox mv");
    println!("\tsysbox ping");
    println!("\tsysbox printenv");
    println!("\tsysbox ps");
    println!("\tsysbox pstat");
    println!("\tsysbox rm");
    println!("\tsysbox rmdir");
    println!("\tsysbox sleep");
    println!("\tsysbox ss");
    println!("\tsysbox stats");
    println!("\tsysbox time");
    println!("\tsysbox top");
    println!("\tsysbox uptime");
    println!("\tsysbox wc");
    std::process::exit(exit_code);
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1 << 10;
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    const TIB: u64 = 1 << 40;

    if bytes >= TIB {
        format!("{:.2}T", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.2}G", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2}M", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2}K", bytes as f64 / KIB as f64)
    } else {
        format!("{}", bytes)
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();

    if args.len() < 2 {
        print_usage_and_exit(0);
    }

    match args[1].as_str() {
        "cat" => commands::cat::do_command(&args[1..]),
        "chmod" => commands::chmod::do_command(&args[1..]),
        "cp" => commands::cp::do_command(&args[1..]),
        "date" => commands::date::do_command(&args[1..]),
        "find" => commands::find::do_command(&args[1..]),
        "free" => commands::free::do_command(&args[1..]),
        "help" => print_usage_and_exit(0),
        "less" => commands::less::do_command(&args[1..]),
        "loop" => commands::loop_cmd::do_command(&args[1..]),
        "ls" => commands::ls::do_command(&args[1..]),
        "mkdir" => commands::mkdir::do_command(&args[1..]),
        "mv" => commands::mv::do_command(&args[1..]),
        "ping" => commands::ping::do_command(&args[1..]),
        "printenv" => commands::printenv::do_command(&args[1..]),
        "ps" => commands::ps::do_command(&args[1..]),
        "pstat" => commands::pstat::do_command(&args[1..]),
        "rm" => commands::rm::do_command(&args[1..]),
        "rmdir" => commands::rmdir::do_command(&args[1..]),
        "sleep" => commands::sleep::do_command(&args[1..]),
        "ss" => commands::ss::do_command(&args[1..]),
        "stats" => commands::stats::do_command(&args[1..]),
        "time" => commands::time::do_command(&args[1..]),
        "top" => commands::top::do_command(&args[1..]),
        "uptime" => commands::uptime::do_command(&args[1..]),
        "wc" => commands::wc::do_command(&args[1..]),
        _ => print_usage_and_exit(1),
    }

    // TODO: remove when stdrt::flush() works.
    // std::thread::sleep(std::time::Duration::from_millis(100));
}
