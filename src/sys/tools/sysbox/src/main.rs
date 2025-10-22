#![feature(io_error_more)]

mod commands;

fn print_usage_and_exit(exit_code: i32) -> ! {
    println!("sysbox commands:");
    println!("\tsysbox cat");
    println!("\tdate");
    println!("\tsysbox echo");
    println!("\tsysbox free");
    println!("\tsysbox help");
    println!("\tsysbox kill");
    println!("\tsysbox loop");
    println!("\tsysbox ls");
    println!("\tsysbox mkdir");
    println!("\tsysbox mv");
    println!("\tsysbox printenv");
    println!("\tsysbox ps");
    println!("\tsysbox pwd");
    println!("\tsysbox rm");
    println!("\tsysbox rmdir");
    println!("\tsysbox sleep");
    println!("\tsysbox ss");
    println!("\tsysbox time");
    println!("\tsysbox top");
    println!("\tsysbox uptime");
    std::process::exit(exit_code);
}

#[allow(unused)]
fn input_listener() {
    use std::io::Read;

    loop {
        let mut input = [0_u8; 16];
        let sz = std::io::stdin().read(&mut input).unwrap();
        for b in &input[0..sz] {
            if *b == 3 {
                println!("Caught ^C: exiting.");
                std::process::exit(1);
            }
        }
    }
}

#[allow(unused)]
fn spawn_generic_input_listener() {
    std::thread::spawn(input_listener);
}

fn main() {
    let args: Vec<_> = std::env::args().collect();

    if args.len() < 2 {
        print_usage_and_exit(0);
    }

    match args[1].as_str() {
        "cat" => commands::cat::do_command(&args[1..]),
        "date" => commands::date::do_command(&args[1..]),
        "echo" => commands::echo::do_command(&args[1..]),
        "free" => commands::free::do_command(&args[1..]),
        "help" => print_usage_and_exit(0),
        "kill" => commands::kill::do_command(&args[1..]),
        "loop" => commands::loop_cmd::do_command(&args[1..]),
        "ls" => commands::ls::do_command(&args[1..]),
        "mkdir" => commands::mkdir::do_command(&args[1..]),
        "mv" => commands::mv::do_command(&args[1..]),
        "printenv" => commands::printenv::do_command(&args[1..]),
        "ps" => commands::ps::do_command(&args[1..]),
        "pwd" => commands::pwd::do_command(&args[1..]),
        "rm" => commands::rm::do_command(&args[1..]),
        "rmdir" => commands::rmdir::do_command(&args[1..]),
        "sleep" => commands::sleep::do_command(&args[1..]),
        "ss" => commands::ss::do_command(&args[1..]),
        "time" => commands::time::do_command(&args[1..]),
        "top" => commands::top::do_command(&args[1..]),
        "uptime" => commands::uptime::do_command(&args[1..]),
        _ => print_usage_and_exit(1),
    }

    // TODO: remove when stdrt::flush() works.
    std::thread::sleep(std::time::Duration::from_millis(100));
}

/*
fn do_syslog() {
    log::trace!("frosh: syslog");
    match moto_log::get_tail_entries() {
        Ok(log_entries) => {
            for entry in &log_entries {
                write_serial!("{}\n", entry);
            }
        }
        Err(e) => write_serial!("Error obtaining syslog: {}\n", e),
    }
}
*/
