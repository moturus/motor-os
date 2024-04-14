#![feature(io_error_more)]

mod commands;

fn print_usage_and_exit(exit_code: i32) -> ! {
    println!("sysbox commands:");
    println!("\tsysbox cat");
    println!("\tsysbox echo");
    println!("\tsysbox free");
    println!("\tsysbox help");
    println!("\tsysbox loop");
    println!("\tsysbox ls");
    println!("\tsysbox mkdir");
    println!("\tsysbox mv");
    println!("\tsysbox ps");
    println!("\tsysbox pwd");
    println!("\tsysbox rm");
    println!("\tsysbox rmdir");
    println!("\tsysbox sleep");
    println!("\tsysbox time");
    std::process::exit(exit_code);
}

fn main() {
    let args: Vec<_> = std::env::args().collect();

    if args.len() < 2 {
        print_usage_and_exit(0);
    }

    match args[1].as_str() {
        "cat" => commands::cat::do_command(&args[1..]),
        "echo" => commands::echo::do_command(&args[1..]),
        "free" => commands::free::do_command(&args[1..]),
        "help" => print_usage_and_exit(0),
        "loop" => commands::cmd_loop::do_command(&args[1..]),
        "ls" => commands::ls::do_command(&args[1..]),
        "mkdir" => commands::mkdir::do_command(&args[1..]),
        "mv" => commands::mv::do_command(&args[1..]),
        "ps" => commands::ps::do_command(&args[1..]),
        "pwd" => commands::pwd::do_command(&args[1..]),
        "rm" => commands::rm::do_command(&args[1..]),
        "rmdir" => commands::rmdir::do_command(&args[1..]),
        "sleep" => commands::sleep::do_command(&args[1..]),
        "time" => commands::time::do_command(&args[1..]),
        _ => print_usage_and_exit(1),
    }
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
