fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tprintenv [VARIABLE]...\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "printenv");

    if args.len() == 1 {
        print_all();
        return;
    }

    if args.len() == 2 && (args[1] == "-h" || args[1] == "--help") {
        print_usage_and_exit(0);
    }

    for (key, value) in std::env::vars().filter(|kv| args[1..].contains(&kv.0)) {
        println!("{key}={value}");
    }
}

fn print_all() {
    for (key, value) in std::env::vars() {
        println!("{key}={value}");
    }
}
