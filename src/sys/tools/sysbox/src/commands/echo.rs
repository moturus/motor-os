pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "echo");

    for idx in 1..args.len() {
        print!("{}", args[idx]);
        if idx < args.len() - 1 {
            print!(" ");
        }
    }

    println!();
}
