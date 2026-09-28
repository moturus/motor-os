pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "nproc");
    if args.len() > 1 {
        eprintln!("usage: nproc");
        std::process::exit(1);
    }

    println!("{}", moto_rt::num_cpus());
}
