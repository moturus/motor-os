pub fn do_command(_args: &[String]) {
    match std::env::current_dir() {
        Ok(path_buf) => println!("{}", path_buf.as_os_str().to_str().unwrap()),
        Err(_) => eprintln!("Current working directory not available."),
    }
}
