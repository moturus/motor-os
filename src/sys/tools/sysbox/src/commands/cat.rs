use std::io::Read;
use std::path::Path;

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tcat [FILENAME]...\n");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "cat");

    let args = &args[1..];
    for arg in args {
        if arg == "--help" {
            print_usage_and_exit(0);
        }
    }

    // Without a filename (or with "-"), cat reads standard input: that is what
    // makes `foo | cat` and `cat < foo` work.
    if args.is_empty() {
        cat_stdin();
        return;
    }

    for arg in args {
        if arg == "-" {
            cat_stdin();
        } else {
            cat_file(arg);
        }
    }
}

fn cat_stdin() {
    let mut bytes = Vec::new();
    match std::io::stdin().read_to_end(&mut bytes) {
        Ok(_) => cat_bytes(&bytes, "stdin"),
        Err(err) => println!("cat: error reading stdin: {err:?}."),
    }
}

fn cat_file(fname: &str) {
    match std::fs::read(Path::new(fname)) {
        Ok(bytes) => cat_bytes(&bytes, fname),
        Err(err) => {
            println!("cat: error reading file '{fname}': {err:?}.");
        }
    }
}

fn cat_bytes(bytes: &[u8], source: &str) {
    match std::str::from_utf8(bytes) {
        Ok(s) => print!("{s}"),
        Err(_) => println!("Can't cat a binary file '{source}'."),
    }
}
