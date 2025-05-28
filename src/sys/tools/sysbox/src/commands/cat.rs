use std::path::Path;

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tcat [FILENAME]\n");
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

    for arg in args {
        cat_file(arg);
    }
}

fn cat_file(fname: &str) {
    match std::fs::read(Path::new(fname)) {
        Ok(bytes) => match std::str::from_utf8(bytes.as_ref()) {
            Ok(s) => print!("{s}"),
            Err(_) => println!("Can't cat a binary file '{fname}'."),
        },
        Err(err) => {
            println!("cat: error reading file '{fname}': {err:?}.");
        }
    }
}
