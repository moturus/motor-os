use std::path::Path;

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\twhich [-a] COMMAND...");
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "which");

    let mut all = false;
    let mut idx = 1;
    while idx < args.len() {
        match args[idx].as_str() {
            "-a" => all = true,
            "--help" => print_usage_and_exit(0),
            "--" => {
                idx += 1;
                break;
            }
            arg if arg.starts_with('-') => print_usage_and_exit(1),
            _ => break,
        }
        idx += 1;
    }

    if idx == args.len() {
        print_usage_and_exit(1);
    }

    let mut found_all = true;
    for command in &args[idx..] {
        found_all &= find(command, all);
    }
    if !found_all {
        std::process::exit(1);
    }
}

fn find(command: &str, all: bool) -> bool {
    if command.contains(std::path::MAIN_SEPARATOR) {
        let path = Path::new(command);
        if is_executable_file(path) {
            println!("{command}");
            return true;
        }
        return false;
    }

    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    let mut found = false;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(command);
        if is_executable_file(&candidate) {
            println!("{}", candidate.display());
            found = true;
            if !all {
                break;
            }
        }
    }
    found
}

#[cfg(target_os = "motor")]
fn is_executable_file(path: &Path) -> bool {
    let Some(path) = path.to_str() else {
        return false;
    };
    moto_rt::fs::stat(path).is_ok_and(|attr| {
        attr.file_type == moto_rt::fs::FILETYPE_FILE && attr.perm & moto_rt::fs::PERM_EXEC != 0
    })
}

#[cfg(not(target_os = "motor"))]
compile_error!("sysbox must be compiled for Motor OS");
