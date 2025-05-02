/*
 * Spawn a subprocess (subcommand) and manage it via stdio.
 */

use std::time::Duration;

pub struct Subcommand {
    inst: std::process::Child,
    stdin: std::process::ChildStdin,
}

pub fn spawn() -> Subcommand {
    let mut inst = std::process::Command::new(std::env::args().next().unwrap())
        .arg("subcommand")
        .env("some_key", "some_val")
        .env("none_key", "")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let stdin = inst.stdin.take().unwrap();
    Subcommand { inst, stdin }
}

impl Subcommand {
    pub fn do_exit(&mut self, code: i32) {
        use std::io::Write;
        self.stdin
            .write_all(format!("exit {}\n", code).as_bytes())
            .unwrap();
        self.stdin.flush().unwrap();
    }

    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.inst.wait()
    }

    pub fn spin(&mut self, duration: std::time::Duration) {
        use std::io::Write;
        self.stdin
            .write_all(format!("spin {}\n", duration.as_micros()).as_bytes())
            .unwrap();
        self.stdin.flush().unwrap();
    }

    pub fn oom(&mut self) {
        use std::io::Write;
        self.stdin.write_all(b"oom\n").unwrap();
        self.stdin.flush().unwrap();
    }

    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.inst.try_wait()
    }

    pub fn kill(&mut self) {
        self.inst.kill().unwrap()
    }

    pub fn start_xor_service(&mut self) {
        use std::io::Write;
        self.stdin.write_all(b"xor_service\n").unwrap();
        self.stdin.flush().unwrap();
    }
}

pub fn run_child(args: Vec<String>) -> ! {
    if args.len() != 2 || args[1] != "subcommand" {
        panic!("bad args: {:?}", args)
    }

    assert_eq!(std::env::var("some_key").unwrap(), "some_val");
    assert_eq!(std::env::var("none_key").unwrap(), "");
    assert!(std::env::var("bad_key").is_err());

    loop {
        let mut cmd = String::new();
        std::io::stdin().read_line(&mut cmd).unwrap();
        do_command(cmd);
    }
}

fn do_command(cmd: String) {
    let words: Vec<&str> = cmd
        .split_ascii_whitespace()
        .filter(|s| !s.trim().is_empty())
        .collect();

    if words.is_empty() {
        return;
    }

    match words[0] {
        "echo1" => {
            println!("{}", cmd.trim());
        }
        "echo2" => {
            eprintln!("{}", cmd.trim());
        }
        "oom" => {
            assert_eq!(1, words.len());
            trigger_oom()
        }
        "spin" => {
            assert_eq!(2, words.len());
            let ms = words[1].parse::<u128>().unwrap();
            let start = std::time::Instant::now();
            while start.elapsed().as_micros() < ms {
                core::hint::spin_loop();
            }
        }
        "exit" => {
            assert_eq!(2, words.len());
            let code = words[1].parse::<i32>().unwrap();
            std::process::exit(code)
        }
        "xor_service" => crate::xor_server::start(),
        _ => panic!("unknown command: {:?}", words),
    }
}

fn trigger_oom() -> ! {
    use moto_sys::SysMem;

    // First reach memory limit.
    println!("oom: stage 1");
    loop {
        if SysMem::alloc(moto_sys::sys_mem::PAGE_SIZE_SMALL, 8).is_err() {
            break;
        }
    }
    println!("oom: stage 2");

    // Now try spawning a thread: this should fail because
    // there's no memory available for this process.
    let handle = std::thread::spawn(|| std::thread::sleep(Duration::MAX));
    handle.join().unwrap();
    unreachable!()
}
