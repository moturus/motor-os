/*
 * Spawn a subprocess (subcommand) and manage it via stdio.
 */

pub struct Subcommand {
    inst: std::process::Child,
    stdin: std::process::ChildStdin,
}

pub fn spawn() -> Subcommand {
    let mut inst = std::process::Command::new(std::env::args().next().unwrap())
        .arg("subcommand")
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
            .write(format!("exit {}\n", code).as_bytes())
            .unwrap();
        self.stdin.flush().unwrap();
    }

    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.inst.wait()
    }

    pub fn spin(&mut self, duration: std::time::Duration) {
        use std::io::Write;
        self.stdin
            .write(format!("spin {}\n", duration.as_micros()).as_bytes())
            .unwrap();
        self.stdin.flush().unwrap();
    }

    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.inst.try_wait()
    }

    pub fn kill(&mut self) {
        self.inst.kill().unwrap()
    }
}

pub fn run_child(args: Vec<String>) -> ! {
    if args.len() != 2 || args[1] != "subcommand" {
        panic!("bad args: {:?}", args)
    }

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
        _ => panic!("unknown command: {:?}", words),
    }
}
