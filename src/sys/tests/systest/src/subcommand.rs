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
    const IS_TERMINAL_TRUE: i32 = 1234;
    const IS_TERMINAL_FALSE: i32 = 4568;

    pub fn std_child(&mut self) -> &mut std::process::Child {
        &mut self.inst
    }

    pub fn do_exit(&mut self, code: i32) {
        use std::io::Write;
        self.stdin
            .write_all(format!("exit {code}\n").as_bytes())
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

    pub fn exec_heap(&mut self) {
        use std::io::Write;
        self.stdin.write_all(b"exec_heap\n").unwrap();
        self.stdin.flush().unwrap();
    }

    pub fn exec_stack(&mut self) {
        use std::io::Write;
        self.stdin.write_all(b"exec_stack\n").unwrap();
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

    pub fn is_terminal(&mut self) -> bool {
        use std::io::Write;

        self.stdin.write_all(b"is_terminal\n").unwrap();
        self.stdin.flush().unwrap();

        let code = self.wait().unwrap().code().unwrap();
        match code {
            Self::IS_TERMINAL_TRUE => true,
            Self::IS_TERMINAL_FALSE => false,
            _ => panic!(),
        }
    }
}

pub fn run_child(args: Vec<String>) -> ! {
    if args.len() != 2 || args[1] != "subcommand" {
        panic!("bad args: {args:?}")
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
        // W^X: executing from R+W memory must get this process killed; if
        // it survives, exit(0) so the parent's !success() assert fires.
        "exec_heap" => {
            let addr =
                moto_sys::SysMem::alloc(moto_sys::sys_mem::PAGE_SIZE_SMALL, 1).unwrap() as usize;
            unsafe {
                (addr as *mut u8).write_volatile(0xc3); // ret
                let f: extern "C" fn() = core::mem::transmute(addr);
                f();
            }
            println!("exec_heap: still alive (NX not enforced)");
            std::process::exit(0);
        }
        "exec_stack" => {
            let code = [0xc3_u8]; // ret
            unsafe {
                let f: extern "C" fn() =
                    core::mem::transmute(std::hint::black_box(code.as_ptr()));
                f();
            }
            println!("exec_stack: still alive (NX not enforced)");
            std::process::exit(0);
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

            let mut bytes = [0];
            moto_rt::fill_random_bytes(&mut bytes);

            if bytes[0] & 1 == 1 {
                std::process::exit(code)
            } else {
                // There was a bug when calling exit_process() from a non-main thread misbehaved.
                let _ =
                    std::thread::spawn(move || moto_sys::SysCpu::exit_process(code as u64)).join();
                loop {}
            }
        }
        "is_terminal" => {
            use std::io::IsTerminal;

            if std::io::stdin().is_terminal() {
                std::process::exit(Subcommand::IS_TERMINAL_TRUE)
            } else {
                std::process::exit(Subcommand::IS_TERMINAL_FALSE)
            }
        }
        "xor_service" => crate::xor_server::start(),
        _ => panic!("unknown command: {words:?}"),
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
