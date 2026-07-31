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
        "write_until_closed" => {
            for _ in 0..1024 {
                if moto_rt::fs::write(moto_rt::FD_STDOUT, &[0; 4096]).is_err() {
                    std::process::exit(0);
                }
            }
            std::process::exit(3);
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
                let f: extern "C" fn() = core::mem::transmute(std::hint::black_box(code.as_ptr()));
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
        // Poll this process's *own* stdio, which rt.vdso used to offer only
        // for a child's. The parent gates each half on the lines printed
        // here, so stdin is provably empty while the idle half runs.
        "poll_self_stdio" => {
            const STDIN_TOKEN: u64 = 71;
            const STDOUT_TOKEN: u64 = 72;
            const READABLE: u64 = moto_rt::poll::POLL_READABLE;
            const WRITABLE: u64 = moto_rt::poll::POLL_WRITABLE;

            let registry = moto_rt::poll::new().unwrap();
            let mut events = [moto_rt::poll::Event::default(); 2];
            let wait = |events: &mut [moto_rt::poll::Event; 2], timeout: Duration| {
                moto_rt::poll::wait(
                    registry,
                    events as *mut _,
                    2,
                    Some(moto_rt::time::Instant::now() + timeout),
                )
                .unwrap()
            };

            // An empty stdout has room, and says so without an edge to wait for.
            moto_rt::poll::add(registry, moto_rt::FD_STDOUT, STDOUT_TOKEN, WRITABLE).unwrap();
            assert_eq!(1, wait(&mut events, Duration::from_secs(5)));
            assert_eq!(events[0].token, STDOUT_TOKEN);
            assert_eq!(events[0].events, WRITABLE);
            moto_rt::poll::del(registry, moto_rt::FD_STDOUT).unwrap();

            // Nothing typed: no event, and a non-blocking read agrees.
            moto_rt::poll::add(registry, moto_rt::FD_STDIN, STDIN_TOKEN, READABLE).unwrap();
            assert_eq!(0, wait(&mut events, Duration::from_millis(20)));
            moto_rt::net::set_nonblocking(moto_rt::FD_STDIN, true).unwrap();
            let mut probe = [0_u8; 4];
            assert_eq!(
                moto_rt::Error::NotReady,
                moto_rt::fs::read(moto_rt::FD_STDIN, &mut probe)
                    .err()
                    .unwrap()
            );
            moto_rt::net::set_nonblocking(moto_rt::FD_STDIN, false).unwrap();
            println!("poll_self_stdio: idle");

            // The parent's next command is what wakes this; the read loop
            // above then consumes it as usual.
            assert_eq!(1, wait(&mut events, Duration::from_secs(5)));
            assert_eq!(events[0].token, STDIN_TOKEN);
            assert_eq!(events[0].events, READABLE);
            moto_rt::fs::close(registry).unwrap();
            println!("poll_self_stdio: readable");
        }
        // Alternate polling this process's own stdin with reading it: the
        // poll registration leaves a readiness task waiting on the very
        // handle the blocking read then waits on, so every round has two
        // threads of this process on one handle.
        "poll_stress" => {
            const STDIN_TOKEN: u64 = 73;
            assert_eq!(2, words.len());
            let rounds = words[1].parse::<usize>().unwrap();

            let registry = moto_rt::poll::new().unwrap();
            let mut events = [moto_rt::poll::Event::default(); 1];
            moto_rt::poll::add(
                registry,
                moto_rt::FD_STDIN,
                STDIN_TOKEN,
                moto_rt::poll::POLL_READABLE,
            )
            .unwrap();

            // The line read above was buffered by std; say so before the
            // parent sends anything else, or the first round's bytes are
            // taken by that buffer and never reach the pipe.
            println!("poll_stress: ready");

            // Reads coalesce, so this counts bytes rather than rounds.
            let total = rounds * 8;
            let mut echoed = 0_usize;
            let mut buf = [0_u8; 32];
            while echoed < total {
                let woke = moto_rt::poll::wait(
                    registry,
                    (&mut events) as *mut _,
                    1,
                    Some(moto_rt::time::Instant::now() + Duration::from_secs(10)),
                )
                .unwrap();
                assert_eq!(
                    1, woke,
                    "poll_stress: no readable event at {echoed}/{total}"
                );

                let sz = moto_rt::fs::read(moto_rt::FD_STDIN, &mut buf).unwrap();
                assert!(sz > 0);
                let mut written = 0;
                while written < sz {
                    written += moto_rt::fs::write(moto_rt::FD_STDOUT, &buf[written..sz]).unwrap();
                }
                echoed += sz;
            }

            moto_rt::fs::close(registry).unwrap();
            println!("poll_stress: done");
        }
        // Blocking reads of this process's own stdin *after* a poll of it,
        // which is what the shape of `poll_self_stdio` leaves behind: the
        // registry is gone but rt.vdso's readiness task still waits on the
        // handle the reads wait on.
        "read_stress" => {
            const STDIN_TOKEN: u64 = 74;
            assert_eq!(2, words.len());
            let rounds = words[1].parse::<usize>().unwrap();

            let registry = moto_rt::poll::new().unwrap();
            moto_rt::poll::add(
                registry,
                moto_rt::FD_STDIN,
                STDIN_TOKEN,
                moto_rt::poll::POLL_READABLE,
            )
            .unwrap();
            moto_rt::fs::close(registry).unwrap();
            println!("read_stress: ready");

            let total = rounds * 8;
            let mut echoed = 0_usize;
            let mut buf = [0_u8; 32];
            while echoed < total {
                let sz = moto_rt::fs::read(moto_rt::FD_STDIN, &mut buf).unwrap();
                assert!(sz > 0);
                let mut written = 0;
                while written < sz {
                    written += moto_rt::fs::write(moto_rt::FD_STDOUT, &buf[written..sz]).unwrap();
                }
                echoed += sz;
            }

            println!("read_stress: done");
        }
        // Write as fast as the pipe takes it, for a parent that is polling
        // this stdout rather than reading it.
        "spew" => {
            assert_eq!(2, words.len());
            let rounds = words[1].parse::<usize>().unwrap();
            for round in 0..rounds {
                let chunk = format!("{round:07}.");
                let mut written = 0;
                while written < chunk.len() {
                    written += moto_rt::fs::write(moto_rt::FD_STDOUT, &chunk.as_bytes()[written..])
                        .unwrap();
                }
                if round % 3 == 0 {
                    moto_sys::SysCpu::sched_yield();
                }
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
