use std::io::Write;
use std::sync::atomic::*;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("usage:\n\tloop $CMD [args]\n");
    std::process::exit(exit_code);
}

const EVENT_NONE: u32 = 0;
const EVENT_INPUT: u32 = 1;
const EVENT_CHILD_EXIT: u32 = 2;

// We need to intercept ^C, so we pipe stdin.
fn input_listener(input_queue: Arc<Mutex<VecDeque<u8>>>, input_futex: Arc<AtomicU32>) {
    use std::io::Read;

    loop {
        let mut buffer = [0_u8; 16];
        let sz = std::io::stdin().read(&mut buffer).unwrap();
        if sz > 0 {
            let mut queue = input_queue.lock().unwrap();
            for b in &buffer[0..sz] {
                if *b == 3 {
                    println!("Caught ^C: exiting.");
                    std::process::exit(1);
                }
                queue.push_back(*b);
            }
        }

        if let Err(val) = input_futex.compare_exchange(
            EVENT_NONE,
            EVENT_INPUT,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            if val == EVENT_CHILD_EXIT {
                continue;
            }
            assert_eq!(val, EVENT_INPUT);
            continue;
        }
        moto_rt::futex::futex_wake(&input_futex);
    }
}

fn child_listener(mut child: std::process::Child, child_futex: Arc<AtomicU32>) {
    let res = child.wait().unwrap();
    if !res.success() {
        println!("loop: child failed: {:?}", res);
        std::process::exit(1);
    }
    child_futex.store(EVENT_CHILD_EXIT, Ordering::Release);
    moto_rt::futex::futex_wake(&child_futex);
}

fn child_input_relay(
    input: &Mutex<VecDeque<u8>>,
    child_stdin: &mut std::process::ChildStdin,
    futex: &AtomicU32,
) {
    loop {
        let mut bytes = VecDeque::new();
        {
            let mut inp = input.lock().unwrap();
            while let Some(b) = inp.pop_front() {
                bytes.push_back(b);
            }
        }
        if !bytes.is_empty() {
            let (b1, b2) = bytes.as_slices();
            let _ = child_stdin.write_all(b1);
            let _ = child_stdin.write_all(b2);
        }

        moto_rt::futex::futex_wait(futex, EVENT_NONE, None);
        match futex.load(Ordering::Acquire) {
            EVENT_INPUT => {
                let _ = futex.compare_exchange(
                    EVENT_INPUT,
                    EVENT_NONE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                continue;
            }
            EVENT_CHILD_EXIT => {
                futex.store(EVENT_NONE, Ordering::Release);
                return;
            }
            val => panic!("unexpected value {val}"),
        }
    }
}

pub fn do_command(args: &[String]) {
    assert_eq!(args[0], "loop");

    if args.len() < 2 {
        print_usage_and_exit(1);
    }

    let input_queue: Arc<Mutex<VecDeque<u8>>> = Arc::new(Mutex::new(VecDeque::new()));
    let input_queue_clone = input_queue.clone();
    let futex = Arc::new(AtomicU32::new(0));
    let input_futex = futex.clone();

    std::thread::spawn(move || {
        input_listener(input_queue_clone, input_futex);
    });

    loop {
        let mut cmd = std::process::Command::new(args[1].as_str());

        for arg in &args[2..] {
            cmd.arg(arg);
        }

        cmd.stdin(std::process::Stdio::piped());

        match cmd.spawn() {
            Ok(mut child) => {
                let mut child_stdin = child.stdin.take().unwrap();
                let child_futex = futex.clone();
                std::thread::spawn(move || {
                    child_listener(child, child_futex);
                });

                child_input_relay(&input_queue, &mut child_stdin, &futex);
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::InvalidFilename => {
                    eprintln!("{}: command not found.", args[1]);
                    return;
                }
                _ => {
                    eprintln!("Command [{}] failed with error: [{}].", args[1], e);
                    return;
                }
            },
        }
    }
}
