use core::slice;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use moto_sys::SysCpu;
use moto_sys::SysHandle;
use moto_sys::SysObj;
use moto_sys::kernel_log::{KERNEL_LOG_RING_SIZE, KernelLogControl};

use crate::output::{Output, Source};

mod ansi;
mod config;
mod forwarder;
mod kernel_log;
mod output;
mod sanitize;
mod serial;

const USER_HOME: &str = "/user";

/// Whether a config word is a `NAME=value` environment assignment rather than
/// the program name or an argument.
fn is_assignment(word: &str) -> bool {
    match word.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// Reports a startup failure and exits once the UART has the whole message.
fn exit_with(output: &Output, args: std::fmt::Arguments<'_>) -> ! {
    output.send_fmt(Source::Stderr, args);
    output.drain();
    std::process::exit(1)
}

fn read_config(output: &Output) -> String {
    let config_path = "/system/cfg/sys-tty.cfg";
    match std::fs::read_to_string(std::path::Path::new(config_path)) {
        Ok(config) => config,
        Err(err) => exit_with(
            output,
            format_args!("sys-tty: error reading '{config_path}': {err:?}"),
        ),
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--output-test-child") {
        output::run_pipe_self_test_child();
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("--pipe-self-test") {
        output::run_pipe_self_test();
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("--self-test") {
        ansi::run_self_tests();
        config::run_self_tests();
        forwarder::run_self_tests();
        sanitize::run_self_tests();
        output::run_self_tests();
        kernel_log::run_self_tests();
        return;
    }

    let output = Output::start_serial_writer();
    let config = read_config(&output);
    let config = match config::parse(&config) {
        Ok(config) => config,
        Err(err) => exit_with(&output, format_args!("sys-tty: invalid config: {err}.")),
    };
    let kernel_log_mode = config.kernel_log;
    let words: Vec<_> = config.command.split_whitespace().collect();

    // Leading `NAME=value` words set the child's environment, as in a shell
    // command line: the config is the only place to hand the login shell its
    // `$ENV` startup file, since sys-tty starts it with an empty environment.
    let assignments: Vec<_> = words
        .iter()
        .take_while(|w| is_assignment(w))
        .copied()
        .collect();
    let words = &words[assignments.len()..];

    if words.is_empty() {
        exit_with(&output, format_args!("sys-tty: error: empty config."));
    }

    let fname = words[0];

    let buf_addr =
        moto_sys::SysMem::alloc(4096, (KERNEL_LOG_RING_SIZE / 4096) as u64).unwrap() as usize;
    let kernel_log_buf =
        unsafe { slice::from_raw_parts(buf_addr as *const u8, KERNEL_LOG_RING_SIZE) };

    let mut kernel_log_control = Box::new(KernelLogControl::new());
    let control_addr = Box::as_mut(&mut kernel_log_control) as *mut KernelLogControl as usize;

    let console_wait_handle = moto_sys::SysObj::get(
        SysHandle::KERNEL,
        0,
        format!("serial_console:{buf_addr}:{control_addr}").as_str(),
    )
    .unwrap();

    let millis = moto_rt::time::since_system_start().as_millis();
    let forwarder = match kernel_log_mode {
        config::KernelLogMode::Console => None,
        config::KernelLogMode::Strobe => {
            let forwarder = forwarder::Forwarder::start(output.clone());
            if let Some(forwarder) = forwarder.as_ref() {
                let preamble =
                    format!("[kernel log: file forwarding started at {millis}ms since boot]\n");
                let _ = forwarder.offer(preamble.into_bytes());
            } else {
                let _ = output.try_send_kernel(
                    b"[kernel log: unable to start file forwarding worker]\n".to_vec(),
                );
            }
            forwarder
        }
    };
    output.send_fmt(
        Source::Stdout,
        format_args!(
            "  ... most services up at {:03}ms. Starting {}.\n\n",
            millis, fname
        ),
    );

    let mut command = std::process::Command::new(fname);
    command.env_clear();
    command.env("HOME", USER_HOME);
    command.env(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true");
    let own_caps = moto_sys::ProcessStaticPage::get().capabilities;
    let role_cap = match moto_sys::caps::ProcessRole::from_caps(own_caps) {
        moto_sys::caps::ProcessRole::System => moto_sys::caps::CAP_SYS,
        moto_sys::caps::ProcessRole::Interactive => moto_sys::caps::CAP_INTERACTIVE,
        moto_sys::caps::ProcessRole::None => 0,
    };
    // Preserve the configured session role without handing the console command
    // sys-tty's I/O-manager authority.
    command.env(
        moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
        format!(
            "0x{:x}",
            moto_sys::caps::CAP_SPAWN
                | moto_sys::caps::CAP_LOG
                | moto_sys::caps::CAP_SPAWN_DETACHED
                | (own_caps & moto_sys::caps::PARENT_OWNED_CAPS)
                | role_cap
        ),
    );
    for assignment in &assignments {
        let (name, value) = assignment.split_once('=').unwrap();
        command.env(name, value);
    }
    command.stdin(std::process::Stdio::piped());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    command.current_dir(USER_HOME);

    for arg in &words[1..] {
        command.arg(*arg);
    }

    match command.spawn() {
        Ok(mut child) => {
            let exit_notifier = Arc::new(AtomicBool::new(false));

            // stdin
            let exit1 = exit_notifier.clone();
            let (this_h, that_h) =
                moto_sys::SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0).unwrap();

            let mut child_stdin = child.stdin.take().unwrap();
            let input_output = output.clone();
            let input_forwarder = forwarder.clone();
            let stdin_thread = std::thread::spawn(move || {
                let mut drain = kernel_log::KernelLogDrain::new();
                let route_kernel = |record: Vec<u8>, synthetic_warning: bool| {
                    let Some(forwarder) = input_forwarder.as_ref() else {
                        return input_output.try_send_kernel(record);
                    };
                    let console = forwarder::console_eligible(&record, synthetic_warning);
                    if console {
                        let _ = forwarder.offer(record.clone());
                        input_output.try_send_kernel(record)
                    } else {
                        match forwarder.offer(record) {
                            Ok(()) => true,
                            Err(record) => input_output.try_send_kernel(record),
                        }
                    }
                };
                let mut service_input = || {
                    while let Some(c) = serial::read_serial() {
                        if c != 13 {
                            child_stdin.write_all(&[c]).ok();
                        } else {
                            child_stdin.write_all(&[c, 10]).ok();
                        }
                    }
                };

                loop {
                    if exit1.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut waiters: [SysHandle; 2] = [console_wait_handle, that_h];
                    SysCpu::wait(&mut waiters, SysHandle::NONE, SysHandle::NONE, None).unwrap();

                    let status = drain.drain(kernel_log_buf, &kernel_log_control, &route_kernel);
                    if status == kernel_log::DrainStatus::Busy {
                        service_input();
                        let _ = drain.drain(kernel_log_buf, &kernel_log_control, &route_kernel);
                    } else {
                        service_input();
                    }
                }

                SysObj::put(that_h).unwrap();
            });

            output.attach(child.stdout.take().unwrap(), child.stderr.take().unwrap());
            let status = child.wait();
            if let Err(err) = &status {
                // The child may still run and hold its pipes open, so the drain
                // below may never finish: say so first.
                output.send_fmt(
                    Source::Stderr,
                    format_args!("Error waiting for '{}': {:?}\n", fname, err),
                );
            }
            exit_notifier.store(true, Ordering::Release);
            SysCpu::wake(this_h).ok();
            SysObj::put(this_h).unwrap();
            stdin_thread.join().unwrap();
            // The exit status follows everything the child wrote.
            output.drain();
            if let Ok(status) = status
                && !status.success()
            {
                match status.code() {
                    Some(code) => output.send_fmt(
                        Source::Stderr,
                        format_args!("'{}' exited with status {}.\n", fname, code),
                    ),
                    None => output.send_fmt(Source::Stderr, format_args!("'{}' failed.\n", fname)),
                }
            }
        }
        Err(err) => output.send_fmt(
            Source::Stderr,
            format_args!("Error spawning '{}': {:?}\n", fname, err),
        ),
    }
    output.drain();
}
