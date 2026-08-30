use core::slice;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use moto_sys::SysCpu;
use moto_sys::SysHandle;
use moto_sys::SysObj;
use moto_sys::SysRay;

use crate::output::{Output, Source};

mod output;
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

fn read_config(output: &Output) -> String {
    let config_path = "/system/cfg/sys-tty.cfg";
    match std::fs::read_to_string(std::path::Path::new(config_path)) {
        Ok(config) => config,
        Err(err) => {
            output.send_fmt(
                Source::Stderr,
                format_args!("sys-tty: error reading '{config_path}': {err:?}"),
            );
            std::process::exit(1);
        }
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--self-test") {
        output::run_self_tests();
        return;
    }

    let output = Output::start_serial_writer();
    let config = read_config(&output);
    let words: Vec<_> = config.split_whitespace().collect();

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
        output.send(Source::Stderr, b"sys-tty: error: empty config.".to_vec());
        std::process::exit(1);
    }

    let fname = words[0];

    let buf_addr = moto_sys::SysMem::alloc(4096, (SysRay::CONSOLE_SHARED_BUF_SZ / 4096) as u64)
        .unwrap() as usize;
    let kernel_log_buf =
        unsafe { slice::from_raw_parts_mut(buf_addr as *mut u8, SysRay::CONSOLE_SHARED_BUF_SZ) };

    let mut kernel_log_buf_offset: Box<AtomicUsize> = Box::new(AtomicUsize::new(0));
    let offset_addr = Box::as_mut_ptr(&mut kernel_log_buf_offset) as usize;

    let console_wait_handle = moto_sys::SysObj::get(
        SysHandle::KERNEL,
        0,
        format!("serial_console:{buf_addr}:{offset_addr}").as_str(),
    )
    .unwrap();

    let millis = moto_rt::time::since_system_start().as_millis();
    output.send_fmt(
        Source::Stdout,
        format_args!(
            "   ... all services up at {:03}ms. Starting {}.\n\n",
            millis, fname
        ),
    );

    let mut command = std::process::Command::new(fname);
    command.env_clear();
    command.env("HOME", USER_HOME);
    command.env(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true");
    let role_cap = match moto_sys::caps::ProcessRole::from_caps(
        moto_sys::ProcessStaticPage::get().capabilities,
    ) {
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
            let stdin_thread = std::thread::spawn(move || {
                let mut prev_offset = 0;
                loop {
                    if exit1.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut waiters: [SysHandle; 2] = [console_wait_handle, that_h];
                    SysCpu::wait(&mut waiters, SysHandle::NONE, SysHandle::NONE, None).unwrap();

                    while let Some(c) = serial::read_serial() {
                        if c != 13 {
                            child_stdin.write_all(&[c]).ok();
                        } else {
                            // Insert newline.
                            child_stdin.write_all(&[c, 10]).ok();
                        }
                    }

                    let offset = kernel_log_buf_offset.load(Ordering::Acquire);
                    if prev_offset != offset {
                        process_kernel_log(kernel_log_buf, prev_offset, offset, &input_output);
                        prev_offset = offset;
                    }
                }

                SysObj::put(that_h).unwrap();
            });

            // stdout
            let mut child_stdout = child.stdout.take().unwrap();
            let stdout_output = output.clone();
            let stdout_thread = std::thread::spawn(move || {
                use std::io::Read;
                let mut buf = [0_u8; 4096];
                loop {
                    match child_stdout.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(sz) => stdout_output.send(Source::Stdout, buf[..sz].to_vec()),
                    }
                }
            });

            let mut child_stderr = child.stderr.take().unwrap();
            let stderr_output = output.clone();
            let stderr_thread = std::thread::spawn(move || {
                use std::io::Read;
                let mut buf = [0_u8; 4096];
                loop {
                    match child_stderr.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(sz) => stderr_output.send(Source::Stderr, buf[..sz].to_vec()),
                    }
                }
            });
            match child.wait() {
                Ok(status) => {
                    if !status.success() {
                        match status.code() {
                            Some(code) => output.send_fmt(
                                Source::Stderr,
                                format_args!("'{}' exited with status {}.\n", fname, code),
                            ),
                            None => output
                                .send_fmt(Source::Stderr, format_args!("'{}' failed.\n", fname)),
                        }
                    }
                }
                Err(err) => output.send_fmt(
                    Source::Stderr,
                    format_args!("Error waiting for '{}': {:?}\n", fname, err),
                ),
            };
            exit_notifier.store(true, Ordering::Release);
            SysCpu::wake(this_h).ok();
            SysObj::put(this_h).unwrap();
            stdin_thread.join().unwrap();
            stdout_thread.join().unwrap();
            stderr_thread.join().unwrap();
        }
        Err(err) => output.send_fmt(
            Source::Stderr,
            format_args!("Error spawning '{}': {:?}\n", fname, err),
        ),
    }
}

fn process_kernel_log(kernel_log_buf: &[u8], prev_offset: usize, offset: usize, output: &Output) {
    assert!(offset > prev_offset);
    assert_eq!(kernel_log_buf.len(), SysRay::CONSOLE_SHARED_BUF_SZ);

    let len = offset - prev_offset;
    let start = prev_offset & (SysRay::CONSOLE_SHARED_BUF_SZ - 1);
    let end = start + len;

    let data = if end <= SysRay::CONSOLE_SHARED_BUF_SZ {
        kernel_log_buf[start..end].to_vec()
    } else {
        let wrapped_end = end & (SysRay::CONSOLE_SHARED_BUF_SZ - 1);
        let mut data = Vec::with_capacity(SysRay::CONSOLE_SHARED_BUF_SZ - start + wrapped_end);
        data.extend_from_slice(&kernel_log_buf[start..]);
        data.extend_from_slice(&kernel_log_buf[..wrapped_end]);
        data
    };
    output.try_send_kernel(data);
}
