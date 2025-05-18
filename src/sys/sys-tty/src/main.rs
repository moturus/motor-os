use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use moto_sys::SysCpu;
use moto_sys::SysHandle;
use moto_sys::SysObj;

use crate::serial::write_serial_raw;

mod serial;

fn _putc(c: u8) {
    serial::write_serial_raw(std::slice::from_ref(&c));
}

fn read_config() -> String {
    let config_path = "/sys/cfg/sys-tty.cfg";
    match std::fs::read_to_string(std::path::Path::new(config_path)) {
        Ok(config) => config,
        Err(err) => {
            moto_sys::SysRay::log(format!("Error reading '{}': {:?}", config_path, err).as_str())
                .ok();
            std::process::exit(1);
        }
    }
}

fn main() {
    #[cfg(debug_assertions)]
    moto_sys::SysRay::log("sys-tty started").ok();
    moto_log::init("sys-tty").unwrap();

    log::set_max_level(log::LevelFilter::Trace);
    #[cfg(debug_assertions)]
    log::debug!("sys-tty started");

    let config = read_config();
    let words: Vec<_> = config.split_whitespace().collect();

    if words.is_empty() {
        moto_sys::SysRay::log("Error: empty config.").ok();
        std::process::exit(1);
    }

    let fname = words[0];
    let millis = moto_rt::time::since_system_start().as_millis();
    crate::serial::write_serial!(
        "   ... all services up at {:03}ms. Starting {}.\n\n",
        millis,
        fname
    );

    let console_wait_handle =
        moto_sys::SysObj::get(SysHandle::KERNEL, 0, "serial_console").unwrap();
    let mut command = std::process::Command::new(fname);
    command.env_clear();
    command.env(moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY, "true");
    command.stdin(std::process::Stdio::piped());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    command.current_dir("/");

    for arg in &words.as_slice()[1..] {
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
            let stdin_thread = std::thread::spawn(move || {
                loop {
                    if exit1.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut waiters: [SysHandle; 2] = [console_wait_handle, that_h];
                    SysCpu::wait(&mut waiters, SysHandle::NONE, SysHandle::NONE, None).unwrap();

                    while let Some(c) = serial::read_serial() {
                        if c == 3 {
                            write_serial_raw(b"^C");
                        }
                        if c != 13 {
                            child_stdin.write_all(&[c]).ok();
                        } else {
                            // Insert newline.
                            child_stdin.write_all(&[c, 10]).ok();
                        }
                    }
                }

                SysObj::put(that_h).unwrap();
            });

            // stdout
            let exit2 = exit_notifier.clone();
            let mut child_stdout = child.stdout.take().unwrap();
            let stdout_thread = std::thread::spawn(move || {
                let mut buf = [0_u8; 80];
                while !exit2.load(Ordering::Relaxed) {
                    use std::io::Read;
                    if let Ok(sz) = child_stdout.read(&mut buf) {
                        if sz > 0 {
                            write_serial_raw(&buf[0..sz]);
                        }
                    } else {
                        break;
                    }
                }
            });
            let exit3 = exit_notifier.clone();
            let mut child_stderr = child.stderr.take().unwrap();
            let stderr_thread = std::thread::spawn(move || {
                let mut buf = [0_u8; 80];
                while !exit3.load(Ordering::Relaxed) {
                    use std::io::Read;
                    if let Ok(sz) = child_stderr.read(&mut buf) {
                        write_serial_raw(&buf[0..sz]);
                    } else {
                        break;
                    }
                }
            });
            match child.wait() {
                Ok(status) => {
                    if !status.success() {
                        match status.code() {
                            Some(code) => {
                                write_serial!("'{}' exited with status {}.\n", fname, code)
                            }
                            None => write_serial!("'{}' failed.\n", fname),
                        }
                    }
                }
                Err(err) => write_serial!("Error waiting for '{}': {:?}\n", fname, err),
            };
            exit_notifier.store(true, Ordering::Release);
            SysCpu::wake(this_h).ok();
            SysObj::put(this_h).unwrap();
            stdin_thread.join().unwrap();
            stdout_thread.join().unwrap();
            stderr_thread.join().unwrap();
        }
        Err(err) => write_serial!("Error spawning '{}': {:?}\n", fname, err),
    }
}
