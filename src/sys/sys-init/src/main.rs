use std::process::Stdio;

use moto_sys::*;
use sys_init::{process_service_line, process_tty_line, TtyRole};

#[derive(Debug)]
struct Config {
    pub tty: String,
    pub tty_role: TtyRole,
    pub strobe: Option<String>,
    pub services: Vec<(u64, String)>,
}

fn process_config() -> Result<Config, String> {
    let cfg_data = std::fs::read_to_string("/system/cfg/sys-init.cfg")
        .expect("Error loading /system/cfg/sys-init.cfg");

    let mut tty = None;
    let mut strobe = None;
    let mut services = vec![];

    let mut curr_line = 0_u32;
    for mut line in cfg_data.lines() {
        curr_line += 1;

        line = line.trim();

        if line.is_empty() {
            continue;
        }

        if let Some(cap_cmd) = line.strip_prefix("svc:") {
            services.push(process_service_line(cap_cmd).map_err(|reason| {
                format!("'/system/cfg/sys-init.cfg': bad service at line {curr_line}: {reason}")
            })?);
        } else if let Some(value) = line.strip_prefix("tty:") {
            tty = Some(process_tty_line(value).map_err(|reason| {
                format!("'/system/cfg/sys-init.cfg': bad tty at line {curr_line}: {reason}")
            })?);
        } else if let Some(file) = line.strip_prefix("strobe:") {
            strobe = Some(file.to_owned());
        } else if line.as_bytes()[0] == b'#' {
            continue;
        } else {
            return Err(format!("'/system/cfg/sys-init.cfg': bad line {curr_line}"));
        }
    }

    if tty.is_none() {
        return Err("'/system/cfg/sys-init.cfg' must contain 'tty:<filename>' line".to_owned());
    }

    let (tty_role, tty) = tty.unwrap();
    let config = Config {
        tty,
        tty_role,
        strobe,
        services,
    };

    Ok(config)
}

fn main() {
    #[cfg(debug_assertions)]
    SysRay::log("sys-init started").ok();

    assert_eq!(
        moto_sys::caps::CAP_SYS,
        moto_sys::ProcessStaticPage::get().capabilities & moto_sys::caps::CAP_SYS
    );

    let config = match process_config() {
        Ok(c) => c,
        Err(msg) => {
            log::error!("sys-init: {msg}");
            SysRay::log(format!("sys-init: {msg}").as_str()).unwrap();
            std::process::exit(1);
        }
    };

    // sys-tty first: the console is what the user waits for, and it needs
    // strobe only for kernel-log forwarding, which retries on its own. Then
    // strobe, then the services, which log to it from the start.
    let role_cap = match config.tty_role {
        TtyRole::System => moto_sys::caps::CAP_SYS,
        TtyRole::Interactive => moto_sys::caps::CAP_INTERACTIVE,
        TtyRole::None => 0,
    };
    let tty_caps = moto_sys::caps::CAP_IO_MANAGER
        | moto_sys::caps::CAP_SPAWN
        | moto_sys::caps::CAP_LOG
        | moto_sys::caps::CAP_SPAWN_DETACHED
        | role_cap;
    let mut tty = std::process::Command::new(config.tty.as_str())
        .env(
            moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
            format!("0x{tty_caps:x}"),
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    if let Some(strobe) = &config.strobe {
        // We just spawn strobe, don't track/wait. Should we?
        #[allow(clippy::zombie_processes)]
        let _ = std::process::Command::new(strobe.as_str())
            .env(
                moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
                format!("0x{:x}", moto_sys::caps::CAP_SYS | moto_sys::caps::CAP_LOG),
            )
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap_or_else(|_| panic!("Error spawning {strobe}"));

        // The log server listens within a millisecond of starting: retry
        // right away rather than sleeping between attempts.
        let log_start = std::time::Instant::now();
        loop {
            if moto_log::init("sys-init").is_ok() {
                log::info!("Started strobe in {} us.", log_start.elapsed().as_micros());
                break;
            }
            if log_start.elapsed() > std::time::Duration::from_secs(5) {
                SysRay::log("sys-init: failed to initialize logging").unwrap();
                std::process::exit(1);
            }
            std::thread::yield_now();
        }
        log::set_max_level(log::LevelFilter::Info);
    }

    if !config.services.is_empty() {
        let services = config.services;
        std::thread::spawn(move || {
            for (caps, cmd) in services {
                spawn_service(caps, cmd.as_str());
            }
        });
    }

    tty.wait().unwrap();
    log::info!("tty stopped. Shutting down.");

    #[cfg(debug_assertions)]
    let _ = moto_sys::SysRay::log("tty stopped. Shutting down.");
}

fn spawn_service(caps: u64, cmd: &str) {
    log::info!("Starting service '{cmd}'.");

    let Ok(words) = shell_words::split(cmd) else {
        let _ = SysRay::log(format!("sys-init: bad command'{cmd}'").as_str());
        std::process::exit(1);
    };

    let mut command = std::process::Command::new(&words[0]);
    command.args(&words[1..]);

    command.env(moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY, format!("0x{caps:x}"));

    let _child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .inspect_err(|e| {
            let _ = SysRay::log(format!("sys-init: bad command '{cmd}': {e:?}").as_str());
            std::process::exit(1);
        });

    log::info!("Started service '{cmd}'; capabilities: 0x{caps:x}.");
}
