use std::process::Stdio;

use moto_sys::*;

#[derive(Debug)]
struct Config {
    pub tty: String,
    pub log: Option<String>,
    pub services: Vec<(u64, String)>,
}

fn process_config() -> Result<Config, String> {
    let cfg_data = std::fs::read_to_string("/sys/cfg/sys-init.cfg")
        .expect("Error loading /sys/cfg/sys-init.cfg");

    let mut tty = None;
    let mut log = None;
    let mut services = vec![];

    let mut curr_line = 0_u32;
    for mut line in cfg_data.lines() {
        curr_line += 1;

        line = line.trim();

        if line.is_empty() {
            continue;
        }

        if let Some(cap_cmd) = line.strip_prefix("svc:") {
            services.push(process_service_line(cap_cmd));
        } else if let Some(file) = line.strip_prefix("tty:") {
            tty = Some(file.to_owned());
        } else if let Some(file) = line.strip_prefix("log:") {
            log = Some(file.to_owned());
        } else if line.as_bytes()[0] == b'#' {
            continue;
        } else {
            return Err(format!("'/sys/cfg/sys-init.cfg': bad line {curr_line}"));
        }
    }

    if tty.is_none() {
        return Err("'/sys/cfg/sys-init.cfg' must contain 'tty:<filename>' line".to_owned());
    }

    let config = Config {
        tty: tty.unwrap(),
        log,
        services,
    };

    Ok(config)
}

fn main() {
    #[cfg(debug_assertions)]
    SysRay::log("sys-init started").ok();

    assert_eq!(
        1,
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

    // First spawn sys-log, then services, then sys-tty.

    if let Some(log) = &config.log {
        // We just spawn sys-log, don't track/wait. Should we?
        #[allow(clippy::zombie_processes)]
        let _ = std::process::Command::new(log.as_str())
            .env(
                moto_sys::caps::MOTURUS_CAPS_ENV_KEY,
                format!("0x{:x}", moto_sys::caps::CAP_LOG),
            )
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap_or_else(|_| panic!("Error spawning {log}"));

        // The logserver has just started. It needs time to start
        // listening, so we need to retry a few times.
        let log_start = std::time::Instant::now();
        loop {
            std::thread::sleep(std::time::Duration::from_millis(1));
            let elapsed = log_start.elapsed().as_millis();
            if elapsed > 5_000 {
                SysRay::log("sys-init: failed to initialize logging").unwrap();
                std::process::exit(1);
            }
            if moto_log::init("sys-init").is_ok() {
                log::info!("Started sys-log in {elapsed} ms.");
                break;
            }
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

    let mut tty = std::process::Command::new(config.tty.as_str())
        .env(moto_sys::caps::MOTURUS_CAPS_ENV_KEY, "0xffffffffffffffff")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    log::info!("Started tty.");
    tty.wait().unwrap();
    log::info!("tty stopped. Shutting down.");

    #[cfg(debug_assertions)]
    let _ = moto_sys::SysRay::log("tty stopped. Shutting down.");
}

fn process_service_line(cap_cmd: &str) -> (u64, String) {
    let Some(pos) = cap_cmd.find(':') else {
        return (0, cap_cmd.to_owned());
    };

    let (caps, cmd) = cap_cmd.split_at(pos);
    if cmd.is_empty() {
        let _ = SysRay::log(format!("sys-init: bad service definition '{cap_cmd}'").as_str());
        std::process::exit(1);
    }

    let cmd = cmd[1..].trim();
    if cmd.is_empty() {
        let _ = SysRay::log(format!("sys-init: bad service definition '{cap_cmd}'").as_str());
        std::process::exit(1);
    }

    let Ok(caps) = caps.parse() else {
        let _ = SysRay::log(format!("sys-init: bad service definition '{cap_cmd}'").as_str());
        std::process::exit(1);
    };

    (caps, cmd.to_owned())
}

fn spawn_service(caps: u64, cmd: &str) {
    let Ok(words) = shell_words::split(cmd) else {
        let _ = SysRay::log(format!("sys-init: bad command'{cmd}'").as_str());
        std::process::exit(1);
    };

    let mut command = std::process::Command::new(&words[0]);
    command.args(&words[1..]);

    if caps != 0 {
        command.env(moto_sys::caps::MOTURUS_CAPS_ENV_KEY, format!("0x{caps:x}"));
    }

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
