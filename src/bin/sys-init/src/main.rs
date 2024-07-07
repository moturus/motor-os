use moto_runtime::moturus_log;

// use moto_sys::caps::{CAP_IO_MANAGER, CAP_LOG, CAP_SHARE, CAP_SPAWN};
use moto_sys::*;

#[no_mangle]
pub extern "C" fn moturus_log_panics_to_kernel() -> bool {
    // Normal binaries should log panics to their stderr. But sys-io, sys-tty, and sys-init
    // don't have stdio, so they will override this function to log via SysMem::log().
    true
}

#[derive(Debug)]
struct Config {
    pub tty: String,
    pub log: Option<String>,
}

fn process_config() -> Result<Config, String> {
    let cfg_data = std::fs::read_to_string("/sys/cfg/sys-init.cfg")
        .expect("Error loading /sys/cfg/sys-init.cfg");

    let mut tty = None;
    let mut log = None;

    let mut curr_line = 0_u32;
    for line in cfg_data.lines() {
        curr_line += 1;

        if line.trim().is_empty() {
            continue;
        }

        if let Some(file) = line.trim().strip_prefix("tty:") {
            tty = Some(file.to_owned());
        } else if let Some(file) = line.trim().strip_prefix("log:") {
            log = Some(file.to_owned());
        } else {
            return Err(format!("'/sys/cfg/sys-init.cfg': bad line {}", curr_line));
        }
    }

    if tty.is_none() {
        return Err("'/sys/cfg/sys-init.cfg' must contain 'tty:<filename>' line".to_owned());
    }

    let config = Config {
        tty: tty.unwrap(),
        log,
    };

    Ok(config)
}

fn main() {
    #[cfg(debug_assertions)]
    SysMem::log("sys-init started").ok();

    assert_eq!(
        1,
        moto_sys::ProcessStaticPage::get().capabilities & moto_sys::caps::CAP_SYS
    );

    let config = process_config();
    if let Err(msg) = config {
        log::error!("sys-init: {}", msg);
        SysMem::log(format!("sys-init: {}", msg).as_str()).unwrap();
        std::process::exit(1);
    }

    let config = config.unwrap();

    if let Some(log) = &config.log {
        std::process::Command::new(log.as_str())
            .env(
                moto_sys::caps::MOTURUS_CAPS_ENV_KEY,
                format!("0x{:x}", moto_sys::caps::CAP_LOG),
            )
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect(format!("Error spawning {}", log).as_str());

        // The logserver has just started. It needs time to start
        // listening, so we need to retry a few times.
        let log_start = std::time::Instant::now();
        loop {
            std::thread::sleep(std::time::Duration::from_millis(1));
            if log_start.elapsed().as_secs() > 5 {
                SysMem::log("sys-init: failed to initialize logging").unwrap();
                std::process::exit(1);
            }
            if moto_log::init("sys-init").is_ok() {
                break;
            }
        }
        log::set_max_level(log::LevelFilter::Info);
    }

    let mut tty = std::process::Command::new(config.tty.as_str())
        .env(moto_sys::caps::MOTURUS_CAPS_ENV_KEY, "0xffffffffffffffff")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    tty.wait().unwrap();

    moturus_log!("tty stopped. Shutting down.");
}
