#![allow(internal_features)]
#![feature(addr_parse_ascii)]
#![feature(core_intrinsics)]
#![feature(io_error_more)]

mod fs;
mod logger;
mod net;
mod rt_vdso;
mod runtime;
mod virtio;

extern crate alloc;

#[macro_export]
macro_rules! moto_log {
    ($($arg:tt)*) => {
        {
            // Note: don't do file!()/line!() here because it is done in logger.rs.
            moto_sys::SysRay::log(alloc::format!($($arg)*).as_str()).ok();
        }
    };
}

fn _log_to_cloud_hypervisor(c: u8) {
    unsafe {
        core::arch::asm!(
            "out 0x80, al",
            in("al") c,
            options(nomem, nostack, preserves_flags)
        )
    };
}

#[no_mangle]
pub extern "C" fn moturus_has_proc_data() -> u8 {
    0
}

#[no_mangle]
pub extern "C" fn moturus_runtime_start() {
    let _ = logger::init();
    rt_vdso::load();
    runtime::init();
    virtio::init();
    // We need to initialize FS before Rust runtime is initialized (Rust runtime != sys-io runtime).
    fs::init();
}

fn main() {
    runtime::start();

    let mut cmd = std::process::Command::new("/sys/sys-init");

    // Init deals with stdio.
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());

    cmd.current_dir("/");

    // Give init the full caps.
    cmd.env(moto_sys::caps::MOTURUS_CAPS_ENV_KEY, "0xffffffffffffffff");

    // Run.
    cmd.spawn()
        .expect("Error starting sys-init: ")
        .wait()
        .unwrap();
    #[cfg(debug_assertions)]
    moto_sys::SysRay::log("sys-io exiting").ok();
}
