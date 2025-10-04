#![allow(internal_features)]
#![feature(addr_parse_ascii)]
#![feature(async_iterator)]
#![feature(core_intrinsics)]
#![feature(io_error_more)]
#![feature(local_waker)]

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
pub extern "C" fn motor_has_proc_data() -> u8 {
    0
}

#[no_mangle]
pub extern "C" fn motor_runtime_start() {
    // Can't panic before vdso has been loaded.
    let _ = logger::init();
    rt_vdso::load();

    // As we don't have stderr, install a custom panic hook to log to kernel.
    std::panic::set_hook(Box::new(|info| {
        std::thread::sleep(std::time::Duration::from_millis(10));
        log::error!("{info}");
        moto_sys::SysCpu::exit(0xbadc0de)
    }));

    runtime::init(); // Allocates the 2M page for PCI/VirtIO mappings.

    // This block is for development/testing only, until ready.
    /*
    #[cfg(debug_assertions)]
    {
        runtime::spawn_async();
        std::thread::sleep(std::time::Duration::from_millis(100));

        panic!("let's not go there");
    }
    */

    virtio::init();
    // We need to initialize FS before Rust runtime is initialized (Rust runtime != sys-io runtime).
    fs::init();
}

fn main() {
    // #[cfg(debug_assertions)]
    // async_runtime::start();

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
