mod dispatcher;
mod driver;
mod filesystem;
mod fs_flatfs;
mod fs_srfs;
mod mbr;

pub use filesystem::*;
const DRIVER_URL: &str = "moturus-fs-driver";

pub static STARTED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub fn init() {
    filesystem::init();
    set_temp_dir();
    dispatcher::start().unwrap();
    while STARTED.load(std::sync::atomic::Ordering::Relaxed) == 0 {
        moto_runtime::futex_wait(&STARTED, 0, None);
    }
    #[cfg(debug_assertions)]
    crate::moto_log!("FS initialized");
}

fn set_temp_dir() {
    let dir = std::env::temp_dir();
    let dirname = dir.to_str().unwrap();

    if let Ok(_attr) = filesystem::fs().stat(dirname) {
        filesystem::fs().delete_dir(dirname).unwrap();
    }

    // Read-only FS can't create dirs, so we ignore errors.
    let _ = filesystem::fs().mkdir(dirname);
}
