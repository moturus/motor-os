mod dispatcher;
mod driver;
mod filesystem;
mod fs_flatfs;
mod fs_srfs;
pub mod mbr;
mod runtime;

pub use filesystem::*;
const DRIVER_URL: &str = "motor-fs-driver";

pub static STARTED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub fn init() {
    filesystem::init();
    set_temp_dir();
    dispatcher::start();
    while STARTED.load(std::sync::atomic::Ordering::Relaxed) == 0 {
        moto_rt::futex::futex_wait(&STARTED, 0, None);
    }
    #[cfg(debug_assertions)]
    crate::moto_log!("FS initialized");
}

fn set_temp_dir() {
    let dir = std::env::temp_dir();
    assert!(
        dir.is_absolute(),
        "Temp dir '{}' must be absolute.",
        dir.as_path().to_str().unwrap()
    );
    let dirname = dir.to_str().unwrap();

    if let Ok(_attr) = filesystem::fs().stat(dirname) {
        filesystem::fs()
            .delete_dir_all(dirname)
            .expect("Failed to delete the temp dir.");
    }

    // Read-only FS can't create dirs, so we ignore errors.
    let _ = filesystem::fs().mkdir(dirname);
}
