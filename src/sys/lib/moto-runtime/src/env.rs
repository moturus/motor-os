use crate::mutex::Mutex;
use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use moto_sys::syscalls::*;
use moto_sys::ErrorCode;

pub(super) unsafe fn create_remote_env(
    address_space: SysHandle,
    env: Vec<(String, String)>,
) -> Result<u64, ErrorCode> {
    let mut flat_vec = Vec::new();
    for (k, v) in env {
        if k.is_empty() {
            continue;
        }
        flat_vec.push(k);
        flat_vec.push(v);
    }

    super::args::create_remote_args(address_space, &Vec::new(), &flat_vec, false)
}

struct EnvRt {
    pointer: *mut BTreeMap<String, String>,
}

unsafe impl Send for EnvRt {}
unsafe impl Sync for EnvRt {}

impl EnvRt {
    const fn new() -> Self {
        Self {
            pointer: core::ptr::null_mut(),
        }
    }

    fn get_all() -> Vec<(String, String)> {
        Self::ensure_init();

        let env = ENV.lock();
        let map = unsafe { env.pointer.as_ref().unwrap_unchecked() };

        let mut result = alloc::vec![];

        for (k, v) in map.iter() {
            result.push((k.clone(), v.clone()))
        }

        result
    }

    fn get(key: &str) -> Option<String> {
        Self::ensure_init();

        let env = ENV.lock();
        let map = unsafe { env.pointer.as_ref().unwrap_unchecked() };
        map.get(key).map(|s| s.clone())
    }

    fn set(key: &str, val: &str) {
        Self::ensure_init();

        let env = ENV.lock();
        let map = unsafe { env.pointer.as_mut().unwrap_unchecked() };
        map.insert(key.to_owned(), val.to_owned());
    }

    fn unset(key: &str) {
        Self::ensure_init();

        let env = ENV.lock();
        let map = unsafe { env.pointer.as_mut().unwrap_unchecked() };
        map.remove(key);
    }

    fn ensure_init() {
        let mut env = ENV.lock();

        if !env.pointer.is_null() {
            return;
        }

        use alloc::boxed::Box;

        env.pointer = Box::leak(Box::new(BTreeMap::new()));
        unsafe {
            let map = env.pointer.as_mut().unwrap_unchecked();
            match crate::rt_api::process::ProcessData::get() {
                Some(pd) => {
                    for (k, v) in pd.env().into_iter() {
                        map.insert(
                            core::str::from_utf8(k).unwrap().to_owned(),
                            core::str::from_utf8(v).unwrap().to_owned(),
                        );
                    }
                }
                None => {}
            }
        }
    }
}

static ENV: Mutex<EnvRt> = Mutex::new(EnvRt::new());

pub fn env() -> alloc::vec::Vec<(String, String)> {
    EnvRt::get_all()
}

pub fn getenv(key: &str) -> Option<String> {
    EnvRt::get(key)
}

pub fn setenv(key: &str, val: &str) {
    EnvRt::set(key, val);
}

pub fn unsetenv(key: &str) {
    EnvRt::unset(key)
}
