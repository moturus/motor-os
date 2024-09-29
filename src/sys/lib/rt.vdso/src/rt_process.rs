use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub unsafe extern "C" fn args() -> u64 {
    let args: Vec<String> = unsafe {
        ProcessData::get()
            .args()
            .into_iter()
            .map(|bytes| core::str::from_utf8(bytes).unwrap().to_owned())
            .collect()
    };

    encode_args(args)
}

pub unsafe extern "C" fn get_full_env() -> u64 {
    let (keys, vals) = EnvRt::get_all();
    encode_env(keys, vals)
}

pub unsafe extern "C" fn getenv(key_ptr: *const u8, key_len: usize) -> u64 {
    assert!(key_len <= moto_rt::process::MAX_ENV_KEY_LEN);
    let key_bytes = unsafe { core::slice::from_raw_parts(key_ptr, key_len) };
    let key = unsafe { core::str::from_utf8_unchecked(key_bytes) };

    match EnvRt::get(key) {
        Some(val) => {
            if val.is_empty() {
                0
            } else {
                let val = val.as_bytes();
                let ptr = crate::rt_alloc::sys_alloc(val.len() + 4);
                if ptr.is_null() {
                    panic!("sys_alloc {} bytes failed.", val.len() + 4);
                }
                unsafe {
                    let plen: *mut u32 = ptr as usize as *mut u32;
                    *plen = val.len() as u32;
                    let pval = (ptr as usize + 4) as *mut u8;
                    core::ptr::copy_nonoverlapping(val.as_ptr(), pval, val.len());
                }
                ptr as usize as u64
            }
        }
        None => u64::MAX,
    }
}

pub unsafe extern "C" fn setenv(
    key_ptr: *const u8,
    key_len: usize,
    val_ptr: usize,
    val_len: usize,
) {
    assert!(key_len <= moto_rt::process::MAX_ENV_KEY_LEN);
    let key_bytes = unsafe { core::slice::from_raw_parts(key_ptr, key_len) };
    let key = unsafe { core::str::from_utf8_unchecked(key_bytes) };

    if val_len == 0 {
        EnvRt::set(key, "");
    } else if val_len == usize::MAX {
        EnvRt::unset(key);
    } else {
        assert!(val_len <= moto_rt::process::MAX_ENV_VAL_LEN);
        unsafe {
            let val_ptr = val_ptr as *const u8;
            let val = core::slice::from_raw_parts(val_ptr, val_len);
            EnvRt::set(key, core::str::from_utf8(val).unwrap());
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct StdioData {
    pub pipe_addr: u64,
    pub pipe_size: u64,
    pub handle: u64,
}

#[repr(C)]
pub struct ProcessData {
    pub version: u64,

    // Stdio.
    pub stdin: StdioData,
    pub stdout: StdioData,
    pub stderr: StdioData,
    pub args: u64, // Command line arguments. See impl below.
    pub env: u64,  // Environment variables. See impl below.
}

#[doc(hidden)]
impl ProcessData {
    const ADDR: u64 = moto_rt::MOTO_SYS_CUSTOM_USERSPACE_REGION_START;

    pub fn get() -> &'static ProcessData {
        let ptr: *const ProcessData = Self::ADDR as *const ProcessData;
        unsafe { ptr.as_ref().unwrap() }
    }

    unsafe fn deserialize_vec(addr: u64) -> Vec<&'static [u8]> {
        assert_ne!(addr, 0);
        // first four bytes: the number of arguments;
        // then arguments, aligned at four bytes: size (four bytes), bytes.

        let mut pos = addr as usize;
        assert_eq!(pos & 3, 0);

        let num_args = *((pos as *const u32).as_ref().unwrap());
        pos += 4;

        let mut result = Vec::new();
        for _i in 0..num_args {
            let len = *((pos as *const u32).as_ref().unwrap());
            pos += 4;
            let bytes: &[u8] = core::slice::from_raw_parts(pos as *const u8, len as usize);
            result.push(bytes);
            pos += len as usize;
            pos = (pos + 3) & !3; // Align up to 4 bytes.
        }

        result
    }

    pub unsafe fn args(&self) -> Vec<&[u8]> {
        if self.args == 0 {
            return Vec::new();
        }

        Self::deserialize_vec(self.args)
    }

    pub unsafe fn env(&self) -> Vec<(&[u8], &[u8])> {
        if self.env == 0 {
            return Vec::new();
        }

        let raw_vec = Self::deserialize_vec(self.env);
        assert_eq!(0, raw_vec.len() & 1);

        let mut result = Vec::new();
        for idx in 0..(raw_vec.len() >> 1) {
            result.push((raw_vec[2 * idx], raw_vec[2 * idx + 1]));
        }

        result
    }
}

// Note: we use a pointer to minimize static size; we don't really care
// about performance here, and use a mutex to avoid races.
pub(crate) struct EnvRt {
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

    fn get_all() -> (Vec<String>, Vec<String>) {
        Self::ensure_init();

        let env = ENV.lock();
        let map = unsafe { env.pointer.as_ref().unwrap_unchecked() };

        let mut keys = alloc::vec![];
        let mut vals = alloc::vec![];

        for (k, v) in map.iter() {
            keys.push(k.clone());
            vals.push(v.clone());
        }

        (keys, vals)
    }

    pub(crate) fn get(key: &str) -> Option<String> {
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
            let pd = ProcessData::get();
            for (k, v) in pd.env().into_iter() {
                map.insert(
                    core::str::from_utf8(k).unwrap().to_owned(),
                    core::str::from_utf8(v).unwrap().to_owned(),
                );
            }
        }
    }
}

static ENV: crate::util::mutex::Mutex<EnvRt> = crate::util::mutex::Mutex::new(EnvRt::new());

fn encode_env(keys: Vec<String>, vals: Vec<String>) -> u64 {
    assert_eq!(keys.len(), vals.len());

    let mut needed_len: u32 = 4; // Total num strings.
    let mut num_args = 0_u32;

    let mut calc_lengths = |arg: &str| {
        needed_len += 4;
        needed_len += ((arg.len() as u32) + 3) & !3_u32;
        num_args += 1;
    };

    for arg in &keys {
        calc_lengths(arg.as_str());
    }

    for arg in &vals {
        calc_lengths(arg.as_str());
    }

    if num_args == 0 {
        return 0;
    }

    let result_addr = crate::rt_alloc::sys_alloc(needed_len as usize) as usize;
    assert_ne!(result_addr, 0);

    unsafe {
        let mut pos = result_addr as usize;
        *((pos as *mut u32).as_mut().unwrap()) = num_args;
        pos += 4;

        let mut write_arg = |arg: &str| {
            *((pos as *mut u32).as_mut().unwrap()) = arg.len() as u32;
            pos += 4;

            let bytes = arg.as_bytes();
            core::intrinsics::copy_nonoverlapping(bytes.as_ptr(), pos as *mut u8, bytes.len());
            pos += (bytes.len() + 3) & !3_usize;
        };

        for arg in keys {
            write_arg(arg.as_str());
        }

        for arg in vals {
            write_arg(arg.as_str());
        }
    }

    result_addr as u64
}

fn encode_args(args: Vec<String>) -> u64 {
    let mut needed_len: u32 = 4; // Args num.
    let mut num_args = 0_u32;

    let mut calc_lengths = |arg: &str| {
        needed_len += 4;
        needed_len += ((arg.len() as u32) + 3) & !3_u32;
        num_args += 1;
    };

    for arg in &args {
        if arg.len() == 0 {
            continue;
        }
        calc_lengths(arg.as_str());
    }

    if num_args == 0 {
        return 0;
    }

    let result_addr = crate::rt_alloc::sys_alloc(needed_len as usize) as usize;
    assert_ne!(result_addr, 0);

    unsafe {
        let mut pos = result_addr;
        *((pos as *mut u32).as_mut().unwrap()) = num_args;
        pos += 4;

        let mut write_arg = |arg: &str| {
            *((pos as *mut u32).as_mut().unwrap()) = arg.len() as u32;
            pos += 4;

            let bytes = arg.as_bytes();
            core::intrinsics::copy_nonoverlapping(bytes.as_ptr(), pos as *mut u8, bytes.len());
            pos += (bytes.len() + 3) & !3_usize;
        };

        for arg in args {
            if arg.len() == 0 {
                continue;
            }
            write_arg(arg.as_str());
        }
    }

    result_addr as u64
}
