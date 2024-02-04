pub use moto_sys::CUSTOM_USERSPACE_REGION_END;
pub use moto_sys::CUSTOM_USERSPACE_REGION_START;

use alloc::vec::Vec;

#[repr(C)]
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

#[cfg(feature = "rustc-dep-of-std")]
#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn moturus_has_proc_data() -> u8 {
    1
}

#[cfg(not(feature = "rustc-dep-of-std"))]
extern "C" {
    #[linkage = "extern_weak"]
    fn moturus_has_proc_data() -> u8;
}

impl ProcessData {
    pub const ADDR: u64 = moto_sys::CUSTOM_USERSPACE_REGION_START;

    pub unsafe fn get() -> Option<&'static ProcessData> {
        if moturus_has_proc_data() == 1 {
            let ptr: *const ProcessData = Self::ADDR as *const ProcessData;
            Some(ptr.as_ref().unwrap())
        } else {
            None
        }
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

pub fn binary() -> Option<&'static str> {
    unsafe {
        if let Some(pd) = ProcessData::get() {
            let args = pd.args();
            if args.len() > 0 {
                return core::str::from_utf8(args[0]).ok();
            }
        }
    }

    None
}
