use alloc::string::String;
use alloc::vec::Vec;
use moto_sys::syscalls::*;
use moto_sys::ErrorCode;

pub fn args() -> alloc::vec::Vec<&'static str> {
    unsafe {
        match crate::rt_api::process::ProcessData::get() {
            Some(pd) => pd
                .args()
                .into_iter()
                .map(|bytes| core::str::from_utf8(bytes).unwrap())
                .collect(),
            None => alloc::vec![],
        }
    }
}

pub(super) unsafe fn create_remote_args(
    address_space: SysHandle,
    args1: &Vec<String>,
    args2: &Vec<String>,
    skip_empty: bool,
) -> Result<u64, ErrorCode> {
    let mut needed_len: u32 = 4; // Args num.
    let mut num_args = 0_u32;

    let mut calc_lengths = |arg: &str| {
        needed_len += 4;
        needed_len += ((arg.len() as u32) + 3) & !3_u32;
        num_args += 1;
    };

    for arg in args1 {
        if arg.len() == 0 && skip_empty {
            continue;
        }
        calc_lengths(arg.as_str());
    }

    for arg in args2 {
        if arg.len() == 0 && skip_empty {
            continue;
        }
        calc_lengths(arg.as_str());
    }

    if num_args == 0 {
        return Ok(0);
    }

    let page_size = SysMem::PAGE_SIZE_SMALL as u32;
    needed_len = (needed_len + page_size - 1) & !(page_size - 1);
    let num_pages = needed_len >> SysMem::PAGE_SIZE_SMALL_LOG2;

    let (remote, local) = SysMem::map2(
        address_space,
        SysMem::F_SHARE_SELF | SysMem::F_READABLE,
        u64::MAX,
        u64::MAX,
        SysMem::PAGE_SIZE_SMALL,
        num_pages as u64,
    )?;

    let mut pos = local as usize;
    *((pos as *mut u32).as_mut().unwrap()) = num_args;
    pos += 4;

    let mut write_arg = |arg: &str| {
        *((pos as *mut u32).as_mut().unwrap()) = arg.len() as u32;
        pos += 4;

        let bytes = arg.as_bytes();
        core::intrinsics::copy_nonoverlapping(bytes.as_ptr(), pos as *mut u8, bytes.len());
        pos += (bytes.len() + 3) & !3_usize;
    };

    for arg in args1 {
        if arg.len() == 0 && skip_empty {
            continue;
        }
        write_arg(arg.as_str());
    }

    for arg in args2 {
        if arg.len() == 0 && skip_empty {
            continue;
        }
        write_arg(arg.as_str());
    }

    SysMem::unmap(SysHandle::SELF, 0, u64::MAX, local).unwrap();
    Ok(remote)
}
