use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use moto_rt::ErrorCode;
use moto_rt::RtFd;

pub unsafe extern "C" fn args() -> u64 {
    let args: Vec<String> = unsafe {
        ProcessData::get()
            .args()
            .into_iter()
            .map(|bytes| core::str::from_utf8(bytes).unwrap().to_owned())
            .collect()
    };

    encode_args(args).unwrap()
}

pub unsafe extern "C" fn get_full_env() -> u64 {
    let (keys, vals) = EnvRt::get_all();
    encode_env(keys, vals).unwrap()
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

pub extern "C" fn kill(handle: u64) -> moto_rt::ErrorCode {
    match moto_sys::SysCpu::kill(handle.into()) {
        Ok(()) => moto_rt::E_OK,
        Err(err) => err,
    }
}

pub unsafe extern "C" fn ctrl_c_register_handler(sequence: *mut u64) -> moto_rt::ErrorCode {
    let Some(sequence) = (unsafe { sequence.as_mut() }) else {
        return moto_rt::E_INVALID_ARGUMENT;
    };
    match crate::stdio::ctrl_c_register_handler() {
        Ok(value) => {
            *sequence = value;
            moto_rt::E_OK
        }
        Err(err) => err,
    }
}

pub unsafe extern "C" fn ctrl_c_wait(last: u64, sequence: *mut u64) -> moto_rt::ErrorCode {
    let Some(sequence) = (unsafe { sequence.as_mut() }) else {
        return moto_rt::E_INVALID_ARGUMENT;
    };
    match crate::stdio::ctrl_c_wait(last) {
        Ok(value) => {
            *sequence = value;
            moto_rt::E_OK
        }
        Err(err) => err,
    }
}

pub extern "C" fn wait(handle: u64) -> moto_rt::ErrorCode {
    loop {
        match moto_sys::SysCpu::wait(
            &mut [handle.into()],
            moto_sys::SysHandle::NONE,
            moto_sys::SysHandle::NONE,
            None,
        ) {
            Ok(()) => match moto_sys::SysRay::process_status(handle.into()) {
                Ok(s) => match s {
                    Some(_) => {
                        crate::stdio_relay::wait_for_child(handle);
                        return moto_rt::E_OK;
                    }
                    None => continue,
                },
                Err(err) => return err,
            },
            Err(err) => return err,
        }
    }
}

pub unsafe extern "C" fn status(handle: u64, status: *mut u64) -> moto_rt::ErrorCode {
    match moto_sys::SysRay::process_status(handle.into()) {
        Ok(s) => match s {
            Some(s) => {
                if !crate::stdio_relay::child_is_finalized(handle) {
                    return moto_rt::E_NOT_READY;
                }
                unsafe {
                    *status = s;
                }
                moto_rt::E_OK
            }
            None => moto_rt::E_NOT_READY,
        },
        Err(err) => err,
    }
}

pub extern "C" fn exit(code: i32) -> ! {
    crate::stdio_relay::drain_for_exit();
    let code = i32::cast_unsigned(code) as u64;
    moto_sys::SysCpu::exit_process(code)
}

fn resolve_exe(exe: &str) -> Result<String, ErrorCode> {
    if let Ok(attr) = moto_rt::fs::stat(exe)
        && attr.file_type == moto_rt::fs::FILETYPE_FILE
    {
        return Ok(exe.to_owned());
    }

    // Only "naked" filenames are resolved with $PATH.
    // TODO: be smarter below (slashes in quotes; escaped slashes, etc.)
    if exe.find('/').is_some() {
        return Ok(exe.to_owned());
    }

    let Some(path) = moto_rt::process::getenv("PATH") else {
        log::warn!("$PATH not defined when spawning '{exe}'");
        return Err(moto_rt::E_INVALID_FILENAME);
    };

    // TODO: be smarter below (colons in quotes; escaped colons, etc.)
    let dirs: Vec<&str> = path.split(':').collect();
    for dir in dirs {
        if dir.is_empty() {
            continue;
        }

        let mut fname = dir.to_owned();
        fname.push('/');
        fname.push_str(exe);
        if let Ok(_attr) = moto_rt::fs::stat(fname.as_str()) {
            return Ok(fname);
        }
    }

    Err(moto_rt::E_INVALID_FILENAME)
}

fn is_elf(buf: &[u8]) -> bool {
    const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

    if buf.len() < 4 {
        return false;
    }

    buf[0..4] == ELF_MAGIC
}

fn is_script(buf: &[u8]) -> bool {
    const SCRIPT_MAGIC: [u8; 3] = *b"#!/";
    if buf.len() < 4 {
        return false;
    }

    buf[0..3] == SCRIPT_MAGIC
}

fn executable_file_size(fd: moto_rt::RtFd) -> Result<u64, ErrorCode> {
    let attr = moto_rt::fs::get_file_attr(fd)?;
    if attr.perm & moto_rt::fs::PERM_EXEC == 0 {
        return Err(moto_rt::E_NOT_ALLOWED);
    }
    if attr.size < 4 {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }
    Ok(attr.size)
}

fn run_script(
    script: String,
    script_fd: moto_rt::RtFd, // Note: the caller closes fd.
    args: &moto_rt::process::SpawnArgsRt,
    stdio: &mut crate::stdio::PreparedChildStdio,
    result_rt: &mut moto_rt::process::SpawnResult,
) -> Result<(), ErrorCode> {
    let mut buf: [u8; 256] = [0; 256];

    let sz = moto_rt::fs::read(script_fd, &mut buf)?;
    assert!(sz <= buf.len());
    let bytes = &buf[0..sz];
    debug_assert!(bytes.len() > 3);
    debug_assert_eq!(bytes[0], b'#');
    debug_assert_eq!(bytes[1], b'!');

    let line = core::str::from_utf8(&bytes[2..]).map_err(|_| moto_rt::E_INVALID_ARGUMENT)?;
    let exe = line
        .lines()
        .next()
        .ok_or(moto_rt::E_INVALID_ARGUMENT)?
        .trim()
        .to_owned();

    let fd = moto_rt::fs::open(exe.as_str(), moto_rt::fs::O_READ)?;

    let res = executable_file_size(fd)
        .and_then(|file_sz| run_elf(exe, fd, file_sz, Some(script), args, stdio, result_rt));
    moto_rt::fs::close(fd).unwrap();
    res
}

fn read_all(fd: moto_rt::RtFd, buf: &mut [u8]) -> Result<usize, ErrorCode> {
    moto_rt::fs::seek(fd, 0, moto_rt::fs::SEEK_SET)?;

    let mut done = 0_usize;
    while done < buf.len() {
        let dst = &mut buf[done..];
        let sz = moto_rt::fs::read(fd, dst)?;
        if sz == 0 {
            crate::moto_log!("read_all EOF: {done} vs {}", buf.len());
            return Err(moto_rt::E_UNEXPECTED_EOF);
        }
        done += sz;
    }

    Ok(done)
}

struct Loader {
    address_space: moto_sys::SysHandle,
    relocated: bool,

    // Map of allocated pages: remote addr -> (local addr, num_pages).
    mapped_regions: BTreeMap<u64, (u64, u64)>,
}

impl Loader {
    unsafe fn write_remotely(&mut self, dst: u64, src: *const u8, sz: u64) {
        // There shouldn't be too many entries in the map, so we can just linearly iterate.
        let mut region: Option<(u64, u64, u64)> = None;
        for entry in &self.mapped_regions {
            if *entry.0 <= dst {
                region = Some((*entry.0, entry.1.0, entry.1.1));
            } else {
                break;
            }
        }

        let region = region.unwrap();

        let remote_region_start = region.0;
        let local_region_start = region.1;
        let region_sz = region.2 << moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2;

        assert!(remote_region_start <= dst);
        assert!((dst + sz) <= (region.0 + region_sz));

        let offset = dst - remote_region_start;

        unsafe {
            core::ptr::copy_nonoverlapping(
                src,
                (local_region_start + offset) as usize as *mut u8,
                sz as usize,
            )
        };
    }
}

impl Drop for Loader {
    fn drop(&mut self) {
        for (addr, _) in self.mapped_regions.values() {
            moto_sys::SysMem::unmap(moto_sys::SysHandle::SELF, 0, u64::MAX, *addr).unwrap();
        }
    }
}

impl elfloader::ElfLoader for Loader {
    fn allocate(
        &mut self,
        load_headers: elfloader::LoadableHeaders<'_, '_>,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        for header in load_headers {
            if header.flags().is_write() && header.flags().is_execute() {
                return Err(elfloader::ElfLoaderErr::UnsupportedElfFormat);
            }

            let vaddr_start = header.virtual_addr() & !(moto_sys::sys_mem::PAGE_SIZE_SMALL - 1);
            let vaddr_end = moto_sys::align_up(
                header.virtual_addr() + header.mem_size(),
                moto_sys::sys_mem::PAGE_SIZE_SMALL,
            );

            // The remote side gets the segment's own protection (so text is
            // R+X, rodata R, data R+W, everything non-EXECUTABLE is NX);
            // loading and relocation write through our local side of the
            // sharing, which is always mapped R+W regardless.
            let mut flags = moto_sys::SysMem::F_SHARE_SELF;
            if header.flags().is_read() {
                flags |= moto_sys::SysMem::F_READABLE;
            }
            if header.flags().is_write() {
                flags |= moto_sys::SysMem::F_WRITABLE;
            }
            if header.flags().is_execute() {
                flags |= moto_sys::SysMem::F_EXECUTABLE;
            }

            let num_pages = (vaddr_end - vaddr_start) >> moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2;

            let (remote, local) = moto_sys::SysMem::map2(
                self.address_space,
                flags,
                u64::MAX,
                vaddr_start,
                moto_sys::sys_mem::PAGE_SIZE_SMALL,
                num_pages,
            )
            .map_err(|_| elfloader::ElfLoaderErr::OutOfMemory)?;

            assert_eq!(remote, vaddr_start);
            self.mapped_regions.insert(vaddr_start, (local, num_pages));
        }
        Ok(())
    }

    fn load(
        &mut self,
        _flags: elfloader::Flags,
        base: elfloader::VAddr,
        region: &[u8],
    ) -> Result<(), elfloader::ElfLoaderErr> {
        unsafe {
            self.write_remotely(base, region.as_ptr(), region.len() as u64);
        }

        Ok(())
    }

    fn relocate(
        &mut self,
        entry: elfloader::RelocationEntry,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        use elfloader::RelocationType::x86_64;
        use elfloader::arch::x86_64::RelocationTypes::*;

        let remote_addr: u64 = entry.offset;

        match entry.rtype {
            x86_64(R_AMD64_RELATIVE) => {
                // This type requires addend to be present.
                let addend: u64 = entry
                    .addend
                    .ok_or(elfloader::ElfLoaderErr::UnsupportedRelocationEntry)?;

                // Need to write (addend + base) into addr.
                unsafe {
                    self.write_remotely(
                        remote_addr,
                        &addend as *const _ as *const u8,
                        core::mem::size_of::<u64>() as u64,
                    );
                }

                self.relocated = true;

                Ok(())
            }
            x86_64(R_AMD64_NONE) => Ok(()),
            _ => Err(elfloader::ElfLoaderErr::UnsupportedRelocationEntry),
        }
    }

    fn tls(
        &mut self,
        _tdata_start: elfloader::VAddr,
        _tdata_length: u64,
        _total_size: u64,
        _align: u64,
    ) -> Result<(), elfloader::ElfLoaderErr> {
        Err(elfloader::ElfLoaderErr::UnsupportedAbi)
    }
}

// Loads a binary; returns the entry point.
fn load_binary(bytes: &[u8], address_space: moto_sys::SysHandle) -> Result<u64, ErrorCode> {
    use elfloader::*;

    let elf_binary = match ElfBinary::new(bytes) {
        Err(_) => {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        Ok(binary) => binary,
    };

    if elf_binary.get_arch() != Machine::X86_64 {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    if elf_binary.interpreter().is_some() {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let mut elf_loader = Loader {
        address_space,
        relocated: false,
        mapped_regions: BTreeMap::default(),
    };
    match elf_binary.load(&mut elf_loader) {
        Err(_) => Err(moto_rt::E_INVALID_ARGUMENT),
        Ok(()) => Ok(elf_binary.entry_point()),
    }
}

fn create_remote_process_data(
    address_space: moto_sys::SysHandle,
) -> Result<*mut ProcessData, moto_rt::ErrorCode> {
    let flags = moto_sys::SysMem::F_SHARE_SELF | moto_sys::SysMem::F_READABLE;
    let (remote, local) = moto_sys::SysMem::map2(
        address_space,
        flags,
        u64::MAX,
        ProcessData::ADDR,
        moto_sys::sys_mem::PAGE_SIZE_SMALL,
        1,
    )?;

    assert_eq!(remote, ProcessData::ADDR);
    Ok(local as usize as *mut ProcessData)
}

unsafe fn create_remote_args(
    address_space: moto_sys::SysHandle,
    args1: &Vec<&[u8]>,
    args2: &Vec<&[u8]>,
) -> Result<u64, ErrorCode> {
    let mut needed_len: u32 = 4; // Args num.
    let mut num_args = 0_u32;

    let mut calc_lengths = |arg: &[u8]| {
        needed_len += 4;
        needed_len += ((arg.len() as u32) + 3) & !3_u32;
        num_args += 1;
    };

    for arg in args1 {
        calc_lengths(arg);
    }

    for arg in args2 {
        calc_lengths(arg);
    }

    if num_args == 0 {
        return Ok(0);
    }

    let page_size = moto_sys::sys_mem::PAGE_SIZE_SMALL as u32;
    needed_len = (needed_len + page_size - 1) & !(page_size - 1);
    let num_pages = needed_len >> moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2;

    let (remote, local) = moto_sys::SysMem::map2(
        address_space,
        moto_sys::SysMem::F_SHARE_SELF | moto_sys::SysMem::F_READABLE,
        u64::MAX,
        u64::MAX,
        moto_sys::sys_mem::PAGE_SIZE_SMALL,
        num_pages as u64,
    )?;

    let mut pos = local as usize;
    unsafe { *((pos as *mut u32).as_mut().unwrap()) = num_args };
    pos += 4;

    let mut write_arg = |arg: &[u8]| {
        unsafe { *((pos as *mut u32).as_mut().unwrap()) = arg.len() as u32 };
        pos += 4;

        unsafe { core::ptr::copy_nonoverlapping(arg.as_ptr(), pos as *mut u8, arg.len()) };
        pos += (arg.len() + 3) & !3_usize;
    };

    for arg in args1 {
        write_arg(arg);
    }

    for arg in args2 {
        write_arg(arg);
    }

    moto_sys::SysMem::unmap(moto_sys::SysHandle::SELF, 0, u64::MAX, local).unwrap();
    Ok(remote)
}

unsafe fn create_remote_env(
    address_space: moto_sys::SysHandle,
    env: Vec<(&[u8], &[u8])>,
) -> Result<u64, ErrorCode> {
    let mut flat_vec = Vec::new();
    for (k, v) in env {
        if k.is_empty() {
            continue;
        }
        flat_vec.push(k);
        flat_vec.push(v);
    }

    unsafe { create_remote_args(address_space, &Vec::new(), &flat_vec) }
}

fn debug_name(exe_plus: &Vec<&[u8]>, args: &Vec<&[u8]>) -> String {
    let mut res = String::new();
    for s in exe_plus {
        res.push_str(core::str::from_utf8(s).unwrap());
        res.push(' ');
    }

    for s in args {
        res.push_str(core::str::from_utf8(s).unwrap());
        res.push(' ');
    }

    res = res.trim().to_owned();
    const MAX_BYTES: usize = moto_sys::stats::ProcessInfoV1::MAX_DEBUG_NAME_BYTES;

    if res.len() > MAX_BYTES {
        let mut truncate_to = MAX_BYTES - 3; // The ellipsis character takes three bytes.
        while !res.is_char_boundary(truncate_to) {
            truncate_to -= 1;
        }
        alloc::format!("{}{}", &res[0..truncate_to], '\u{2026}') // Append the ellipsis character.
    } else {
        res
    }
}

fn run_elf(
    exe: String,
    fd: moto_rt::RtFd, // Note: the caller closes fd.
    file_sz: u64,
    prepend_arg: Option<String>,
    args_rt: &moto_rt::process::SpawnArgsRt,
    stdio: &mut crate::stdio::PreparedChildStdio,
    result_rt: &mut moto_rt::process::SpawnResult,
) -> Result<(), ErrorCode> {
    // TODO: currently the binary is first fully loaded into RAM, and then
    //       the bytes are copied again as part of ELF loading. There should
    //       be a way to avoid the extra copying. Or even do lazy loading,
    //       i.e. don't load anything from storage until it is actually
    //       needed (this is what Linux does, I believe).

    // First, load the binary into RAM.
    let (page_size, num_pages) = {
        (
            moto_sys::sys_mem::PAGE_SIZE_SMALL,
            moto_sys::align_up(file_sz, moto_sys::sys_mem::PAGE_SIZE_SMALL)
                >> moto_sys::sys_mem::PAGE_SIZE_SMALL_LOG2,
        )
    };
    let buf_addr = moto_sys::SysMem::alloc(page_size, num_pages)?;
    let buf: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(buf_addr as usize as *mut u8, file_sz as usize) };
    crate::util::scopeguard::defer! {
        // Free the allocated buffer.
        moto_sys::SysMem::free(buf_addr).unwrap();
    }

    let sz = read_all(fd, buf)?;
    if sz != file_sz as usize {
        log::warn!("Unexpected EOF reading exe '{exe}'");
        return Err(moto_rt::E_UNEXPECTED_EOF);
    }

    let args = unsafe { ProcessData::deserialize_vec(args_rt.args) };

    let mut exe_plus = Vec::new();
    exe_plus.push(exe.as_bytes());
    if let Some(arg) = prepend_arg.as_ref() {
        exe_plus.push(arg.as_bytes());
    }

    let debug_name = debug_name(&exe_plus, &args);

    // Create an address space for the new process.
    let full_url = alloc::format!(
        "address_space:debug_name={}",
        moto_sys::url_encode(debug_name.as_str())
    );
    let address_space = moto_sys::syscalls::RaiiHandle::from(moto_sys::SysObj::create(
        moto_sys::SysHandle::NONE,
        0,
        &full_url,
    )?);
    let load_result = load_binary(buf, address_space.syshandle()).inspect_err(|err| {
        let hash = moto_rt::fnv1a_hash_64(buf);
        log::warn!(
            "\n\tError loading ELF for '{exe}': {err:?}; buf len: {} hash: 0x{hash:x}.",
            buf.len()
        )
    })?;
    let res = crate::load::load_vdso(address_space.syshandle().as_u64());
    if res != moto_rt::E_OK {
        log::warn!("Spawn '{exe}': VDSO error: {res}.");
        return Err(res);
    };

    // Parse env.
    let raw_env = unsafe { ProcessData::deserialize_vec(args_rt.env) };
    assert_eq!(0, raw_env.len() & 1); // Must be even number: keys + vals.
    let mut env = Vec::new();
    let num_keys = raw_env.len() / 2;
    for idx in 0..num_keys {
        env.push((raw_env[idx], raw_env[num_keys + idx]));
    }

    let mut caps =
        moto_sys::caps::default_child_capabilities(moto_sys::ProcessStaticPage::get().capabilities);
    // Whether to spawn the child detached (owner = kernel, survives our exit).
    // Requested by an env var and consumed here, the same way caps are; the
    // kernel enforces that we actually hold CAP_SPAWN_DETACHED.
    let mut detached = false;
    // A terminal provider's instruction to mark the child's explicitly
    // created stdio pipes as terminals. Consumed regardless of value so it
    // cannot become inherited live state (docs/tui.md).
    let mut terminal_hint = false;
    // Whether this spawn explicitly declines the session terminal stream.
    let mut no_terminal = false;
    // Find the capability, detached, and stdio launch-only env vars.
    for (k, v) in &mut env {
        if *k == moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY.as_bytes() {
            *k = "".as_bytes(); // Clear the key: see env::create_remote_env().
            let v = core::str::from_utf8(v).map_err(|_| moto_rt::E_INVALID_ARGUMENT)?;
            caps = u64::from_str_radix(v.trim_start_matches("0x"), 16).map_err(|_| {
                crate::moto_log!("could not parse caps {v}");
                moto_rt::E_INVALID_ARGUMENT
            })?;
        } else if *k == moto_sys::caps::MOTOR_OS_DETACHED_ENV_KEY.as_bytes() {
            *k = "".as_bytes(); // Clear the key so the child never sees it.
            if let Ok(s) = core::str::from_utf8(v) {
                detached = s == "true" || s == "TRUE";
            }
        } else if *k == moto_rt::process::STDIO_IS_TERMINAL_ENV_KEY.as_bytes() {
            *k = "".as_bytes(); // Clear the key so the child never sees it.
            if let Ok(s) = core::str::from_utf8(v) {
                terminal_hint = s == "true" || s == "TRUE";
            }
        } else if *k == moto_rt::process::STDIO_NO_TERMINAL_ENV_KEY.as_bytes() {
            *k = "".as_bytes(); // Clear the key so the child never sees it.
            if let Ok(s) = core::str::from_utf8(v) {
                no_terminal = s == "true" || s == "TRUE";
            }
        }
    }

    // Create the process from the address space.
    let proc_url = alloc::format!(
        "process:entry_point={load_result};capabilities={caps};detached={}",
        if detached { 1 } else { 0 }
    );
    let process = moto_sys::syscalls::RaiiHandle::from(moto_sys::SysObj::create(
        address_space.syshandle(),
        0,
        &proc_url,
    )?);

    // Set up stdio.
    let remote_process_data = create_remote_process_data(address_space.syshandle())?;
    crate::util::scopeguard::defer! {
        moto_sys::SysMem::unmap(
            moto_sys::SysHandle::SELF,
            0,
            u64::MAX,
            remote_process_data as usize as u64,
        )
        .unwrap();
    }

    unsafe {
        let pd = remote_process_data.as_mut().unwrap();
        pd.args = create_remote_args(address_space.syshandle(), &exe_plus, &args)?;
        pd.env = create_remote_env(address_space.syshandle(), env)?;
    }

    let (stdin, stdout, stderr) = crate::stdio::create_child_stdio(
        process.syshandle(),
        remote_process_data,
        stdio,
        terminal_hint,
        detached,
        no_terminal,
    )?;

    let main_thread = moto_sys::SysObj::get(process.syshandle(), 0, "main_thread").unwrap();
    let wake_result = moto_sys::SysCpu::wake(main_thread);
    // While thread objects extracted from TCB or returned from spawn() must
    // not be put(), this is a cross-process thread handle, and so it must be.
    moto_sys::SysObj::put(main_thread).unwrap();
    if wake_result.is_ok() {
        // The spawner gets the child's pid; the handle is still held here.
        let pid = moto_sys::SysRay::process_pid(process.syshandle())
            .expect("pid query on a held process handle");
        result_rt.pid = i32::try_from(pid).expect("pid fits i32");

        result_rt.handle = process.take().as_u64();
        result_rt.stdin = stdin;
        result_rt.stdout = stdout;
        result_rt.stderr = stderr;

        Ok(())
    } else {
        // Take the group before dropping the handle: killing the child is what
        // lets the relays finish, but the handle number is reusable the moment
        // it is released, so it cannot be used to find the group afterwards.
        let relays = crate::stdio_relay::completion_group(process.syshandle().as_u64());
        drop(process);
        if let Some(relays) = relays {
            relays.wait();
        }
        Err(moto_rt::E_INTERNAL_ERROR)
    }
}

unsafe fn spawn_impl(
    args_rt: &moto_rt::process::SpawnArgsRt,
    result_rt: &mut moto_rt::process::SpawnResult,
) -> Result<(), ErrorCode> {
    let mut stdio = crate::stdio::prepare_child_stdio(args_rt)?;

    // A new process is exactly the memory-growing load the kernel is
    // refusing under pressure; fail here, before any work is done, with an
    // error the parent can handle.
    if moto_sys::memory_pressure() {
        return Err(moto_rt::E_OUT_OF_MEMORY);
    }

    // Open the file.
    let program_name = unsafe {
        core::slice::from_raw_parts(
            args_rt.prog_name_addr as usize as *const u8,
            args_rt.prog_name_size as usize,
        )
    };
    let program_name =
        core::str::from_utf8(program_name).map_err(|_| moto_rt::E_INVALID_ARGUMENT)?;
    log::debug!("spawn {program_name}");
    let exe = resolve_exe(program_name)?;

    let fd = moto_rt::fs::open(exe.as_str(), moto_rt::fs::O_READ)?;

    // Check if this is an elf file or a script.
    let file_sz = executable_file_size(fd).inspect_err(|_| {
        moto_rt::fs::close(fd).unwrap();
    })?;
    let mut buf: [u8; 4] = [0; 4];

    let sz = moto_rt::fs::read(fd, &mut buf).inspect_err(|_| {
        moto_rt::fs::close(fd).unwrap();
    })?;
    if sz != 4 {
        moto_rt::fs::close(fd).unwrap();
        return Err(moto_rt::E_UNEXPECTED_EOF);
    }

    if is_elf(&buf) {
        moto_rt::fs::seek(fd, 0, moto_rt::fs::SEEK_SET).inspect_err(|_| {
            moto_rt::fs::close(fd).unwrap();
        })?;
        let res = run_elf(exe, fd, file_sz, None, args_rt, &mut stdio, result_rt);
        moto_rt::fs::close(fd).unwrap();
        return res;
    }

    if is_script(&buf) {
        moto_rt::fs::seek(fd, 0, moto_rt::fs::SEEK_SET).inspect_err(|_| {
            moto_rt::fs::close(fd).unwrap();
        })?;
        let res = run_script(exe, fd, args_rt, &mut stdio, result_rt);
        moto_rt::fs::close(fd).unwrap();
        return res;
    }

    moto_rt::fs::close(fd).unwrap();
    Err(moto_rt::E_INVALID_ARGUMENT)
}

pub unsafe extern "C" fn spawn(
    args_rt: *const moto_rt::process::SpawnArgsRt,
    result_rt: *mut moto_rt::process::SpawnResult,
) -> moto_rt::ErrorCode {
    match unsafe { spawn_impl(args_rt.as_ref().unwrap(), result_rt.as_mut().unwrap()) } {
        Ok(()) => moto_rt::E_OK,
        Err(err) => err,
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct StdioData {
    tag: u64,
    payload: [u64; 5],
}

impl StdioData {
    pub const TAG_NULL: u64 = 0;
    pub const TAG_PIPE: u64 = 1;
    pub const TAG_FILE: u64 = 2;

    /// The child-side endpoint of this stream is a terminal
    /// (docs/tui.md). The spawning VDSO writes the
    /// bit per stream; the child VDSO copies it into the corresponding
    /// `SelfStdio` at startup. Safe to add without a version bump: the
    /// spawner maps its own VDSO image into the child, so both sides of
    /// this page are always the same build.
    pub const FLAG_TERMINAL: u64 = 1;

    const FILE_READABLE: u64 = 1;
    const FILE_WRITABLE: u64 = 2;
    const FILE_FLAGS: u64 = Self::FILE_READABLE | Self::FILE_WRITABLE;

    pub fn null() -> Self {
        Self {
            tag: Self::TAG_NULL,
            payload: [0; 5],
        }
    }

    pub fn pipe(pipe_addr: u64, pipe_size: u64, handle: u64, terminal: bool) -> Self {
        Self {
            tag: Self::TAG_PIPE,
            payload: [
                pipe_addr,
                pipe_size,
                handle,
                if terminal { Self::FLAG_TERMINAL } else { 0 },
                0,
            ],
        }
    }

    pub fn file(file: StdioFileData) -> Self {
        let flags = (u64::from(file.readable) * Self::FILE_READABLE)
            | (u64::from(file.writable) * Self::FILE_WRITABLE);
        Self {
            tag: Self::TAG_FILE,
            payload: [
                file.entry_id as u64,
                (file.entry_id >> 64) as u64,
                file.offset,
                flags,
                file.parent_open_id,
            ],
        }
    }

    pub fn pipe_data(&self) -> Result<Option<(u64, u64, u64, bool)>, ErrorCode> {
        match self.tag {
            Self::TAG_NULL | Self::TAG_FILE => Ok(None),
            Self::TAG_PIPE => {
                if self.payload[3] & !Self::FLAG_TERMINAL != 0 || self.payload[4] != 0 {
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                }
                Ok(Some((
                    self.payload[0],
                    self.payload[1],
                    self.payload[2],
                    self.payload[3] & Self::FLAG_TERMINAL != 0,
                )))
            }
            _ => Err(moto_rt::E_INVALID_ARGUMENT),
        }
    }

    pub fn file_data(&self) -> Result<Option<StdioFileData>, ErrorCode> {
        match self.tag {
            Self::TAG_NULL | Self::TAG_PIPE => Ok(None),
            Self::TAG_FILE => {
                let flags = self.payload[3];
                let entry_id = self.payload[0] as u128 | (self.payload[1] as u128) << 64;
                if entry_id == 0 || flags == 0 || flags & !Self::FILE_FLAGS != 0 {
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                }
                Ok(Some(StdioFileData {
                    entry_id,
                    offset: self.payload[2],
                    readable: flags & Self::FILE_READABLE != 0,
                    writable: flags & Self::FILE_WRITABLE != 0,
                    parent_open_id: self.payload[4],
                }))
            }
            _ => Err(moto_rt::E_INVALID_ARGUMENT),
        }
    }

    pub fn is_null(&self) -> bool {
        self.tag == Self::TAG_NULL
    }
}

#[derive(Clone, Copy)]
pub struct StdioFileData {
    pub entry_id: u128,
    pub offset: u64,
    pub readable: bool,
    pub writable: bool,
    pub parent_open_id: u64,
}

#[repr(C)]
pub struct ProcessData {
    pub version: u64,

    // Stdio.
    pub stdin: StdioData,
    pub stdout: StdioData,
    pub stderr: StdioData,
    pub terminal: StdioData,
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
        if addr == 0 {
            return Vec::new();
        };
        // first four bytes: the number of arguments;
        // then arguments, aligned at four bytes: size (four bytes), bytes.

        let mut pos = addr as usize;
        assert_eq!(pos & 3, 0);

        let num_args = unsafe { *((pos as *const u32).as_ref().unwrap()) };
        pos += 4;

        let mut result = Vec::new();
        for _i in 0..num_args {
            let len = unsafe { *((pos as *const u32).as_ref().unwrap()) };
            pos += 4;
            let bytes: &[u8] =
                unsafe { core::slice::from_raw_parts(pos as *const u8, len as usize) };
            result.push(bytes);
            pos += len as usize;
            pos = (pos + 3) & !3; // Align up to 4 bytes.
        }

        result
    }

    pub unsafe fn args(&self) -> Vec<&[u8]> {
        if self.args == 0 {
            // Only sys-io has no args; every other process has them.
            return alloc::vec![b"sys-io"];
        }

        unsafe { Self::deserialize_vec(self.args) }
    }

    pub unsafe fn binary() -> &'static str {
        let ptr: *const ProcessData = Self::ADDR as *const ProcessData;
        if ptr.is_null() {
            // Only sys-io has no args; every other process has them.
            return "sys-io";
        }

        let pdata = unsafe { ptr.as_ref().unwrap() };
        if pdata.args == 0 {
            // Only sys-io has no args; every other process has them.
            return "sys-io";
        }

        // See deserialize_vec() above.
        // first four bytes: the number of arguments;
        // then arguments, aligned at four bytes: size (four bytes), bytes.

        let mut pos = pdata.args as usize;
        assert_eq!(pos & 3, 0);
        pos += 4;

        let len = unsafe { *((pos as *const u32).as_ref().unwrap()) };
        pos += 4;
        let bytes: &[u8] = unsafe { core::slice::from_raw_parts(pos as *const u8, len as usize) };
        core::str::from_utf8(bytes).unwrap()
    }

    pub unsafe fn env(&self) -> Vec<(&[u8], &[u8])> {
        if self.env == 0 {
            return Vec::new();
        }

        let raw_vec = unsafe { Self::deserialize_vec(self.env) };
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
        map.get(key).cloned()
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

static ENV: moto_rt::mutex::Mutex<EnvRt> = moto_rt::mutex::Mutex::new(EnvRt::new());

fn encode_env(keys: Vec<String>, vals: Vec<String>) -> Result<u64, ErrorCode> {
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
        return Ok(0);
    }

    let result_addr = crate::rt_alloc::sys_alloc(needed_len as usize) as usize;
    if result_addr == 0 {
        return Err(moto_rt::E_OUT_OF_MEMORY);
    }

    unsafe {
        let mut pos = result_addr;
        *((pos as *mut u32).as_mut().unwrap()) = num_args;
        pos += 4;

        let mut write_arg = |arg: &str| {
            *((pos as *mut u32).as_mut().unwrap()) = arg.len() as u32;
            pos += 4;

            let bytes = arg.as_bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), pos as *mut u8, bytes.len());
            pos += (bytes.len() + 3) & !3_usize;
        };

        for arg in keys {
            write_arg(arg.as_str());
        }

        for arg in vals {
            write_arg(arg.as_str());
        }
    }

    Ok(result_addr as u64)
}

fn encode_args(args: Vec<String>) -> Result<u64, ErrorCode> {
    let mut needed_len: u32 = 4; // Args num.
    let mut num_args = 0_u32;

    let mut calc_lengths = |arg: &str| {
        needed_len += 4;
        needed_len += ((arg.len() as u32) + 3) & !3_u32;
        num_args += 1;
    };

    for arg in &args {
        calc_lengths(arg.as_str());
    }

    if num_args == 0 {
        return Ok(0);
    }

    let result_addr = crate::rt_alloc::sys_alloc(needed_len as usize) as usize;
    if result_addr == 0 {
        return Err(moto_rt::E_OUT_OF_MEMORY);
    }

    unsafe {
        let mut pos = result_addr;
        *((pos as *mut u32).as_mut().unwrap()) = num_args;
        pos += 4;

        let mut write_arg = |arg: &str| {
            *((pos as *mut u32).as_mut().unwrap()) = arg.len() as u32;
            pos += 4;

            let bytes = arg.as_bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), pos as *mut u8, bytes.len());
            pos += (bytes.len() + 3) & !3_usize;
        };

        for arg in args {
            write_arg(arg.as_str());
        }
    }

    Ok(result_addr as u64)
}

pub extern "C" fn current_exe(out_ptr: *mut u8, out_size: *mut usize) -> ErrorCode {
    // For now, just return args[0].
    let args: Vec<String> = unsafe {
        ProcessData::get()
            .args()
            .into_iter()
            .map(|bytes| core::str::from_utf8(bytes).unwrap().to_owned())
            .collect()
    };

    if args.is_empty() {
        return moto_rt::E_NOT_FOUND;
    }

    let out_bytes = args[0].as_bytes();
    assert!(out_bytes.len() <= moto_rt::fs::MAX_PATH_LEN);
    unsafe {
        core::ptr::copy_nonoverlapping(out_bytes.as_ptr(), out_ptr, out_bytes.len());
        *out_size = out_bytes.len();
    }

    moto_rt::E_OK
}

pub extern "C" fn current_pid() -> u64 {
    moto_sys::ProcessStaticPage::get().pid
}
