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
pub extern "C" fn wait(handle: u64) -> moto_rt::ErrorCode {
    match moto_sys::SysCpu::wait(
        &mut [handle.into()],
        moto_sys::SysHandle::NONE,
        moto_sys::SysHandle::NONE,
        None,
    ) {
        Ok(()) => moto_rt::E_OK,
        Err(err) => err,
    }
}

pub unsafe extern "C" fn status(handle: u64, status: *mut u64) -> moto_rt::ErrorCode {
    match moto_sys::SysRay::process_status(handle.into()) {
        Ok(s) => match s {
            Some(s) => {
                *status = s;
                moto_rt::E_OK
            }
            None => moto_rt::E_NOT_READY,
        },
        Err(err) => err,
    }
}

pub extern "C" fn exit(code: i32) -> ! {
    let code = unsafe { core::mem::transmute::<i32, u32>(code) } as u64;
    moto_sys::SysCpu::exit(code)
}

fn resolve_exe(exe: &str) -> Result<String, ErrorCode> {
    if let Ok(attr) = moto_rt::fs::stat(exe) {
        if attr.file_type == moto_rt::fs::FILETYPE_FILE {
            return Ok(exe.to_owned());
        }
    }

    // Only "naked" filenames are resolved with $PATH.
    // TODO: be smarter below (slashes in quotes; escaped slashes, etc.)
    if exe.find('/').is_some() {
        return Ok(exe.to_owned());
    }

    let path = moto_rt::process::getenv("PATH").ok_or(moto_rt::E_INVALID_FILENAME)?;

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
    const SCRIPT_MAGIC: [u8; 3] = [b'#', b'!', b'/'];
    if buf.len() < 4 {
        return false;
    }

    buf[0..3] == SCRIPT_MAGIC
}

fn run_script(
    script: String,
    script_fd: moto_rt::RtFd, // Note: the caller closes fd.
    args: &moto_rt::process::SpawnArgsRt,
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

    let res = run_elf(exe, fd, Some(script), args, result_rt);
    moto_rt::fs::close(fd).unwrap();
    res
}

fn read_all(fd: moto_rt::RtFd, buf: &mut [u8]) -> Result<usize, ErrorCode> {
    let size = moto_rt::fs::get_file_attr(fd)?.size;

    if buf.len() < size as usize {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }
    moto_rt::fs::seek(fd, 0, moto_rt::fs::SEEK_SET)?;

    let mut done = 0_usize;
    while done < size as usize {
        let dst = &mut buf[done..];
        let sz = moto_rt::fs::read(fd, dst)?;
        if sz == 0 {
            break;
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
                region = Some((*entry.0, entry.1 .0, entry.1 .1));
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

        core::ptr::copy_nonoverlapping(
            src,
            (local_region_start + offset) as usize as *mut u8,
            sz as usize,
        );
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
            let vaddr_start = header.virtual_addr() & !(moto_sys::sys_mem::PAGE_SIZE_SMALL - 1);
            let vaddr_end = moto_sys::align_up(
                header.virtual_addr() + header.mem_size(),
                moto_sys::sys_mem::PAGE_SIZE_SMALL,
            );

            // TODO: Implement proper RelRo.
            /*
            let mut flags = moto_sys::SysMem::F_SHARE_SELF;
            if header.flags().is_read() {
                flags |= moto_sys::SysMem::F_READABLE;
            }
            if header.flags().is_write() {
                flags |= moto_sys::SysMem::F_WRITABLE;
            }
            */
            let flags = moto_sys::SysMem::F_SHARE_SELF
                | moto_sys::SysMem::F_READABLE
                | moto_sys::SysMem::F_WRITABLE;

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
        use elfloader::arch::x86_64::RelocationTypes::*;
        use elfloader::RelocationType::x86_64;

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
    skip_empty: bool,
) -> Result<u64, ErrorCode> {
    let mut needed_len: u32 = 4; // Args num.
    let mut num_args = 0_u32;

    let mut calc_lengths = |arg: &[u8]| {
        needed_len += 4;
        needed_len += ((arg.len() as u32) + 3) & !3_u32;
        num_args += 1;
    };

    for arg in args1 {
        if arg.is_empty() && skip_empty {
            continue;
        }
        calc_lengths(arg);
    }

    for arg in args2 {
        if arg.is_empty() && skip_empty {
            continue;
        }
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
    *((pos as *mut u32).as_mut().unwrap()) = num_args;
    pos += 4;

    let mut write_arg = |arg: &[u8]| {
        *((pos as *mut u32).as_mut().unwrap()) = arg.len() as u32;
        pos += 4;

        core::ptr::copy_nonoverlapping(arg.as_ptr(), pos as *mut u8, arg.len());
        pos += (arg.len() + 3) & !3_usize;
    };

    for arg in args1 {
        if arg.is_empty() && skip_empty {
            continue;
        }
        write_arg(arg);
    }

    for arg in args2 {
        if arg.is_empty() && skip_empty {
            continue;
        }
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

    create_remote_args(address_space, &Vec::new(), &flat_vec, false)
}

fn run_elf(
    exe: String,
    fd: moto_rt::RtFd, // Note: the caller closes fd.
    prepend_arg: Option<String>,
    args_rt: &moto_rt::process::SpawnArgsRt,
    result_rt: &mut moto_rt::process::SpawnResult,
) -> Result<(), ErrorCode> {
    // TODO: currently the binary is first fully loaded into RAM, and then
    //       the bytes are copied again as part of ELF loading. There should
    //       be a way to avoid the extra copying. Or even do lazy loading,
    //       i.e. don't load anything from storage until it is actually
    //       needed (this is what Linux does, I believe).

    // First, load the binary info RAM.
    let file_sz = moto_rt::fs::get_file_attr(fd)?.size;
    if file_sz < 4 {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let (page_size, num_pages) = {
        (
            moto_sys::sys_mem::PAGE_SIZE_SMALL,
            moto_sys::align_up(file_sz as u64, moto_sys::sys_mem::PAGE_SIZE_SMALL)
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
        return Err(moto_rt::E_UNEXPECTED_EOF);
    }

    let args = unsafe { ProcessData::deserialize_vec(args_rt.args) };

    let debug_name = match args.len() {
        0 => exe.clone(),
        1 => alloc::format!("{} {}", exe, core::str::from_utf8(args[0]).unwrap()),
        _ => alloc::format!("{} {} ...", exe, core::str::from_utf8(args[0]).unwrap()),
    };

    // Create an address space for the new process.
    let full_url = alloc::format!(
        "address_space:debug_name={}",
        &moto_sys::url_encode(debug_name.as_str())
    );
    let address_space = moto_sys::syscalls::RaiiHandle::from(moto_sys::SysObj::create(
        moto_sys::SysHandle::NONE,
        0,
        &full_url,
    )?);
    let load_result = load_binary(buf, address_space.syshandle())?;
    let res = crate::load::load_vdso(address_space.syshandle().as_u64());
    if res != moto_rt::E_OK {
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

    // TODO: remove CAP_LOG when the runtime is stabilized.
    let mut caps = moto_sys::caps::CAP_SPAWN | moto_sys::caps::CAP_LOG;
    // Find MOTURUS_CAPS env var.
    for (k, v) in &mut env {
        if *k == moto_sys::caps::MOTURUS_CAPS_ENV_KEY.as_bytes() {
            *k = "".as_bytes(); // Clear the key: see env::create_remote_env().
            let v = core::str::from_utf8(v).map_err(|_| moto_rt::E_INVALID_ARGUMENT)?;
            if let Ok(env_caps) = u64::from_str_radix(v.trim_start_matches("0x"), 16) {
                caps = env_caps;
            } else {
                crate::moto_log!("could not parse caps {}", v);
            }
        }
    }

    // Create the process from the address space.
    let proc_url = alloc::format!("process:entry_point={};capabilities={}", load_result, caps);
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

    let mut args1 = Vec::new();
    args1.push(exe.as_bytes());
    if let Some(arg) = prepend_arg.as_ref() {
        args1.push(arg.as_bytes());
    }

    unsafe {
        let pd = remote_process_data.as_mut().unwrap();
        pd.args = create_remote_args(address_space.syshandle(), &args1, &args, true)?;
        pd.env = create_remote_env(address_space.syshandle(), env)?;
    }

    let (stdin, stdout, stderr) =
        crate::stdio::create_child_stdio(process.syshandle(), remote_process_data, args_rt)?;

    let main_thread = moto_sys::SysObj::get(process.syshandle(), 0, "main_thread").unwrap();
    if moto_sys::SysCpu::wake(main_thread).is_ok() {
        // While thread objects extracted from TCB or returned from spawn()
        // must not be put(), this is a cross-process thread handle, and so
        // it must be put().
        moto_sys::SysObj::put(main_thread).unwrap();
        result_rt.handle = process.take().as_u64();
        result_rt.stdin = stdin;
        result_rt.stdout = stdout;
        result_rt.stderr = stderr;

        Ok(())
    } else {
        Err(moto_rt::E_INTERNAL_ERROR)
    }
}

unsafe fn spawn_impl(
    args_rt: &moto_rt::process::SpawnArgsRt,
    result_rt: &mut moto_rt::process::SpawnResult,
) -> Result<(), ErrorCode> {
    // Open the file.
    let program_name = core::slice::from_raw_parts(
        args_rt.prog_name_addr as usize as *const u8,
        args_rt.prog_name_size as usize,
    );
    let program_name =
        core::str::from_utf8(program_name).map_err(|_| moto_rt::E_INVALID_ARGUMENT)?;
    let exe = resolve_exe(program_name)?;

    let fd = moto_rt::fs::open(exe.as_str(), moto_rt::fs::O_READ)?;

    // Check if this is an elf file or a script.
    let file_sz = moto_rt::fs::get_file_attr(fd)
        .inspect_err(|_| {
            moto_rt::fs::close(fd).unwrap();
        })?
        .size;
    if file_sz < 4 {
        moto_rt::fs::close(fd).unwrap();
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }
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
        let res = run_elf(exe, fd, None, args_rt, result_rt);
        moto_rt::fs::close(fd).unwrap();
        return res;
    }

    if is_script(&buf) {
        moto_rt::fs::seek(fd, 0, moto_rt::fs::SEEK_SET).inspect_err(|_| {
            moto_rt::fs::close(fd).unwrap();
        })?;
        let res = run_script(exe, fd, args_rt, result_rt);
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
    match spawn_impl(args_rt.as_ref().unwrap(), result_rt.as_mut().unwrap()) {
        Ok(()) => moto_rt::E_OK,
        Err(err) => err,
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
        if addr == 0 {
            return Vec::new();
        };
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
            // Only sys-io has no args; every other process has them.
            return alloc::vec![b"sys-io"];
        }

        Self::deserialize_vec(self.args)
    }

    pub unsafe fn binary() -> &'static str {
        let ptr: *const ProcessData = Self::ADDR as *const ProcessData;
        if ptr.is_null() {
            // Only sys-io has no args; every other process has them.
            return "sys-io";
        }

        let pdata = ptr.as_ref().unwrap();
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

        let len = *((pos as *const u32).as_ref().unwrap());
        pos += 4;
        let bytes: &[u8] = core::slice::from_raw_parts(pos as *const u8, len as usize);
        core::str::from_utf8(bytes).unwrap()
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
        let mut pos = result_addr as usize;
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
        if arg.is_empty() {
            continue;
        }
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
            if arg.is_empty() {
                continue;
            }
            write_arg(arg.as_str());
        }
    }

    Ok(result_addr as u64)
}
