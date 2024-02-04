use super::stdio::StdioKind;
use crate::external::elfloader;
use crate::external::elfloader::*;
use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use moto_sys::syscalls::*;
use moto_sys::ErrorCode;

pub struct CommandRt {
    program: String,
    args: Vec<String>,
    current_directory: Option<String>,
    stdin: Option<StdioRt>,
    stdout: Option<StdioRt>,
    stderr: Option<StdioRt>,
}

impl CommandRt {
    pub fn new(program: &str) -> Self {
        CommandRt {
            program: program.to_owned(),
            args: Vec::new(),
            current_directory: None,
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    pub fn arg(&mut self, arg: &str) {
        self.args.push(arg.to_owned());
    }

    pub fn cwd(&mut self, dir: &str) {
        self.current_directory = Some(dir.to_owned())
    }

    pub fn stdin(&mut self, stdin: StdioRt) {
        self.stdin = Some(stdin);
    }

    pub fn stdout(&mut self, stdout: StdioRt) {
        self.stdout = Some(stdout);
    }

    pub fn stderr(&mut self, stderr: StdioRt) {
        self.stderr = Some(stderr);
    }

    pub fn get_program(&self) -> &str {
        &self.program
    }

    pub fn get_args(&self) -> &Vec<String> {
        &self.args
    }

    pub fn get_current_dir(&self) -> Option<&String> {
        self.current_directory.as_ref()
    }
}

pub struct Process {
    handle: SysHandle,
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.handle.is_none() {
            SysCtl::put(self.handle).unwrap();
        }
    }
}

impl Process {
    pub fn kill(&mut self) -> Result<(), ErrorCode> {
        if self.handle.is_none() {
            return Err(ErrorCode::InvalidArgument);
        }
        SysCpu::kill(self.handle)
    }

    fn convert_exit_status(exit_status: u64) -> i32 {
        if exit_status & 0xffff_ffff_0000_0000 == 0 {
            // Map u64 to i32.
            let status_u32: u32 = exit_status as u32;
            unsafe { core::mem::transmute::<u32, i32>(status_u32) }
        } else {
            // The process exited not via Rust's std::process::exit, but
            // via a lower-level syscall. Don't try to second-guess what
            // it wanted to say, just return a -1.
            -1
        }
    }

    pub fn wait(&mut self) -> Result<i32, ErrorCode> {
        if self.handle.is_none() {
            return Err(ErrorCode::InvalidArgument);
        }

        SysCpu::wait(&mut [self.handle], SysHandle::NONE, SysHandle::NONE, None)?;

        let exit_status = SysCtl::process_status(self.handle)?.unwrap();
        Ok(Self::convert_exit_status(exit_status))
    }

    pub fn try_wait(&mut self) -> Result<Option<i32>, ErrorCode> {
        if self.handle.is_none() {
            return Err(ErrorCode::InvalidArgument);
        }

        let exit_status = SysCtl::process_status(self.handle)?;
        Ok(exit_status.map(Self::convert_exit_status))
    }
}

// Loads a binary; returns the entry point.
fn load_binary(bytes: &[u8], address_space: SysHandle) -> Result<u64, ErrorCode> {
    let elf_binary = match ElfBinary::new(bytes) {
        Err(_) => {
            return Err(ErrorCode::InvalidArgument);
        }
        Ok(binary) => binary,
    };

    if elf_binary.get_arch() != Machine::X86_64 {
        return Err(ErrorCode::InvalidArgument);
    }

    if elf_binary.interpreter().is_some() {
        return Err(ErrorCode::InvalidArgument);
    }

    let mut elf_loader = Loader {
        address_space,
        relocated: false,
        mapped_regions: BTreeMap::default(),
    };
    match elf_binary.load(&mut elf_loader) {
        Err(_) => Err(ErrorCode::InvalidArgument),
        Ok(()) => Ok(elf_binary.entry_point()),
    }
}

pub fn spawn(
    command: &mut CommandRt,
    env: Vec<(String, String)>,
    default_stdio: StdioRt,
    needs_stdin: bool,
) -> Result<(Process, StdioPipesRt), ErrorCode> {
    // Open the file.
    let mut opts = super::fs::OpenOptions::new();
    opts.read(true);
    let exe = resolve_exe(command.program.as_str())?;
    let program_bytes = super::fs::File::open(exe.as_str(), &opts)?;

    // Check if this is an elf file or a script.
    let file_sz = program_bytes.size();
    if file_sz < 4 {
        return Err(ErrorCode::InvalidArgument);
    }
    let mut buf: [u8; 4] = [0; 4];

    let sz = program_bytes.read(&mut buf)?;
    if sz != 4 {
        return Err(ErrorCode::UnexpectedEof);
    }

    if is_elf(&buf) {
        program_bytes.seek(super::fs::SeekFrom::Start(0))?;
        return run_elf(
            exe,
            program_bytes,
            None,
            command,
            env,
            default_stdio,
            needs_stdin,
        );
    }

    if is_script(&buf) {
        program_bytes.seek(super::fs::SeekFrom::Start(0))?;
        return run_script(exe, program_bytes, command, env, default_stdio, needs_stdin);
    }

    return Err(ErrorCode::InvalidArgument);
}

fn run_script(
    script: String,
    program_bytes: super::fs::File,
    command: &mut CommandRt,
    env: Vec<(String, String)>,
    default_stdio: StdioRt,
    needs_stdin: bool,
) -> Result<(Process, StdioPipesRt), ErrorCode> {
    let mut buf: [u8; 256] = [0; 256];

    let sz = program_bytes.read(&mut buf)?;
    assert!(sz <= buf.len());
    let bytes = &buf[0..sz];
    debug_assert!(bytes.len() > 3);
    debug_assert_eq!(bytes[0], b'#');
    debug_assert_eq!(bytes[1], b'!');

    let line = core::str::from_utf8(&bytes[2..]).map_err(|_| ErrorCode::InvalidArgument)?;
    let exe = line
        .lines()
        .next()
        .ok_or(ErrorCode::InvalidArgument)?
        .trim()
        .to_owned();

    let mut opts = super::fs::OpenOptions::new();
    opts.read(true);
    let program_bytes = super::fs::File::open(exe.as_str(), &opts)?;

    run_elf(
        exe,
        program_bytes,
        Some(script),
        command,
        env,
        default_stdio,
        needs_stdin,
    )
}

fn run_elf(
    exe: String,
    program_bytes: super::fs::File,
    prepend_arg: Option<String>,
    command: &mut CommandRt,
    mut env: Vec<(String, String)>,
    default_stdio: StdioRt,
    needs_stdin: bool,
) -> Result<(Process, StdioPipesRt), ErrorCode> {
    // TODO: currently the binary is first fully loaded into RAM, and then
    //       the bytes are copied again as part of ELF loading. There should
    //       be a way to avoid the extra copying. Or even do lazy loading,
    //       i.e. don't load anything from storage until it is actually
    //       needed (this is what Linux does, I believe).

    // First, load the binary info RAM.
    let file_sz = program_bytes.size();
    if file_sz < 4 {
        return Err(ErrorCode::InvalidArgument);
    }

    let (page_size, num_pages) = {
        (
            SysMem::PAGE_SIZE_SMALL,
            moto_sys::align_up(file_sz as u64, SysMem::PAGE_SIZE_SMALL)
                >> SysMem::PAGE_SIZE_SMALL_LOG2,
        )
    };
    let buf_addr = SysMem::alloc(page_size, num_pages)?;
    let buf: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(buf_addr as usize as *mut u8, file_sz as usize) };
    crate::external::scopeguard::defer! {
        // Free the allocated buffer.
        SysMem::free(buf_addr).unwrap();
    }

    let sz = program_bytes.read_all(buf)?;
    if sz != file_sz as usize {
        return Err(ErrorCode::UnexpectedEof);
    }

    let debug_name = match command.args.len() {
        0 => exe.clone(),
        1 => alloc::format!("{} {}", exe, command.args[0]),
        _ => alloc::format!("{} {} ...", exe, command.args[0]),
    };

    // Create an address space for the new process.
    let full_url = alloc::format!(
        "address_space:debug_name={}",
        &moto_sys::url_encode(debug_name.as_str())
    );
    let address_space = RaiiHandle::from(SysCtl::create(SysHandle::NONE, 0, &full_url)?);
    let load_result = load_binary(buf, address_space.syshandle());

    if let Err(err) = load_result {
        return Err(err);
    }

    let mut caps = moto_sys::caps::CAP_SPAWN | moto_sys::caps::CAP_LOG;
    // Find MOTURUS_CAPS env var.
    for (k, v) in &mut env {
        if k.as_str() == moto_sys::caps::MOTURUS_CAPS_ENV_KEY {
            *k = "".to_owned(); // Clear the key: see env::create_remote_env().
            if let Ok(env_caps) = u64::from_str_radix(v.as_str().trim_start_matches("0x"), 16) {
                caps = env_caps;
            } else {
                crate::util::moturus_log!("could not parse caps {}", v);
            }
        }
    }

    // Create the process from the address space.
    let proc_url = alloc::format!(
        "process:entry_point={};capabilities={}",
        load_result.unwrap(),
        caps
    );
    let process = RaiiHandle::from(SysCtl::create(address_space.syshandle(), 0, &proc_url)?);

    // Set up stdio.
    let remote_process_data = create_remote_process_data(address_space.syshandle())?;
    crate::external::scopeguard::defer! {
        SysMem::unmap(
            SysHandle::SELF,
            0,
            u64::MAX,
            remote_process_data as usize as u64,
        )
        .unwrap();
    }

    // Clear PWD.
    for (k, _) in &mut env {
        if k.as_str() == "PWD" {
            *k = "".to_owned(); // Clear the key: see env::create_remote_env().
        }
    }

    if let Some(pwd) = command.current_directory.as_ref() {
        env.push(("PWD".to_owned(), pwd.clone()));
    } else if let Ok(pwd) = super::fs::getcwd() {
        env.push(("PWD".to_owned(), pwd));
    }

    let mut args1 = Vec::new();
    args1.push(exe);
    if let Some(arg) = prepend_arg {
        args1.push(arg);
    }

    unsafe {
        let pd = remote_process_data.as_mut().unwrap();
        pd.args = super::args::create_remote_args(
            address_space.syshandle(),
            &args1,
            &command.args,
            true,
        )?;
        pd.env = super::env::create_remote_env(address_space.syshandle(), env)?;
    }

    let our_pipes = create_child_stdio(
        process.syshandle(),
        remote_process_data,
        command,
        default_stdio,
        needs_stdin,
    )?;

    let main_thread = SysCtl::get(process.syshandle(), 0, "main_thread").unwrap();
    if SysCpu::wake(main_thread).is_ok() {
        // While thread objects extracted from TCB or returned from spawn()
        // must not be put(), this is a cross-process thread handle, and so
        // it must be put().
        SysCtl::put(main_thread).unwrap();
        Ok((
            Process {
                handle: process.take(),
            },
            our_pipes,
        ))
    } else {
        Err(ErrorCode::InternalError)
    }
}

fn create_remote_process_data(
    address_space: SysHandle,
) -> Result<*mut super::rt_api::process::ProcessData, ErrorCode> {
    let flags = SysMem::F_SHARE_SELF | SysMem::F_READABLE;
    let (remote, local) = SysMem::map2(
        address_space,
        flags,
        u64::MAX,
        super::rt_api::process::ProcessData::ADDR,
        SysMem::PAGE_SIZE_SMALL,
        1,
    )?;

    assert_eq!(remote, super::rt_api::process::ProcessData::ADDR);
    Ok(local as usize as *mut super::rt_api::process::ProcessData)
}

pub enum StdioRt {
    Inherit,
    Null,
    MakePipe,
    Pipe(crate::sync_pipe::Pipe),
}

impl StdioRt {
    fn copy(&self) -> Self {
        match self {
            Self::Pipe(_) => panic!("can't copy a pipe"),
            Self::Inherit => Self::Inherit,
            Self::Null => Self::Null,
            Self::MakePipe => Self::MakePipe,
        }
    }
}

pub struct StdioPipesRt {
    pub stdin: Option<crate::sync_pipe::Pipe>,
    pub stdout: Option<crate::sync_pipe::Pipe>,
    pub stderr: Option<crate::sync_pipe::Pipe>,
}

fn create_child_stdio(
    remote_process: SysHandle,
    remote_process_data: *mut super::rt_api::process::ProcessData,
    command: &mut CommandRt,
    default_stdio: StdioRt,
    needs_stdin: bool,
) -> Result<StdioPipesRt, ErrorCode> {
    // If command has stdin/out/err, take those, otherwise use default.
    let stdin = command.stdin.take().map_or(
        {
            if needs_stdin {
                default_stdio.copy()
            } else {
                StdioRt::Null
            }
        },
        |v| v,
    );
    let stdout = command.stdout.take().map_or(default_stdio.copy(), |v| v);
    let stderr = command.stderr.take().map_or(default_stdio.copy(), |v| v);

    let (stdin, stdin_theirs) = create_stdio_pipes(remote_process, stdin, StdioKind::Stdin)?;
    let (stdout, stdout_theirs) = create_stdio_pipes(remote_process, stdout, StdioKind::Stdout)?;
    let (stderr, stderr_theirs) = create_stdio_pipes(remote_process, stderr, StdioKind::Stderr)?;

    unsafe {
        let pd = remote_process_data.as_mut().unwrap();
        pd.stdin = stdin_theirs;
        pd.stdout = stdout_theirs;
        pd.stderr = stderr_theirs;
    }

    Ok(StdioPipesRt {
        stdin,
        stdout,
        stderr,
    })
}

fn create_stdio_pipes(
    remote_process: SysHandle,
    stdio: StdioRt,
    kind: StdioKind,
) -> Result<
    (
        Option<crate::sync_pipe::Pipe>,
        super::rt_api::process::StdioData,
    ),
    ErrorCode,
> {
    fn null_data() -> super::rt_api::process::StdioData {
        super::rt_api::process::StdioData {
            pipe_addr: 0,
            pipe_size: 0,
            handle: 0,
        }
    }
    match stdio {
        StdioRt::Null => Ok((None, null_data())),
        StdioRt::Inherit => {
            let (local_data, remote_data) =
                crate::sync_pipe::make_pair(SysHandle::SELF, remote_process)?;

            let thread = super::stdio::set_relay(kind, local_data).map_err(|err| {
                unsafe {
                    remote_data.unsafe_copy().release(remote_process);
                }
                err
            })?;

            // These relay threads are "detached" below (we release the handles).
            // TODO: remote shutdowns are now detected via bad remote handle IPCs.
            //       Should we set up a protocol to do it explicitly?
            //       But why? On remote errors/panics we need to handle bad IPCs
            //       anyway.
            SysCtl::put(thread).unwrap();
            Ok((
                None,
                super::rt_api::process::StdioData {
                    pipe_addr: remote_data.buf_addr as u64,
                    pipe_size: remote_data.buf_size as u64,
                    handle: remote_data.ipc_handle,
                },
            ))
        }
        StdioRt::MakePipe => {
            let (local_data, remote_data) =
                crate::sync_pipe::make_pair(SysHandle::SELF, remote_process)?;
            if kind.is_reader() {
                Ok((
                    Some(unsafe {
                        crate::sync_pipe::Pipe::Writer(crate::sync_pipe::Writer::new(local_data))
                    }),
                    super::rt_api::process::StdioData {
                        pipe_addr: remote_data.buf_addr as u64,
                        pipe_size: remote_data.buf_size as u64,
                        handle: remote_data.ipc_handle,
                    },
                ))
            } else {
                Ok((
                    Some(unsafe {
                        crate::sync_pipe::Pipe::Reader(crate::sync_pipe::Reader::new(local_data))
                    }),
                    super::rt_api::process::StdioData {
                        pipe_addr: remote_data.buf_addr as u64,
                        pipe_size: remote_data.buf_size as u64,
                        handle: remote_data.ipc_handle,
                    },
                ))
            }
        }
        StdioRt::Pipe(_pipe) => {
            todo!("relay")
        }
    }
}

struct Loader {
    address_space: SysHandle,
    relocated: bool,

    // Map of allocated pages: remote addr -> (local addr, num_pages).
    mapped_regions: BTreeMap<u64, (u64, u64)>,
}

impl Loader {
    unsafe fn write_remotely(&mut self, dst: u64, src: *const u8, sz: u64) {
        assert_eq!(
            dst & (SysMem::PAGE_SIZE_SMALL - 1),
            (src as usize as u64) & (SysMem::PAGE_SIZE_SMALL - 1)
        );
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
        let region_sz = region.2 << SysMem::PAGE_SIZE_SMALL_LOG2;

        assert!(remote_region_start <= dst);
        assert!((dst + sz) <= (region.0 + region_sz));

        let offset = dst - remote_region_start;

        core::intrinsics::copy_nonoverlapping(
            src,
            (local_region_start + offset) as usize as *mut u8,
            sz as usize,
        );
    }
}

impl Drop for Loader {
    fn drop(&mut self) {
        for (_, (addr, _)) in &self.mapped_regions {
            SysMem::unmap(SysHandle::SELF, 0, u64::MAX, *addr).unwrap();
        }
    }
}

impl ElfLoader for Loader {
    fn allocate(&mut self, load_headers: LoadableHeaders<'_, '_>) -> Result<(), ElfLoaderErr> {
        for header in load_headers {
            let vaddr_start = header.virtual_addr() & !(SysMem::PAGE_SIZE_SMALL - 1);
            let vaddr_end = moto_sys::align_up(
                header.virtual_addr() + header.mem_size(),
                SysMem::PAGE_SIZE_SMALL,
            );

            let mut flags = SysMem::F_SHARE_SELF;
            if header.flags().is_read() {
                flags |= SysMem::F_READABLE;
            }
            if header.flags().is_write() {
                flags |= SysMem::F_WRITABLE;
            }

            let num_pages = (vaddr_end - vaddr_start) >> SysMem::PAGE_SIZE_SMALL_LOG2;

            let (remote, local) = SysMem::map2(
                self.address_space,
                flags,
                u64::MAX,
                vaddr_start,
                SysMem::PAGE_SIZE_SMALL,
                num_pages,
            )
            .map_err(|_| ElfLoaderErr::OutOfMemory)?;

            assert_eq!(remote, vaddr_start);
            self.mapped_regions.insert(vaddr_start, (local, num_pages));
        }
        Ok(())
    }

    fn load(&mut self, _flags: Flags, base: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
        unsafe {
            self.write_remotely(base, region.as_ptr(), region.len() as u64);
        }

        Ok(())
    }

    fn relocate(&mut self, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        use elfloader::arch::x86_64::RelocationTypes::*;
        use RelocationType::x86_64;

        let remote_addr: u64 = entry.offset;

        match entry.rtype {
            x86_64(R_AMD64_RELATIVE) => {
                // This type requires addend to be present.
                let addend: u64 = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;

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
            _ => Err(ElfLoaderErr::UnsupportedRelocationEntry),
        }
    }

    fn tls(
        &mut self,
        _tdata_start: VAddr,
        _tdata_length: u64,
        _total_size: u64,
        _align: u64,
    ) -> Result<(), ElfLoaderErr> {
        Err(ElfLoaderErr::UnsupportedAbi)
    }
}

fn resolve_exe(exe: &str) -> Result<String, ErrorCode> {
    if let Ok(attr) = super::fs::stat(exe) {
        if attr.file_type().is_file() {
            return Ok(exe.to_owned());
        }
    }

    // Only "naked" filenames are resolved with $PATH.
    // TODO: be smarter below (slashes in quotes; escaped slashes, etc.)
    if exe.find('/').is_some() {
        return Ok(exe.to_owned());
    }

    let path = super::env::getenv("PATH").ok_or(ErrorCode::InvalidFilename)?;

    // TODO: be smarter below (colons in quotes; escaped colons, etc.)
    let dirs: Vec<&str> = path.split(':').collect();
    for dir in dirs {
        if dir.is_empty() {
            continue;
        }

        let mut fname = dir.to_owned();
        fname.push('/');
        fname.push_str(exe);
        if let Ok(_attr) = super::fs::stat(fname.as_str()) {
            return Ok(fname);
        }
    }

    Err(ErrorCode::InvalidFilename)
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
