//! sys-io loading and demand paging: a requester gets a stopped child of
//! its own and is refused what it may not run, a demand-paged image holds the
//! right bytes, an executable stays locked while any child maps it and
//! unlocks when the last one exits, children die cleanly in every state,
//! syscall buffers in untouched pages work, and unusual or malformed images
//! fall back or are refused.

use moto_sys::stats::ProcessInfoV1;
use moto_sys::{SysCpu, SysHandle, SysObj, SysRay};
use moto_sys_io::api_fs::SpawnRequest;
use std::io::{BufRead, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::rc::Rc;

const CHILD: &str = "cold-spawn-child";
const EXEC: u64 = moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC;

const VALUES: usize = 1024;
static WORDS: [&str; 4] = ["alpha", "beta", "gamma", "delta"];
static mut COUNTER: u64 = 7;
static mut ZEROS: [u64; 4096] = [0; 4096];
static NUMBERS: [u64; VALUES] = {
    let mut values = [0; VALUES];
    let mut idx = 0;
    while idx < VALUES {
        values[idx] = (idx as u64) * 2654435761;
        idx += 1;
    }
    values
};
static POINTERS: [&u64; VALUES] = {
    let mut pointers = [&NUMBERS[0]; VALUES];
    let mut idx = 0;
    while idx < VALUES {
        pointers[idx] = &NUMBERS[VALUES - 1 - idx];
        idx += 1;
    }
    pointers
};

// A 9-byte stride walks every page offset, so some relocated pointers cross
// a page boundary and are written half by each page's fill.
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Unaligned {
    tag: u8,
    target: &'static u64,
}
const UNALIGNED: usize = 4096 + 512;
static CROSSING: [Unaligned; UNALIGNED] = {
    let mut entries = [Unaligned {
        tag: 0,
        target: &NUMBERS[0],
    }; UNALIGNED];
    let mut idx = 0;
    while idx < UNALIGNED {
        entries[idx] = Unaligned {
            tag: idx as u8,
            target: &NUMBERS[idx % VALUES],
        };
        idx += 1;
    }
    entries
};

// Read-only bytes spanning many pages, which nothing reads unless asked, so
// that a page of them lies untouched when a syscall is handed a slice of it.
const PROBE_PAGES: usize = 32;
const PROBE: &[u8; PROBE_PAGES * 4096] = &{
    let mut bytes = [b'p'; PROBE_PAGES * 4096];
    bytes[40960] = b'#';
    bytes
};

// Read-only bytes nothing checks: where a test points a relocation.
static RELOC_TARGET: [u8; 16] = [0; 16];
static RELOC_SOURCE: &u64 = &NUMBERS[0];

fn first() -> u64 {
    11
}
fn second() -> u64 {
    13
}
static FUNCTIONS: [fn() -> u64; 2] = [first, second];

/// Checks the relocated, initialized, read-only, and zeroed data of this
/// image against values computed here, and returns a digest that every
/// launch of it must reproduce.
fn image_digest() -> String {
    let mut digest = 0_u64;
    let mut mix = |value: u64| digest = (digest ^ value).wrapping_mul(0x100000001b3);
    // Contents are recomputed rather than compared with another copy of the
    // same read-only data: a page filled from the wrong bytes is caught.
    for (idx, value) in std::hint::black_box(&NUMBERS).iter().enumerate() {
        assert_eq!(*value, (idx as u64) * 2654435761);
    }
    let words = std::hint::black_box(&WORDS);
    let word_bytes: u64 = words.iter().flat_map(|w| w.bytes()).map(u64::from).sum();
    assert_eq!(word_bytes, 1967);
    assert!(
        std::hint::black_box(PROBE)
            .iter()
            .enumerate()
            .all(|(idx, byte)| *byte == if idx == 40960 { b'#' } else { b'p' })
    );
    for word in words {
        for byte in word.bytes() {
            mix(byte as u64);
        }
    }
    for (idx, pointer) in std::hint::black_box(&POINTERS).iter().enumerate() {
        assert_eq!(**pointer, (VALUES - 1 - idx) as u64 * 2654435761);
        mix(**pointer);
    }
    for (idx, entry) in std::hint::black_box(&CROSSING).iter().enumerate() {
        let target = unsafe { core::ptr::addr_of!(entry.target).read_unaligned() };
        assert_eq!(entry.tag, idx as u8);
        assert_eq!(*target, (idx % VALUES) as u64 * 2654435761);
    }
    for function in std::hint::black_box(&FUNCTIONS) {
        mix(function());
    }
    let zeros = unsafe { &mut *std::hint::black_box(core::ptr::addr_of_mut!(ZEROS)) };
    assert!(zeros.iter().all(|word| *word == 0));
    zeros[4095] = 1;
    let counter = unsafe { &mut *std::hint::black_box(core::ptr::addr_of_mut!(COUNTER)) };
    assert_eq!(*counter, 7);
    *counter += 1;
    mix(*counter);
    format!("image-ok {digest:x}")
}

pub fn is_child(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| arg == CHILD)
}

pub fn run_child(args: &[String]) -> ! {
    match args.get(2).map(String::as_str) {
        Some("digest") => println!("{}", image_digest()),
        Some("bss-relocations") => {
            let base: usize = args[3].parse().unwrap();
            assert!(moto_sys::SysMem::virt_to_phys((base + 4096) as u64).is_err());
            // Fault the upper half first, so read-ahead cannot hide a
            // missing relocation on either side of the page boundary.
            unsafe {
                assert_eq!(((base + 4096) as *const u32).read_volatile(), 0x11223344);
                assert!(moto_sys::SysMem::virt_to_phys(base as u64).is_err());
                assert_eq!(((base + 4092) as *const u32).read_volatile(), 0x55667788);
                assert_eq!(((base + 8208) as *const u64).read_volatile(), 0xabcdef);
                let bytes = core::slice::from_raw_parts_mut(base as *mut u8, 4 * 4096);
                for (idx, byte) in bytes.iter().enumerate() {
                    if !(4092..4100).contains(&idx) && !(8208..8216).contains(&idx) {
                        assert_eq!(*byte, 0, "BSS byte {idx}");
                    }
                }
                bytes[4 * 4096 - 1] = 1;
                assert_eq!(std::hint::black_box(bytes)[4 * 4096 - 1], 1);
            }
            println!("bss-relocations-ok");
        }
        Some("syscall-buffer" | "syscall-zero") => {
            let address = if args[2] == "syscall-zero" {
                // This image's first read-only segment starts at zero; its
                // first four bytes are the ASCII ELF magic. Use the raw API
                // because a Rust reference must be non-null, even if mapped.
                0
            } else {
                let base = PROBE.as_ptr() as u64;
                (0..PROBE_PAGES)
                    .map(|idx| base + idx as u64 * 4096)
                    .find(|addr| moto_sys::SysMem::virt_to_phys(*addr).is_err())
                    .expect("an untouched page of the probe table")
            };
            assert!(moto_sys::SysMem::virt_to_phys(address).is_err());
            let result = moto_sys::syscalls::do_syscall(
                ((moto_sys::syscalls::SYS_RAY as u64) << 56) | ((SysRay::OP_LOG as u64) << 48),
                address,
                4,
                0,
                0,
                0,
                0,
            );
            assert!(result.is_ok(), "{result:?}");
            assert!(moto_sys::SysMem::virt_to_phys(address).is_ok());
            println!("syscall-buffer-ok");
        }
        Some("hold") => {
            // Report readiness, then live until stdin closes.
            println!("ready");
            std::io::stdout().flush().unwrap();
            let mut line = String::new();
            while std::io::stdin().lock().read_line(&mut line).unwrap() > 0 {}
        }
        Some("exit-while-faulting") => {
            // One thread faults through relocated pages while the main
            // thread exits; an in-flight relocation read may outlive it.
            std::thread::spawn(|| {
                let mut sum = 0_u64;
                loop {
                    for entry in std::hint::black_box(&CROSSING).iter().step_by(455) {
                        let target = unsafe { core::ptr::addr_of!(entry.target).read_unaligned() };
                        sum = sum.wrapping_add(std::hint::black_box(*target));
                    }
                    std::hint::black_box(sum);
                }
            });
            std::thread::yield_now();
            std::process::exit(7)
        }
        other => panic!("unknown {CHILD} mode {other:?}"),
    }
    std::process::exit(0)
}

/// A child command with null stdin and inherited stderr.
fn child(program: &Path, mode: &str) -> Command {
    let mut command = Command::new(program);
    command
        .args([CHILD, mode])
        .stdin(Stdio::null())
        .stderr(Stdio::inherit());
    command
}

fn digest_of(program: &Path) -> String {
    let output = child(program, "digest").output().unwrap();
    assert!(output.status.success(), "{:?}", output.status);
    String::from_utf8(output.stdout).unwrap()
}

/// A holding child: alive, with its image mapped, until its stdin closes.
fn hold(program: &Path) -> Child {
    let mut child = child(program, "hold")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "ready\n");
    child
}

fn release(mut child: Child) {
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
}

fn assert_refused<T: std::fmt::Debug>(what: &str, result: std::io::Result<T>) {
    let err = result.expect_err(what);
    assert_eq!(
        err.raw_os_error(),
        Some(moto_rt::E_NOT_ALLOWED as i32),
        "{what}: {err:?}"
    );
}

/// A copy of this executable, altered by `patch`, with `perm`.
fn copy(dir: &Path, name: &str, perm: u64, patch: impl FnOnce(&mut Vec<u8>)) -> PathBuf {
    let path = dir.join(name);
    let mut bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    patch(&mut bytes);
    std::fs::write(&path, &bytes).unwrap();
    if perm == EXEC | moto_rt::fs::PERM_WRITE {
        // The own-role transitions are Rw -> Rx -> Rwx.
        moto_rt::fs::set_perm(path.to_str().unwrap(), EXEC).unwrap();
    }
    moto_rt::fs::set_perm(path.to_str().unwrap(), perm).unwrap();
    path
}

/// One FS connection for the whole suite. sys-io abandons a child whose
/// requester is gone right after the response, so the connection must
/// outlive every handle the tests hold, as rt.vdso's outlives its process.
struct Requester {
    runtime: moto_async::LocalRuntime,
    client: Rc<moto_io::fs::FsClient>,
}

impl Requester {
    fn new() -> Self {
        let mut runtime = moto_async::LocalRuntime::new();
        let client = runtime.block_on(async { moto_io::fs::FsClient::connect().unwrap() });
        Self { runtime, client }
    }

    /// Requests a child built from `program` with `capabilities`, as this
    /// process; the response is the child's handle in our table.
    fn request(&mut self, program: &Path, capabilities: u64, name: &str) -> moto_rt::Result<u64> {
        let path = program.to_str().unwrap().to_owned();
        let client = &self.client;
        self.runtime.block_on(async {
            let (entry_id, _) = client.stat(&path).await?;
            client
                .spawn(&SpawnRequest {
                    entry_id,
                    capabilities,
                    detached: false,
                    debug_name: name.to_owned(),
                })
                .await
        })
    }
}

fn our_capabilities() -> u64 {
    moto_sys::ProcessStaticPage::get().capabilities
}

/// Kills a child that was never woken, which completes its exit, and lets
/// go of it.
fn kill_unstarted(handle: SysHandle, what: &str) {
    SysCpu::kill(handle).unwrap();
    crate::raw_spawn::wait_exit(handle, what);
    SysObj::put(handle).unwrap();
}

fn test_image_contents() {
    let faults = crate::tcp::read_sys_io_metric("pager.faults");
    let program = std::env::current_exe().unwrap();
    let digest = digest_of(&program);
    assert!(digest.starts_with("image-ok "), "{digest}");
    assert!(crate::tcp::read_sys_io_metric("pager.faults") > faults);
    println!("cold_spawn::test_image_contents PASS");
}

/// Eight children at once, with ordinary file I/O going on beside them.
fn test_concurrent_launches(dir: &Path) {
    let program = std::env::current_exe().unwrap();
    let expected = digest_of(&program);
    let data: Vec<u8> = (0..1_u32 << 20).map(|idx| (idx % 251) as u8).collect();
    let source = dir.join("io-source");
    std::fs::write(&source, &data).unwrap();

    let children: Vec<Child> = (0..8)
        .map(|_| {
            child(&program, "digest")
                .stdout(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let copy = dir.join("io-copy");
    std::fs::copy(&source, &copy).unwrap();
    assert_eq!(std::fs::read(&copy).unwrap(), data);
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert_eq!(expected, String::from_utf8(output.stdout).unwrap());
    }
    std::fs::remove_file(&source).unwrap();
    std::fs::remove_file(&copy).unwrap();
    println!("cold_spawn::test_concurrent_launches PASS");
}

fn test_executable_lock(dir: &Path) {
    let program = copy(dir, "locked", EXEC | moto_rt::fs::PERM_WRITE, |_| {});
    let other = copy(dir, "other", EXEC, |_| {});
    let first = hold(&program);
    let second = hold(&program);

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&program)
        .unwrap();
    assert_refused("write", file.write_all(b"x").and_then(|_| file.flush()));
    assert_refused("truncate", file.set_len(0));
    drop(file);
    assert_refused("delete", std::fs::remove_file(&program));
    assert_refused("rename", std::fs::rename(&program, dir.join("renamed")));
    assert_refused("replace", std::fs::rename(&other, &program));
    let mut permissions = std::fs::metadata(&program).unwrap().permissions();
    permissions.set_readonly(true);
    assert_refused("chmod", std::fs::set_permissions(&program, permissions));
    assert!(
        std::fs::copy(&other, &program).is_err(),
        "copy onto a mapped executable"
    );

    // Both children map the file; it stays locked until the last one exits,
    // and is unlocked as soon as that exit is visible.
    release(first);
    assert_refused("delete with one child left", std::fs::remove_file(&program));
    release(second);
    std::fs::write(&program, b"unlocked").unwrap();
    std::fs::remove_file(&program).unwrap();
    std::fs::remove_file(&other).unwrap();

    // A relocation into read-only data selects eager loading. The stopped
    // child holds no executable reference once construction has finished.
    let eager = copy(dir, "eager", EXEC, |b| retarget_relocation_into_rodata(b));
    let mut requester = Requester::new();
    let handle = SysHandle::from_u64(
        requester
            .request(&eager, our_capabilities(), "eager")
            .unwrap(),
    );
    std::fs::rename(&eager, dir.join("eager-renamed")).unwrap();
    kill_unstarted(handle, "eager");
    std::fs::remove_file(dir.join("eager-renamed")).unwrap();
    println!("cold_spawn::test_executable_lock PASS");
}

/// A killed child releases its mapping references like an exiting one.
fn test_killed_child_unlocks(dir: &Path) {
    let program = copy(dir, "killed", EXEC, |_| {});
    let mut child = hold(&program);
    assert_refused("delete while mapped", std::fs::remove_file(&program));
    child.kill().unwrap();
    child.wait().unwrap();
    std::fs::remove_file(&program).unwrap();
    println!("cold_spawn::test_killed_child_unlocks PASS");
}

/// A child killed right after it was woken is most likely parked on its
/// first instruction fetch; its exit must complete and unlock the file.
fn test_kill_during_startup(dir: &Path) {
    let program = copy(dir, "startup", EXEC, |_| {});
    for _ in 0..20 {
        let mut child = child(&program, "hold")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
    }
    std::fs::remove_file(&program).unwrap();
    println!("cold_spawn::test_kill_during_startup PASS");
}

/// A process exit completes while another of its threads is faulting.
fn test_exit_while_faulting(dir: &Path) {
    let program = copy(dir, "exit", EXEC | moto_rt::fs::PERM_WRITE, |_| {});
    let bytes = std::fs::read(&program).unwrap();
    let (table, size) = rela_table(&bytes);
    let original = &bytes[table..table + size];
    let mut changed = original.to_vec();
    for record in changed.as_chunks_mut::<24>().0 {
        record[..8].fill(0xff); // An old serve must not decode this destination.
    }
    for _ in 0..20 {
        let status = child(&program, "exit-while-faulting")
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(7), "{status:?}");
        // Exit releases the executable lock even if a serve is still in
        // flight. Overwrite its records, then restore them for the next child.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&program)
            .unwrap();
        for records in [&changed[..], original] {
            file.seek(SeekFrom::Start(table as u64)).unwrap();
            file.write_all(records).unwrap();
            file.flush().unwrap();
        }
    }
    std::fs::remove_file(&program).unwrap();
    println!("cold_spawn::test_exit_while_faulting PASS");
}

/// A static string on a page no instruction touched is still a valid
/// syscall argument: the kernel names the absent page and the syscall
/// wrapper faults it in and retries.
fn test_syscall_buffer(mode: &str) {
    let misses_before = crate::admission::kernel_metric_at(
        "mem.file_paged_syscall_misses",
        moto_sys::stats::PID_KERNEL,
    );
    let output = child(&std::env::current_exe().unwrap(), mode)
        // Default child capabilities drop CAP_LOG; keep ours.
        .env(
            moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
            format!("0x{:x}", moto_sys::ProcessStaticPage::get().capabilities),
        )
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.status);
    assert_eq!(output.stdout, b"syscall-buffer-ok\n");
    assert!(
        crate::admission::kernel_metric_at(
            "mem.file_paged_syscall_misses",
            moto_sys::stats::PID_KERNEL,
        ) > misses_before,
        "the kernel never reported the absent page"
    );
    println!("cold_spawn::test_syscall_buffer({mode}) PASS");
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_W: u32 = 2;

/// (type, flags, file offset, address, file size, memory size) per program
/// header.
fn program_headers(bytes: &[u8]) -> Vec<(u32, u32, u64, u64, u64, u64)> {
    let phoff = u64_at(bytes, 32) as usize;
    let phnum = u16::from_le_bytes([bytes[56], bytes[57]]) as usize;
    (0..phnum)
        .map(|idx| {
            let at = phoff + idx * 56;
            (
                u32_at(bytes, at),
                u32_at(bytes, at + 4),
                u64_at(bytes, at + 8),
                u64_at(bytes, at + 16),
                u64_at(bytes, at + 32),
                u64_at(bytes, at + 40),
            )
        })
        .collect()
}

/// The file offset of the first program header of type `p_type`.
fn phdr(bytes: &[u8], p_type: u32) -> usize {
    let phoff = u64_at(bytes, 32) as usize;
    let phnum = u16::from_le_bytes([bytes[56], bytes[57]]) as usize;
    (0..phnum)
        .map(|idx| phoff + idx * 56)
        .find(|at| u32_at(bytes, *at) == p_type)
        .unwrap()
}

/// The file offset and byte size of the RELA table the dynamic section names.
fn rela_table(bytes: &[u8]) -> (usize, usize) {
    let headers = program_headers(bytes);
    let (_, _, dyn_offset, _, dyn_size, _) = headers
        .iter()
        .find(|h| h.0 == PT_DYNAMIC)
        .expect("a dynamic section");
    let (mut rela, mut relasz) = (0, 0);
    for entry in bytes[*dyn_offset as usize..(*dyn_offset + *dyn_size) as usize]
        .as_chunks::<16>()
        .0
    {
        match u64_at(entry, 0) {
            0 => break,
            7 => rela = u64_at(entry, 8),
            8 => relasz = u64_at(entry, 8),
            _ => {}
        }
    }
    let (_, _, offset, vaddr, _, _) = headers
        .iter()
        .find(|h| h.0 == PT_LOAD && (h.3..h.3 + h.4).contains(&rela))
        .expect("the relocation table inside a segment");
    ((rela - vaddr + offset) as usize, relasz as usize)
}

/// Points an otherwise unused relocation into read-only data. Images are
/// linked at their run address, so the parent's address of the target is the
/// child's too. sys-io cannot demand-page a relocated read-only page and
/// builds such an image eagerly.
fn retarget_relocation_into_rodata(bytes: &mut [u8]) {
    let (table, size) = rela_table(bytes);
    let source = core::ptr::addr_of!(RELOC_SOURCE) as u64;
    let at = (table..table + size)
        .step_by(24)
        .find(|at| u64_at(bytes, *at) == source)
        .expect("the unused pointer's relocation");
    let target = RELOC_TARGET.as_ptr() as u64;
    bytes[at..at + 8].copy_from_slice(&target.to_le_bytes());
}

/// The custom region supports eager mappings, but cannot be file-paged.
fn test_high_segment(dir: &Path) {
    let path = copy(dir, "high-segment", EXEC, |bytes| {
        let at = phdr(bytes, 4); // Replace the ignored PT_NOTE after the load headers.
        bytes[at..at + 56].fill(0);
        bytes[at..at + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&4_u32.to_le_bytes()); // Read-only.
        // Leave the region's first page to the runtime's ProcessData.
        let address = moto_sys::CUSTOM_USERSPACE_REGION_START + (1 << 30);
        bytes[at + 16..at + 24].copy_from_slice(&address.to_le_bytes());
        for field in [32, 40, 48] {
            bytes[at + field..at + field + 8].copy_from_slice(&4096_u64.to_le_bytes());
        }
    });
    assert_eq!(
        digest_of(&path),
        digest_of(&std::env::current_exe().unwrap())
    );
    std::fs::remove_file(&path).unwrap();
    println!("cold_spawn::test_high_segment PASS");
}

/// Images the paged loader hands to a simpler plan still run correctly: a
/// relocation table not sorted by address loads its writable segments
/// eagerly, a relocation into read-only data loads the whole image eagerly.
fn test_relocation_fallbacks(dir: &Path) {
    const RECORD: usize = 24;
    let program = std::env::current_exe().unwrap();
    let expected = digest_of(&program);
    let bytes = std::fs::read(&program).unwrap();
    let (table, size) = rela_table(&bytes);
    let writable: Vec<(u64, u64)> = program_headers(&bytes)
        .iter()
        .filter(|h| h.0 == PT_LOAD && h.1 & PF_W != 0)
        .map(|h| (h.3, h.3 + h.5))
        .collect();
    let offsets: Vec<u64> = (0..size / RECORD)
        .map(|idx| u64_at(&bytes, table + idx * RECORD))
        .collect();
    let in_one_segment = |a: u64, b: u64| {
        writable
            .iter()
            .any(|(start, end)| (*start..*end).contains(&a) && (*start..*end).contains(&b))
    };
    let pair = (0..offsets.len().saturating_sub(1))
        .find(|&idx| {
            offsets[idx] < offsets[idx + 1] && in_one_segment(offsets[idx], offsets[idx + 1])
        })
        .expect("two ascending relocations in one writable segment");

    let unsorted = copy(dir, "unsorted", EXEC, |b| {
        let at = table + pair * RECORD;
        let (first, second) = b[at..at + 2 * RECORD].split_at_mut(RECORD);
        first.swap_with_slice(second);
    });
    assert_eq!(expected, digest_of(&unsorted));

    let rodata = copy(dir, "rodata-reloc", EXEC, |b| {
        retarget_relocation_into_rodata(b)
    });
    assert_eq!(expected, digest_of(&rodata));

    std::fs::remove_file(&unsorted).unwrap();
    std::fs::remove_file(&rodata).unwrap();
    println!("cold_spawn::test_relocation_fallbacks PASS");
}

/// Add a writable segment with a copied relocation table and targets in
/// its BSS. The final page has neither file bytes nor relocations.
fn test_bss_relocations(dir: &Path) {
    const ADDRESS: u64 = 1 << 30;
    let mut bss = 0;
    let path = copy(dir, "bss-relocations", EXEC, |bytes| {
        let (table, size) = rela_table(bytes);
        let offset = bytes.len().next_multiple_of(4096);
        let filesz = size + 2 * 24;
        bss = ADDRESS + filesz.next_multiple_of(4096) as u64;
        bytes.resize(offset, 0);
        bytes.extend_from_within(table..table + size);
        for (target, value) in [(bss + 4092, 0x1122334455667788_u64), (bss + 8208, 0xabcdef)] {
            bytes.extend_from_slice(&target.to_le_bytes());
            bytes.extend_from_slice(&8_u64.to_le_bytes()); // R_X86_64_RELATIVE.
            bytes.extend_from_slice(&value.to_le_bytes());
        }

        let at = phdr(bytes, 4); // Replace PT_NOTE after the load headers.
        bytes[at..at + 56].fill(0);
        bytes[at..at + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&6_u32.to_le_bytes()); // R+W.
        for (field, value) in [
            (8, offset as u64),
            (16, ADDRESS),
            (32, filesz as u64),
            (40, bss - ADDRESS + 4 * 4096),
            (48, 4096),
        ] {
            bytes[at + field..at + field + 8].copy_from_slice(&value.to_le_bytes());
        }
        let dynamic = phdr(bytes, PT_DYNAMIC);
        let start = u64_at(bytes, dynamic + 8) as usize;
        let end = start + u64_at(bytes, dynamic + 32) as usize;
        for entry in bytes[start..end].as_chunks_mut::<16>().0 {
            let value = match u64_at(entry, 0) {
                0 => break,
                7 => ADDRESS,       // DT_RELA.
                8 => filesz as u64, // DT_RELASZ.
                _ => continue,
            };
            entry[8..].copy_from_slice(&value.to_le_bytes());
        }
    });
    for _ in 0..2 {
        let output = child(&path, "bss-relocations")
            .arg(bss.to_string())
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.status);
        assert_eq!(output.stdout, b"bss-relocations-ok\n");
    }
    std::fs::remove_file(&path).unwrap();
    println!("cold_spawn::test_bss_relocations PASS");
}

/// Images the parser refuses are refused as requests, and as spawns through
/// std; sys-io goes on serving.
fn test_malformed_images(dir: &Path, requester: &mut Requester) {
    type Patch = fn(&mut Vec<u8>);
    let cases: [(&str, Patch); 7] = [
        ("phoff-past-end", |b| {
            let len = b.len() as u64;
            b[32..40].copy_from_slice(&len.to_le_bytes());
        }),
        ("no-phdrs", |b| {
            b[56..58].copy_from_slice(&0_u16.to_le_bytes())
        }),
        ("truncated", |b| b.truncate(100)),
        ("wrong-machine", |b| {
            b[18..20].copy_from_slice(&3_u16.to_le_bytes())
        }),
        ("filesz-over-memsz", |b| {
            let at = phdr(b, PT_LOAD);
            let memsz = u64_at(b, at + 40);
            b[at + 32..at + 40].copy_from_slice(&(memsz + 1).to_le_bytes());
        }),
        ("file-range-past-end", |b| {
            let at = phdr(b, PT_LOAD);
            let len = b.len() as u64;
            b[at + 8..at + 16].copy_from_slice(&len.to_le_bytes());
        }),
        ("write-execute", |b| {
            let at = phdr(b, PT_LOAD);
            b[at + 4..at + 8].copy_from_slice(&7_u32.to_le_bytes());
        }),
    ];
    let ours = our_capabilities();
    for (name, patch) in cases {
        let path = copy(dir, name, EXEC, patch);
        assert_eq!(
            requester.request(&path, ours, name),
            Err(moto_rt::Error::InvalidArgument),
            "{name}"
        );
        let err = child(&path, "digest")
            .stdout(Stdio::null())
            .status()
            .expect_err(name);
        assert_eq!(
            err.raw_os_error(),
            Some(moto_rt::E_INVALID_ARGUMENT as i32),
            "{name}: {err:?}"
        );
        std::fs::remove_file(&path).unwrap();
    }
    // sys-io is unharmed.
    let program = std::env::current_exe().unwrap();
    assert!(digest_of(&program).starts_with("image-ok "));
    println!("cold_spawn::test_malformed_images PASS");
}

/// The request itself: the handle is ours, the child is ours and carries the
/// name we gave it, a never-woken child can be killed, and our capabilities
/// bound the child's.
fn test_direct_request(dir: &Path, requester: &mut Requester) {
    let what = "cold_spawn::test_direct_request";
    let program = copy(dir, "direct", EXEC, |_| {});
    let ours = our_capabilities();
    let handle = SysHandle::from_u64(
        requester
            .request(&program, ours, "cold-spawn-direct")
            .unwrap(),
    );
    let pid = SysRay::process_pid(handle).unwrap();
    let mut info = [ProcessInfoV1::default(); 1];
    assert_eq!(ProcessInfoV1::list(pid, &mut info).unwrap(), 1);
    assert_eq!(info[0].pid, pid);
    assert_eq!(info[0].parent_pid, moto_sys::current_pid());
    assert_eq!(info[0].debug_name(), "cold-spawn-direct");

    // A capability the requester lacks is refused by the kernel, as the
    // requester's own; a System requester may grant anything.
    if ours & moto_sys::caps::CAP_SYS == 0 {
        assert_eq!(
            requester.request(
                &program,
                ours | moto_sys::caps::CAP_IO_MANAGER,
                "cold-spawn-denied"
            ),
            Err(moto_rt::Error::NotAllowed)
        );
    } else {
        println!("{what}: System requester, denial not tested");
    }

    kill_unstarted(handle, what);
    std::fs::remove_file(&program).unwrap();
    println!("{what} PASS");
}

/// Only a regular file the requester may read and execute is loaded.
fn test_unauthorized_entries(dir: &Path, requester: &mut Requester) {
    let ours = our_capabilities();
    assert_eq!(
        requester.request(dir, ours, "cold-spawn-directory"),
        Err(moto_rt::Error::InvalidArgument)
    );
    let unexecutable = copy(dir, "unexecutable", moto_rt::fs::PERM_READ, |_| {});
    assert_eq!(
        requester.request(&unexecutable, ours, "cold-spawn-unexecutable"),
        Err(moto_rt::Error::NotAllowed)
    );
    std::fs::remove_file(&unexecutable).unwrap();
    println!("cold_spawn::test_unauthorized_entries PASS");
}

/// A requester that closes its channel before the response: sys-io serves
/// the request and abandons the child, which would otherwise sit in the
/// requester's handle table, stopped, until the requester exits. Two
/// arrangements make it deterministic: the channel is closed only once the
/// child exists, so it is the handoff that fails and not the request, and
/// the response ring is full by then, so sys-io cannot send the response
/// before it finds the client gone.
fn test_abandoned_request(dir: &Path, requester: &mut Requester) {
    use moto_ipc::io_channel::QUEUE_SIZE;
    use moto_sys_io::api_fs;
    use std::time::{Duration, Instant};

    let program = copy(dir, "abandoned", EXEC, |_| {});
    let path = program.to_str().unwrap().to_owned();
    let our_pid = moto_sys::current_pid();
    let name = "cold-spawn-abandoned";
    let child_listed = || {
        let mut processes = vec![ProcessInfoV1::default(); 1024];
        let count = ProcessInfoV1::list(moto_sys::stats::PID_SYSTEM, &mut processes).unwrap();
        processes[..count].iter().any(|process| {
            process.parent_pid == our_pid
                && process.active != 0
                && process.debug_name().contains(name)
        })
    };
    let wait_listed = |listed: bool, what: &str| {
        let deadline = Instant::now() + Duration::from_secs(10);
        while child_listed() != listed {
            assert!(Instant::now() < deadline, "{what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    };

    let requests_before = crate::tcp::read_sys_io_metric("spawn.requests");
    let client = &requester.client;
    let channel = requester.runtime.block_on(async {
        let (entry_id, _) = client.stat(&path).await.unwrap();
        let (sender, mut receiver) = moto_ipc::io_channel::connect(api_fs::FS_URL).unwrap();
        // One request answered: the connection is accepted and served.
        let mut msg = api_fs::metadata_msg_encode(entry_id);
        msg.id = 1;
        sender.send(msg).await.unwrap();
        let resp = receiver.recv().await.unwrap();
        assert_eq!(resp.id, 1);
        api_fs::metadata_resp_decode(resp, &sender).unwrap();
        // Responses nobody reads, as many as the ring holds.
        for id in 2..2 + QUEUE_SIZE {
            let mut msg = api_fs::metadata_msg_encode(entry_id);
            msg.id = id;
            sender.send(msg).await.unwrap();
        }
        let page = sender.alloc_page(u64::MAX).await.unwrap();
        let mut msg = api_fs::spawn_msg_encode(
            &SpawnRequest {
                entry_id,
                capabilities: our_capabilities(),
                detached: false,
                debug_name: name.to_owned(),
            },
            page,
        );
        msg.id = 2 + QUEUE_SIZE;
        sender.send(msg).await.unwrap();
        (sender, receiver)
    });
    wait_listed(true, "sys-io did not build the abandoned child");
    assert!(crate::tcp::read_sys_io_metric("spawn.requests") > requests_before);
    // Gone before the response can be delivered.
    drop(channel);
    wait_listed(
        false,
        "the abandoned child remains, held by a handle its requester never learned",
    );
    std::fs::remove_file(&program).unwrap();
    println!("cold_spawn::test_abandoned_request PASS");
}

/// A paged image commits all of its pages when it is mapped: at the memory
/// floor the spawn is refused up front, and no child runs to die later.
fn test_spawn_under_memory_floor(dir: &Path) {
    use moto_sys::stats::AdmissionStats;

    let program = copy(dir, "floor", EXEC, |_| {});
    assert!(
        std::fs::metadata(&program).unwrap().len() >= 2 << 20,
        "the image is too small to exceed the squeeze band"
    );
    // Hold free memory a little above the low watermark: the pressure flag
    // stays down, so sys-io keeps serving, while a whole image's pages can
    // no longer be committed over the user floor.
    let target = AdmissionStats::get().unwrap().pressure_low_pages + 256;
    let mut squeeze = crate::subcommand::spawn();
    let mut squeeze_out = std::io::BufReader::new(squeeze.std_child().stdout.take().unwrap());
    squeeze.pressure_squeeze(target);
    let mut line = String::new();
    squeeze_out.read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "squeezed");
    assert!(!moto_sys::memory_pressure(), "the squeeze raised the flag");

    let result = child(&program, "digest").stdout(Stdio::null()).status();

    squeeze.do_exit(0);
    assert!(squeeze.wait().unwrap().success());
    drop(squeeze);

    let err = result.expect_err("a paged image was committed at the floor");
    assert_eq!(
        err.raw_os_error(),
        Some(moto_rt::E_OUT_OF_MEMORY as i32),
        "{err:?}"
    );
    // Nothing of the refused child remains: the file is not locked.
    std::fs::remove_file(&program).unwrap();
    println!("cold_spawn::test_spawn_under_memory_floor PASS");
}

pub fn run_all_tests() {
    let dir = crate::temp_path(&format!("systest-cold-spawn-{}", moto_sys::current_pid()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();

    test_image_contents();
    test_concurrent_launches(&dir);
    test_executable_lock(&dir);
    test_killed_child_unlocks(&dir);
    test_kill_during_startup(&dir);
    test_exit_while_faulting(&dir);
    if crate::has_cap_log() {
        test_syscall_buffer("syscall-buffer");
        test_syscall_buffer("syscall-zero");
    }
    test_high_segment(&dir);
    test_relocation_fallbacks(&dir);
    test_bss_relocations(&dir);
    let mut requester = Requester::new();
    test_malformed_images(&dir, &mut requester);
    test_direct_request(&dir, &mut requester);
    test_unauthorized_entries(&dir, &mut requester);
    test_abandoned_request(&dir, &mut requester);
    drop(requester);
    test_spawn_under_memory_floor(&dir);

    std::fs::remove_dir_all(&dir).unwrap();
    println!("cold_spawn::run_all_tests PASS");
}
