//! sys-io's spawn request: a requester gets a stopped child of its own, is
//! refused a capability it lacks, entries it may not run and malformed
//! images, and a requester gone before the response loses the child rather
//! than holding it, stopped, until its own exit.

use moto_sys::stats::ProcessInfoV1;
use moto_sys::{SysCpu, SysHandle, SysObj, SysRay};
use moto_sys_io::api_fs::SpawnRequest;
use std::path::{Path, PathBuf};
use std::rc::Rc;

const EXEC: u64 = moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC;

/// A copy of this executable, altered by `patch`, with `perm`.
fn copy(dir: &Path, name: &str, perm: u64, patch: impl FnOnce(&mut Vec<u8>)) -> PathBuf {
    let path = dir.join(name);
    let mut bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    patch(&mut bytes);
    std::fs::write(&path, &bytes).unwrap();
    moto_rt::fs::set_perm(path.to_str().unwrap(), perm).unwrap();
    path
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

const PT_LOAD: u32 = 1;

/// The file offset of the first program header of type `p_type`.
fn phdr(bytes: &[u8], p_type: u32) -> usize {
    let phoff = u64_at(bytes, 32) as usize;
    let phnum = u16::from_le_bytes([bytes[56], bytes[57]]) as usize;
    (0..phnum)
        .map(|idx| phoff + idx * 56)
        .find(|at| u32_at(bytes, *at) == p_type)
        .unwrap()
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

/// Images the parser refuses are refused as requests; sys-io goes on
/// serving.
fn test_malformed_images(dir: &Path, requester: &mut Requester) {
    let what = "cold_spawn::test_malformed_images";
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
        std::fs::remove_file(&path).unwrap();
    }
    let program = copy(dir, "well-formed", EXEC, |_| {});
    let handle = SysHandle::from_u64(
        requester
            .request(&program, ours, "cold-spawn-well-formed")
            .unwrap(),
    );
    kill_unstarted(handle, what);
    std::fs::remove_file(&program).unwrap();
    println!("{what} PASS");
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

pub fn run_all_tests() {
    let dir = crate::temp_path(&format!("systest-cold-spawn-{}", moto_sys::current_pid()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();

    let mut requester = Requester::new();
    test_direct_request(&dir, &mut requester);
    test_unauthorized_entries(&dir, &mut requester);
    test_malformed_images(&dir, &mut requester);
    test_abandoned_request(&dir, &mut requester);

    std::fs::remove_dir_all(&dir).unwrap();
    println!("cold_spawn::run_all_tests PASS");
}
