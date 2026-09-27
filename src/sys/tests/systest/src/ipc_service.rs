use moto_ipc::sync::{ChannelSize, ClientConnection, LocalServer, RequestHeader, ResponseHeader};
use moto_sys::{SysHandle, SysObj};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdout, Command, Stdio};

const CHILD: &str = "ipc-service-child";
const HOARD: &str = "ipc-service-hoard";
const POOL_GROWTH: &str = "ipc-service-pool-growth";
const CHILD_CAPS: u64 = moto_sys::caps::CAP_SPAWN | moto_sys::caps::CAP_INTERACTIVE;

fn listen(url: &str) -> Result<LocalServer, moto_rt::ErrorCode> {
    LocalServer::new(url, ChannelSize::Small, 4, 1)
}

// Connects with an address that is not a mapped page, so mapping fails.
fn connect_unmapped(url: &str) -> Result<SysHandle, moto_rt::ErrorCode> {
    let url = moto_sys::url_encode(url);
    SysObj::get(
        SysHandle::SELF,
        0,
        &format!("shared:url={url};address=0;page_type=small;page_num=1"),
    )
}

pub fn run_command(args: &[String]) -> bool {
    match args.get(1).map(String::as_str) {
        Some("test-ipc-service-ownership") => run_tests(),
        Some("ipc-service-busy") if args.len() == 3 => {
            assert_eq!(listen(&args[2]).err(), Some(moto_rt::E_INVALID_ARGUMENT));
        }
        Some(CHILD) if args.len() == 3 => run_child(&args[2]),
        Some(HOARD) if args.len() == 2 => run_hoard(),
        Some(POOL_GROWTH) if args.len() == 3 => run_pool_growth(&args[2]),
        _ => return false,
    }
    true
}

fn run_child(url: &str) {
    let mut server = Some(listen(url).unwrap());
    let mut last = SysHandle::NONE;
    let mut duplicate = SysHandle::NONE;
    println!("ready");
    std::io::stdout().flush().unwrap();
    for command in std::io::stdin().lock().lines() {
        match command.unwrap().as_str() {
            command @ ("rpc" | "retry") => {
                let server = server.as_mut().unwrap();
                let mut report_retry = command == "retry";
                // While refills are refused, wait() also returns empty.
                let ready = loop {
                    let ready = server.wait(SysHandle::NONE, &[]).unwrap();
                    if !ready.is_empty() {
                        break ready;
                    }
                    if report_retry {
                        println!("retrying");
                        std::io::stdout().flush().unwrap();
                        report_retry = false;
                    }
                };
                assert_eq!(ready.len(), 1);
                last = ready[0];
                let conn = server.get_connection(last).unwrap();
                assert!(conn.have_req());
                conn.resp::<ResponseHeader>().result = moto_rt::E_OK;
                conn.finish_rpc().unwrap();
            }
            "reap" => assert!(server.as_mut().unwrap().wait(SysHandle::NONE, &[]).is_err()),
            "kick" => {
                let server = server.as_mut().unwrap();
                server.get_connection(last).unwrap().disconnect();
            }
            "duplicate" => duplicate = SysObj::dup(last).unwrap(),
            "close" => drop(server.take().unwrap()),
            "release" => {
                SysObj::put(duplicate).unwrap();
                duplicate = SysHandle::NONE;
            }
            "busy" => assert_eq!(listen(url).err(), Some(moto_rt::E_INVALID_ARGUMENT)),
            "free" => drop(listen(url).unwrap()),
            _ => panic!("unknown IPC service test command"),
        }
        println!("ok");
        std::io::stdout().flush().unwrap();
    }
    assert_eq!(duplicate, SysHandle::NONE);
}

// Keeps free memory at the user floor until stdin closes, taking back any
// memory that other processes free meanwhile. Every mapping is charged 64
// extra pages, so kernel objects, charged 16, take the last pages below that.
fn run_hoard() -> ! {
    use moto_sys::{SysMem, sys_mem::PAGE_SIZE_SMALL};

    std::thread::spawn(|| {
        let _ = std::io::stdin().read_line(&mut String::new());
        std::process::exit(0);
    });
    let pid = std::process::id();
    let object = format!("shared:url={HOARD}-{pid};address=4096;page_type=small;page_num=1");
    let take = |pages| SysMem::alloc(PAGE_SIZE_SMALL, pages).is_ok();
    let fill = || {
        while take(64) {}
        while take(1) {}
        while SysObj::create(SysHandle::SELF, 0, &object).is_ok() {}
    };
    println!("ready");
    fill();
    println!("hoarded");
    loop {
        fill();
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

// Object admission reserves 64 KiB, so the pool must grow in small increments.
// A contiguous pool of this many entries fills 64 KiB, and the next insertion
// would double it to 128 KiB. Larger counts leave the kernel heap bloated for
// the rest of the suite: it does not shrink when the listeners are freed.
fn run_pool_growth(url: &str) -> ! {
    use moto_sys::{SysMem, sys_mem::PAGE_SIZE_SMALL};

    let object = format!("shared:url={url};address=4096;page_type=small;page_num=1");
    for _ in 0..8_192 {
        SysObj::create(SysHandle::SELF, 0, &object).unwrap();
    }
    println!("ready");
    while SysMem::alloc(PAGE_SIZE_SMALL, 64).is_ok() {}
    while SysMem::alloc(PAGE_SIZE_SMALL, 1).is_ok() {}
    // Mapping admission stops above the smaller object charge. The following
    // insertion must succeed without consuming the protected user reserve.
    SysObj::create(SysHandle::SELF, 0, &object).unwrap();
    let stats = moto_sys::stats::AdmissionStats::get().unwrap();
    assert!(stats.free_for_admission() >= stats.user_floor_pages);
    println!("grown");
    loop {
        std::thread::park();
    }
}

struct Peer {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

impl Peer {
    fn start(url: &str) -> Self {
        Self::spawn(&[CHILD, url])
    }

    fn spawn(args: &[&str]) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(args)
            .env(
                moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY,
                format!("0x{CHILD_CAPS:x}"),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut peer = Self { child, stdout };
        peer.expect("ready\n");
        peer
    }

    fn expect(&mut self, expected: &str) {
        let mut line = String::new();
        assert_ne!(self.stdout.read_line(&mut line).unwrap(), 0);
        assert_eq!(line, expected);
    }

    fn send(&mut self, command: &str) {
        writeln!(self.child.stdin.as_mut().unwrap(), "{command}").unwrap();
    }

    fn command(&mut self, command: &str) {
        self.send(command);
        self.expect("ok\n");
    }

    fn rpc(&mut self, client: &mut ClientConnection) {
        self.send("rpc");
        client.req::<RequestHeader>().cmd = 1;
        client.do_rpc(None).unwrap();
        assert_eq!(client.resp::<ResponseHeader>().result, moto_rt::E_OK);
        self.expect("ok\n");
    }

    fn stop(mut self) {
        drop(self.child.stdin.take());
        assert_eq!(self.child.wait().unwrap().code(), Some(0));
    }
}

pub fn run_tests() {
    let url = format!("systest-ipc-owner-{}", std::process::id());
    let mut peer = Peer::start(&url);
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));
    // Each failed mapping leaves the only listener pooled for the next client.
    for _ in 0..8 {
        assert_eq!(connect_unmapped(&url), Err(moto_rt::E_INVALID_ARGUMENT));
    }
    let mut client = ClientConnection::new(ChannelSize::Small).unwrap();
    assert_eq!(client.handle(), SysHandle::NONE);
    client.connect(&url).unwrap();
    assert_eq!(
        SysObj::get_pid(client.handle()).unwrap(),
        u64::from(peer.child.id())
    );
    assert_eq!(
        SysObj::get_capabilities(client.handle()).unwrap(),
        CHILD_CAPS
    );

    // Connecting and a subsequent failed lookup must both retain ownership.
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));
    let mut extra = ClientConnection::new(ChannelSize::Small).unwrap();
    assert_eq!(extra.connect(&url), Err(moto_rt::E_NOT_FOUND));
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));
    peer.rpc(&mut client);
    peer.rpc(&mut client); // Replenishes the exhausted listener pool.
    extra.connect(&url).unwrap();
    assert_eq!(
        SysObj::get_pid(extra.handle()).unwrap(),
        u64::from(peer.child.id())
    );
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));

    // Closing a client does not release the server's endpoint or name.
    extra.disconnect();
    assert_eq!(extra.handle(), SysHandle::NONE);
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));
    peer.command("duplicate");
    peer.command("close");
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));
    peer.command("release");
    let replacement = listen(&url).unwrap();
    client.disconnect(); // Old client cleanup must not affect the replacement.
    peer.command("busy");
    drop(replacement);
    peer.command("free"); // Closing an unconnected listener also releases its name.
    peer.stop();
    assert_eq!(extra.connect(&url), Err(moto_rt::E_NOT_FOUND));

    // Preserve takeover after death even with an exhausted pool and retained
    // process/client handles. The original pending-listener restart test stays.
    // Unlike Child::kill, kill_pid does not wait for exit cleanup, so the
    // takeover may precede the dead owner's cleanup; both orders must pass.
    let mut peer = Peer::start(&url);
    client.connect(&url).unwrap();
    moto_sys::SysCpu::kill_pid(u64::from(peer.child.id())).unwrap();
    let replacement = listen(&url).unwrap();
    assert_eq!(peer.child.wait().unwrap().code(), Some(-1));
    client.disconnect();
    assert!(
        Command::new(std::env::current_exe().unwrap())
            .args(["ipc-service-busy", &url])
            .status()
            .unwrap()
            .success()
    );
    drop(replacement);
    drop(listen(&url).unwrap());
    println!("test_ipc_service_ownership PASS");

    test_closed_listeners_freed();
    test_closed_endpoints_keep_name();
    test_dup_races_close();
    test_listener_pool_closes();
    test_listener_pool_growth();
    test_refused_refill_retries();
}

fn test_listener_pool_growth() {
    let url = format!("systest-ipc-pool-growth-{}", std::process::id());
    let object = format!("shared:url={url};address=4096;page_type=small;page_num=1");
    let mut peer = Peer::spawn(&[POOL_GROWTH, &url]);
    let mut grown = [0_u8; 6];
    peer.stdout.read_exact(&mut grown).unwrap();
    assert_eq!(&grown, b"grown\n");
    moto_sys::SysCpu::kill_pid(u64::from(peer.child.id())).unwrap();
    // Let exit cleanup close the entire pool before taking its name again.
    assert_eq!(peer.child.wait().unwrap().code(), Some(-1));
    drop(peer);
    let replacement = SysObj::create(SysHandle::SELF, 0, &object).unwrap();
    SysObj::put(replacement).unwrap();
    println!("test_listener_pool_growth PASS");
}

fn test_listener_pool_closes() {
    use moto_sys::{SysMem, sys_mem::PAGE_SIZE_SMALL};

    let url = format!("systest-ipc-pool-closes-{}", std::process::id());
    let page = SysMem::map(SysHandle::SELF, 0, u64::MAX, u64::MAX, PAGE_SIZE_SMALL, 1).unwrap();
    let object = format!("shared:url={url};address={page};page_type=small;page_num=1");
    let listeners: Vec<_> = (0..4_096)
        .map(|_| SysObj::create(SysHandle::SELF, 0, &object).unwrap())
        .collect();
    for handle in listeners.iter().step_by(2) {
        SysObj::put(*handle).unwrap();
    }

    let mut client = ClientConnection::new(ChannelSize::Small).unwrap();
    for handle in listeners.into_iter().skip(1).step_by(2) {
        assert_eq!(connect_unmapped(&url), Err(moto_rt::E_INVALID_ARGUMENT));
        client.connect(&url).unwrap();
        assert_eq!(SysObj::is_connected(handle), Ok(true));
        // Closing an accepted endpoint must leave the other listeners alone.
        SysObj::put(handle).unwrap();
        client.disconnect();
    }
    assert_eq!(client.connect(&url), Err(moto_rt::E_NOT_FOUND));
    SysMem::unmap(SysHandle::SELF, 0, u64::MAX, page).unwrap();
    drop(listen(&url).unwrap());
    println!("test_listener_pool_closes PASS");
}

// Closed listeners must not accumulate in the kernel while another endpoint
// keeps the name: each leaked one would hold a few hundred heap bytes.
fn test_closed_listeners_freed() {
    let url = format!("systest-ipc-churn-{}", std::process::id());
    let _holder = listen(&url).unwrap();
    let churn = |count| {
        for _ in 0..count {
            drop(listen(&url).unwrap());
        }
    };
    let heap = || moto_sys::stats::MemoryStats::get().unwrap().heap_total;

    churn(1_000); // Warms up the kernel allocator's caches.
    let before = heap();
    churn(10_000);
    let growth = heap().saturating_sub(before);
    assert!(growth < (1 << 20), "kernel heap grew by {growth} bytes");
    println!("test_closed_listeners_freed PASS (kernel heap grew by {growth} bytes)");
}

// A live server keeps its name while it replaces a closed endpoint, even
// when that endpoint was its last one.
fn test_closed_endpoints_keep_name() {
    let url = format!("systest-ipc-retire-{}", std::process::id());
    let mut client = ClientConnection::new(ChannelSize::Small).unwrap();

    // The only listener connects and drops before the server wakes.
    let mut peer = Peer::start(&url);
    client.connect(&url).unwrap();
    client.disconnect();
    peer.command("reap");
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));
    peer.stop();

    // The server disconnects its only connection before refilling its pool.
    let mut peer = Peer::start(&url);
    client.connect(&url).unwrap();
    peer.rpc(&mut client);
    peer.command("kick");
    assert_eq!(listen(&url).err(), Some(moto_rt::E_INVALID_ARGUMENT));
    client.disconnect();
    peer.stop();
    println!("test_closed_endpoints_keep_name PASS");
}

// Duplicating a listener's only handle while another thread closes it: when
// the duplicate is created, the listener must stay open and connectable.
// Both orders are correct, so the test cannot flake. It runs both orders, but
// the old race window was a few instructions wide and is rarely hit.
fn test_dup_races_close() {
    use moto_sys::{SysMem, sys_mem::PAGE_SIZE_SMALL};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    const ROUNDS: usize = 2_000;
    let url = format!("systest-ipc-dup-{}", std::process::id());
    let map = |flags| {
        SysMem::map(
            SysHandle::SELF,
            flags,
            u64::MAX,
            u64::MAX,
            PAGE_SIZE_SMALL,
            1,
        )
        .unwrap()
    };
    let shared_url = |addr| {
        let url = moto_sys::url_encode(&url);
        format!("shared:url={url};address={addr};page_type=small;page_num=1")
    };
    let listener_page = map(0);
    let client_page = map(SysMem::F_READABLE | SysMem::F_WRITABLE);
    let (listener_url, client_url) = (shared_url(listener_page), shared_url(client_page));

    // Spinning starts both syscalls together; yielding keeps one vCPU moving.
    let wait_for = |counter: &AtomicUsize, value| {
        let mut spins = 0;
        while counter.load(Ordering::Acquire) != value {
            spins += 1;
            if spins < 10_000 {
                std::hint::spin_loop();
            } else {
                std::thread::yield_now();
            }
        }
    };
    let (listener, published, closed) =
        (AtomicU64::new(0), AtomicUsize::new(0), AtomicUsize::new(0));
    let mut duplicated = 0;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for round in 1..=ROUNDS {
                wait_for(&published, round);
                SysObj::put(SysHandle::from_u64(listener.load(Ordering::Relaxed))).unwrap();
                closed.store(round, Ordering::Release);
            }
        });
        for round in 1..=ROUNDS {
            let handle = SysObj::create(SysHandle::SELF, 0, &listener_url).unwrap();
            listener.store(handle.as_u64(), Ordering::Relaxed);
            published.store(round, Ordering::Release);
            // Sweeps the timing so that either call can come first or overlap.
            for _ in 0..round % 16 {
                std::hint::spin_loop();
            }
            let dup = SysObj::dup(handle);
            wait_for(&closed, round);
            let Ok(dup) = dup else {
                continue;
            };
            duplicated += 1;
            let client = SysObj::get(SysHandle::SELF, 0, &client_url).unwrap();
            SysObj::put(client).unwrap();
            SysObj::put(dup).unwrap();
        }
    });
    SysMem::unmap(SysHandle::SELF, 0, u64::MAX, listener_page).unwrap();
    SysMem::unmap(SysHandle::SELF, 0, u64::MAX, client_page).unwrap();
    println!("test_dup_races_close PASS ({duplicated} of {ROUNDS} duplicated)");
}

// When memory is low, the kernel refuses new listeners. The server must keep
// serving its open connection, and must add a listener again soon after the
// memory comes back, even if no client wakes it.
fn test_refused_refill_retries() {
    let url = format!("systest-ipc-refill-{}", std::process::id());
    let mut peer = Peer::start(&url);
    let mut client = ClientConnection::new(ChannelSize::Small).unwrap();
    let mut late = ClientConnection::new(ChannelSize::Small).unwrap();
    client.connect(&url).unwrap();
    peer.rpc(&mut client); // Takes the only listener; the next wait() refills.

    let mut hoarder = Peer::spawn(&[HOARD]);
    // Nothing here may allocate until the hoarder is gone: at the floor this
    // process cannot grow its heap either.
    let mut hoarded = [0_u8; 8];
    hoarder.stdout.read_exact(&mut hoarded).unwrap();
    assert_eq!(&hoarded, b"hoarded\n");
    peer.send("rpc"); // The refill is refused.
    client.req::<RequestHeader>().cmd = 1;
    client.do_rpc(None).unwrap();
    assert_eq!(client.resp::<ResponseHeader>().result, moto_rt::E_OK);
    let mut ok = [0_u8; 3];
    peer.stdout.read_exact(&mut ok).unwrap();
    assert_eq!(&ok, b"ok\n");
    peer.send("retry");
    // Keep the pressure until the server has actually returned from a wait
    // without a request, rather than merely queuing its next command.
    let mut retrying = [0_u8; 9];
    peer.stdout.read_exact(&mut retrying).unwrap();
    assert_eq!(&retrying, b"retrying\n");
    drop(hoarder.child.stdin.take());
    assert!(hoarder.child.wait().unwrap().success());
    drop(hoarder); // A dead process keeps its memory until its last handle closes.

    // Only the retry timer can add the listener this client needs.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while let Err(err) = late.connect(&url) {
        assert_eq!(err, moto_rt::E_NOT_FOUND);
        assert!(
            std::time::Instant::now() < deadline,
            "no listener after refusal"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    late.req::<RequestHeader>().cmd = 1;
    // A lost first wake would block this rpc for good; fail loudly instead.
    let answer_by = moto_rt::time::Instant::now() + std::time::Duration::from_secs(10);
    late.do_rpc(Some(answer_by))
        .expect("the server did not answer the first request on a fresh listener");
    assert_eq!(late.resp::<ResponseHeader>().result, moto_rt::E_OK);
    peer.expect("ok\n");
    drop((client, late));
    peer.stop();
    println!("test_refused_refill_retries PASS");
}
