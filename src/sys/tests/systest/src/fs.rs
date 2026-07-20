use std::{io::Seek, path::PathBuf};

fn temp_dir() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push("systest");
    path
}

fn create_dir_with_children(root: &std::path::Path, depth: u8) {
    assert!(!std::fs::exists(root).unwrap());
    std::fs::create_dir_all(root).unwrap();
    assert!(std::fs::exists(root).unwrap());
    let stats = std::fs::metadata(root).unwrap();
    assert!(stats.is_dir());

    if depth == 0 {
        return;
    }

    for i in 0..2 {
        let mut child = root.to_owned();
        child.push(format!("child 1.{i}"));
        create_dir_with_children(&child, depth - 1);

        std::fs::create_dir(PathBuf::from(root).join(format!("child 2.{i}"))).unwrap();
        std::fs::write(
            PathBuf::from(root).join(format!("file_{i}")),
            b"foo bar baz",
        )
        .unwrap();
    }
}

fn remove_dir_all_test() {
    let root = temp_dir();
    let _ = std::fs::remove_dir_all(&root);

    create_dir_with_children(&root, 2);

    assert!(std::fs::exists(&root).unwrap());
    let stats = std::fs::metadata(&root).unwrap();
    assert!(stats.is_dir());
    std::fs::remove_dir_all(&root).unwrap();

    assert!(!std::fs::exists(&root).unwrap());

    println!("    ---- FS: remove_dir_all_test PASS");
}

fn copy_test() {
    let root = temp_dir();
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let src = root.join("copy_src");
    let dst = root.join("copy_dst");

    // Generate some random source data larger than a single block to exercise
    // the copy loop.
    const LEN: usize = 1024 * 1024 * 3 + 333;
    let mut bytes = Vec::with_capacity(LEN);
    bytes.resize(LEN, 0u8);
    for byte in &mut bytes {
        *byte = std::random::random(..);
    }

    std::fs::write(&src, bytes.as_slice()).unwrap();

    // Copy to a fresh destination.
    let copied = std::fs::copy(&src, &dst).unwrap();
    assert_eq!(copied, LEN as u64);

    assert!(std::fs::exists(&dst).unwrap());
    let dst_meta = std::fs::metadata(&dst).unwrap();
    assert!(dst_meta.is_file());
    assert_eq!(dst_meta.len(), LEN as u64);

    let dst_bytes = std::fs::read(&dst).unwrap();
    assert_eq!(dst_bytes.len(), LEN);
    assert_eq!(
        moto_rt::fnv1a_hash_64(bytes.as_slice()),
        moto_rt::fnv1a_hash_64(dst_bytes.as_slice())
    );

    // The source must be left untouched.
    let src_meta = std::fs::metadata(&src).unwrap();
    assert!(src_meta.is_file());
    assert_eq!(src_meta.len(), LEN as u64);

    // Copying over an existing file must truncate/overwrite it: first write a
    // smaller file at the destination, then copy a larger one over it.
    /*
    let small = b"small contents";
    std::fs::write(&dst, small).unwrap();
    assert_eq!(std::fs::metadata(&dst).unwrap().len(), small.len() as u64);

    let copied = std::fs::copy(&src, &dst).unwrap();
    assert_eq!(copied, LEN as u64);
    assert_eq!(std::fs::metadata(&dst).unwrap().len(), LEN as u64);
    let dst_bytes = std::fs::read(&dst).unwrap();
    assert_eq!(
        moto_rt::fnv1a_hash_64(bytes.as_slice()),
        moto_rt::fnv1a_hash_64(dst_bytes.as_slice())
    );
    */

    // Copying a non-existent source must fail with NotFound.
    let missing = root.join("does_not_exist");
    assert_eq!(
        std::fs::copy(&missing, &dst).err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );

    // Copying an empty file must succeed and produce an empty file.
    let empty_src = root.join("empty_src");
    let empty_dst = root.join("empty_dst");
    std::fs::write(&empty_src, b"").unwrap();
    let copied = std::fs::copy(&empty_src, &empty_dst).unwrap();
    assert_eq!(copied, 0);
    assert_eq!(std::fs::metadata(&empty_dst).unwrap().len(), 0);

    std::fs::remove_dir_all(&root).unwrap();
    assert!(!std::fs::exists(&root).unwrap());

    println!("    ---- FS: copy_test PASS");
}

pub fn smoke_test() {
    if std::fs::metadata("/foo").is_ok() {
        std::fs::remove_file("/foo").unwrap();
    }
    if std::fs::metadata("/bar").is_ok() {
        std::fs::remove_file("/bar").unwrap();
    }

    assert_eq!(
        std::fs::metadata("/foo").err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        std::fs::metadata("/bar").err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );

    std::fs::write("/foo", "bar").expect("async write failed");
    let bytes = std::fs::read("/foo").expect("async read failed");
    assert_eq!(bytes.as_slice(), "bar".as_bytes());

    const LEN: usize = 1024 * 1024 * 19 + 1001;

    let mut bytes = Vec::with_capacity(LEN);
    bytes.resize(LEN, 0);
    for byte in &mut bytes {
        *byte = std::random::random(..);
    }

    // add stats
    let sys_io_provider = moto_stats::Collector::providers()
        .into_iter()
        .find(|p| p.id == 2)
        .unwrap();

    let mut stats_before = [0_u64; 12];
    for idx in 0..12 {
        stats_before[idx] =
            moto_stats::Collector::read(&sys_io_provider, 1002 + idx as u32, 0).unwrap();
    }

    // WRITE.
    let ts0 = std::time::Instant::now();
    std::fs::write("/bar", bytes.as_slice()).unwrap();
    let dur_write = ts0.elapsed();
    let cpu_usage_write = crate::mpmc::get_cpu_usage();

    // Sleep to let async writes to flush and not pollute read time/stats.
    std::thread::sleep(std::time::Duration::from_millis(100));

    // READ.
    run_pstat("before");
    let ts1 = std::time::Instant::now();
    let bytes_back = std::fs::read("/bar").unwrap();
    let dur_read = ts1.elapsed();
    let cpu_usage_read = crate::mpmc::get_cpu_usage();
    run_pstat("after");

    let mut stats_after = [0_u64; 12];
    for idx in 0..12 {
        stats_after[idx] =
            moto_stats::Collector::read(&sys_io_provider, 1002 + idx as u32, 0).unwrap();
    }

    for idx in 0..12 {
        println!(
            "sys-io::{} metric values before/after write+read: {} - {}",
            idx + 1002,
            stats_before[idx],
            stats_after[idx]
        );
    }

    assert_eq!(
        moto_rt::fnv1a_hash_64(bytes.as_slice()),
        moto_rt::fnv1a_hash_64(bytes_back.as_slice())
    );

    let write_mbps = (bytes.len() as f64) / dur_write.as_secs_f64() / (1024.0 * 1024.0);
    let read_mbps = (bytes.len() as f64) / dur_read.as_secs_f64() / (1024.0 * 1024.0);
    println!(
        "async FS smoke test: write {:.3} mbps; read: {:.3} mbps",
        write_mbps, read_mbps
    );

    print!("\tcpu usage writing: ");
    for n in &cpu_usage_write {
        print!("{: >5.1}% ", (*n) * 100.0);
    }
    println!();
    print!("\tcpu usage reading: ");
    for n in &cpu_usage_read {
        print!("{: >5.1}% ", (*n) * 100.0);
    }
    println!();
    let metadata = std::fs::metadata("/bar").unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), bytes.len() as u64);

    std::fs::remove_file("/foo").unwrap();
    std::fs::remove_file("/bar").unwrap();

    assert_eq!(
        std::fs::metadata("/foo").err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        std::fs::metadata("/bar").err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );

    println!("    ---- FS: smoke_test PASS");
}

/// Repeatedly reads a file that fits entirely in sys-io's block cache
/// (512 blocks = 2MB): the same per-message pipeline as `smoke_test`'s
/// streaming read, but with zero device reads and no readahead. Comparing
/// its MB/s and sys-io CPU/block against the streaming benchmark splits
/// per-message CPU costs from per-device-miss CPU costs.
pub fn hot_cache_read_test() {
    println!("    ---- FS: hot_cache_read_test starting...");

    const LEN: usize = 1024 * 1024 + 512 * 1024; // 1.5MB: fits in the block cache.
    const PASSES: usize = 13; // ~19.5MB total, comparable to smoke_test's read.

    let mut bytes = Vec::with_capacity(LEN);
    bytes.resize(LEN, 0);
    for byte in &mut bytes {
        *byte = std::random::random(..);
    }
    std::fs::write("/hot", bytes.as_slice()).unwrap();

    // Warm the cache; also verifies the content.
    let bytes_back = std::fs::read("/hot").unwrap();
    assert_eq!(
        moto_rt::fnv1a_hash_64(bytes.as_slice()),
        moto_rt::fnv1a_hash_64(bytes_back.as_slice())
    );

    let sys_io_provider = moto_stats::Collector::providers()
        .into_iter()
        .find(|p| p.id == 2)
        .unwrap();

    let mut stats_before = [0_u64; 12];
    for idx in 0..12 {
        stats_before[idx] =
            moto_stats::Collector::read(&sys_io_provider, 1002 + idx as u32, 0).unwrap();
    }

    run_pstat("hot before");
    let ts = std::time::Instant::now();
    let mut total_read = 0_usize;
    for _ in 0..PASSES {
        total_read += std::fs::read("/hot").unwrap().len();
    }
    let dur = ts.elapsed();
    let cpu_usage = crate::mpmc::get_cpu_usage();
    run_pstat("hot after");

    let mut stats_after = [0_u64; 12];
    for idx in 0..12 {
        stats_after[idx] =
            moto_stats::Collector::read(&sys_io_provider, 1002 + idx as u32, 0).unwrap();
    }

    for idx in 0..12 {
        println!(
            "sys-io::{} metric values before/after hot read: {} - {}",
            idx + 1002,
            stats_before[idx],
            stats_after[idx]
        );
    }

    let read_mbps = (total_read as f64) / dur.as_secs_f64() / (1024.0 * 1024.0);
    println!(
        "hot cache read: {:.3} mbps ({} passes x {} bytes in {:?})",
        read_mbps, PASSES, LEN, dur
    );
    print!("\tcpu usage hot reading: ");
    for n in &cpu_usage {
        print!("{: >5.1}% ", (*n) * 100.0);
    }
    println!();

    std::fs::remove_file("/hot").unwrap();
    println!("    ---- FS: hot_cache_read_test PASS");
}

fn run_pstat(timing: &str) {
    let this_pid = moto_sys::current_pid();

    let kernel = moto_stats::Collector::kernel();
    let kernel_cpu = moto_stats::Collector::read(&kernel, 1, 1).unwrap();
    let sys_io_cpu = moto_stats::Collector::read(&kernel, 1, 2).unwrap();
    let systest_cpu = moto_stats::Collector::read(&kernel, 1, this_pid).unwrap();

    println!(
        "CPU usage {timing}:\n    kernel: {kernel_cpu} sys-io: {sys_io_cpu} systest: {systest_cpu}"
    );

    // SysCpuWaits = metric 8, SysCpuWakes = metric 9: how often each side
    // blocks/wakes the other (per-response wake/sleep thrash shows up here).
    let sys_io_waits = moto_stats::Collector::read(&kernel, 8, 2).unwrap();
    let sys_io_wakes = moto_stats::Collector::read(&kernel, 9, 2).unwrap();
    let systest_waits = moto_stats::Collector::read(&kernel, 8, this_pid).unwrap();
    let systest_wakes = moto_stats::Collector::read(&kernel, 9, this_pid).unwrap();
    println!(
        "waits/wakes {timing}:\n    sys-io: {sys_io_waits}/{sys_io_wakes} systest: {systest_waits}/{systest_wakes}"
    );

    // Large (>4KB) heap allocations bypass frusa and hit SysMem alloc/free
    // directly; each freed 4KB page triggers a broadcast TLB shootdown
    // (kernel tlb.rs::invalidate: IPI all CPUs + spin for acks) charged to
    // the caller. SysMem* = metrics 4/5/6 (systest scope); shootdown/wakeup
    // IPIs = metrics 19/18 (kernel scope, remote CPUs only); IrqPfFired = 20.
    let mem_calls = moto_stats::Collector::read(&kernel, 4, this_pid).unwrap();
    let mem_maps = moto_stats::Collector::read(&kernel, 5, this_pid).unwrap();
    let mem_unmaps = moto_stats::Collector::read(&kernel, 6, this_pid).unwrap();
    let tlb_shootdowns = moto_stats::Collector::read(&kernel, 19, 1).unwrap();
    let wakeup_irqs = moto_stats::Collector::read(&kernel, 18, 1).unwrap();
    let pf_irqs = moto_stats::Collector::read(&kernel, 20, 1).unwrap();
    println!(
        "systest mem calls/maps/unmaps {timing}: {mem_calls}/{mem_maps}/{mem_unmaps}\n\
         kernel irqs tlb_shootdown/wakeup/pf {timing}: {tlb_shootdowns}/{wakeup_irqs}/{pf_irqs}"
    );
    println!(
        "Time since UNIX_EPOCH {timing}: {:?}",
        std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH)
    );
}

fn resize_test() {
    println!("    ---- FS: resize_test starting...");
    const LEN: usize = 1024 * 1024 * 7 + 131;

    let mut bytes = Vec::with_capacity(LEN);
    bytes.resize(LEN, 0);
    for byte in &mut bytes {
        *byte = std::random::random(..);
    }

    std::fs::write("/baz", bytes.as_slice()).unwrap();
    let file = std::fs::File::open("/baz").unwrap();
    assert_eq!(file.metadata().unwrap().len(), LEN as u64);

    println!("    ---- FS: resize_test resizing...");
    file.set_len(8192 + 11).unwrap();

    drop(file);
    std::fs::remove_file("/baz").unwrap();
    println!("    ---- FS: resize_test PASS");
}

/// Regression test for a sys-io reentrancy panic: a `RefCell` double-borrow in
/// motor-fs's txn_log committer (`spawn_txn_committer_task`).
///
/// sys-io is single-threaded but cooperatively concurrent. The txn committer,
/// the timeout flushers, and `log_txn` all share one `Rc<RefCell<TxnBatch>>`.
/// A `CMD_FLUSH` that found the txn batch already empty used to make the
/// committer hold `borrow_mut()` across the block-device flush await
/// (`AsyncStub::flush`, which suspends on a background-task oneshot). A timeout
/// flusher waking in that window then called `borrow_mut()` again and panicked,
/// taking sys-io — and thus all of the VM's I/O — down.
///
/// The race is internal to sys-io, so a single client stream can drive it:
/// every write makes the batch non-empty (sys-io spawns a ~50ms timeout
/// flusher); the first flush commits the batch, the second finds it empty and
/// exercises the vulnerable branch. Hammering write+flush+flush keeps many
/// timeout flushers firing while empty flushes are in flight, so the coincidence
/// is hit within a fraction of a second. Extra threads just keep the sys-io
/// pipeline full and interleave flushes across batches.
///
/// Without the fix sys-io panics (the serial console shows "RefCell already
/// borrowed" pointing at txn_log.rs, and this test then hangs on an I/O that
/// never completes). With the fix it runs to completion.
pub fn concurrent_flush_stress_test() {
    use std::io::{SeekFrom, Write};
    use std::os::fd::AsRawFd;

    println!("    ---- FS: concurrent_flush_stress_test starting...");

    const THREADS: usize = 4;
    const ITERS: usize = 4000;

    let mut handles = Vec::with_capacity(THREADS);
    for t in 0..THREADS {
        handles.push(std::thread::spawn(move || {
            let path = format!("/flush_stress_{t}");
            let _ = std::fs::remove_file(&path);
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            // Flush directly via moto_rt so we always emit CMD_FLUSH regardless
            // of how std maps `Write::flush` for files.
            let fd = file.as_raw_fd();

            for i in 0..ITERS {
                // Keep the file a single block; each write dirties it, so sys-io
                // opens a txn batch and (when it was empty) spawns a timeout
                // flusher that fires ~MAX_FLUSH_DELAY_MS later.
                file.seek(SeekFrom::Start(0)).unwrap();
                file.write_all(&[i as u8, (i >> 8) as u8]).unwrap();

                // First flush commits the (non-empty) batch; the second finds
                // the batch empty -> the branch that used to double-borrow.
                moto_rt::fs::flush(fd).unwrap();
                moto_rt::fs::flush(fd).unwrap();
            }

            drop(file);
            let _ = std::fs::remove_file(&path);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    println!("    ---- FS: concurrent_flush_stress_test PASS");
}

fn permissions_vdso_test() {
    use std::os::fd::AsRawFd;

    const RWX: u64 = moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE | moto_rt::fs::PERM_EXEC;
    const RX: u64 = moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC;

    let path = "/permissions_vdso_test";
    let _ = std::fs::remove_file(path);
    std::fs::write(path, b"permissions").unwrap();

    assert_eq!(moto_rt::fs::stat(path).unwrap().perm, RWX);
    moto_rt::fs::set_perm(path, RX).unwrap();
    assert_eq!(moto_rt::fs::stat(path).unwrap().perm, RX);

    let file = std::fs::File::open(path).unwrap();
    assert_eq!(
        moto_rt::fs::get_file_attr(file.as_raw_fd()).unwrap().perm,
        RX
    );
    moto_rt::fs::set_file_perm(file.as_raw_fd(), moto_rt::fs::PERM_READ).unwrap();
    assert_eq!(
        moto_rt::fs::get_file_attr(file.as_raw_fd()).unwrap().perm,
        moto_rt::fs::PERM_READ
    );

    assert_eq!(
        moto_rt::fs::set_perm(path, moto_rt::fs::PERM_WRITE),
        Err(moto_rt::Error::InvalidArgument)
    );
    assert_eq!(
        moto_rt::fs::set_file_perm(-1, moto_rt::fs::PERM_READ),
        Err(moto_rt::Error::BadHandle)
    );

    drop(file);
    std::fs::remove_file(path).unwrap();
    println!("    ---- FS: permissions_vdso_test PASS");
}

pub fn run_tests() {
    println!("running FS tests ...");
    permissions_vdso_test();
    concurrent_flush_stress_test();
    smoke_test();
    hot_cache_read_test();
    copy_test();
    remove_dir_all_test();
    resize_test();

    println!("FS tests PASS");
}
