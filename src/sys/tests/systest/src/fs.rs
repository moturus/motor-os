use std::{io::Seek, path::PathBuf};

/// sys-io FS metric ids read by the benchmarks below (see
/// `sys-io/src/runtime/fs/stats.rs`).
const FS_METRICS: std::ops::Range<u32> = 1002..1014;

/// Read every metric in [`FS_METRICS`] from one snapshot.
///
/// Two reasons not to call `Collector::read()` per metric: it issues a full
/// query per call (12 RPCs, each round-tripping into sys-io's FS runtime), and
/// each call samples a different instant. It is also flaky under load — sys-io
/// assembles this list by asking its FS/NET runtimes for a snapshot, and that
/// request's failure mode is an empty or short metric set returned as success,
/// so an individual read can report NotFound for a metric that always exists.
/// Retry until a complete snapshot arrives; only a persistent absence fails.
fn read_sys_io_fs_metrics(provider: &moto_stats::ProviderInfo) -> [u64; 12] {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let snapshot = moto_stats::Collector::query(provider).unwrap_or_default();
        let mut vals = [0_u64; 12];
        let missing = FS_METRICS.clone().position(|metric| {
            match snapshot.iter().find(|e| e.metric == metric) {
                Some(entry) => {
                    vals[(metric - FS_METRICS.start) as usize] = entry.value;
                    false
                }
                None => true,
            }
        });
        let Some(missing) = missing else {
            return vals;
        };
        assert!(
            std::time::Instant::now() < deadline,
            "sys-io stats: metric {} absent from {} entries",
            FS_METRICS.start + missing as u32,
            snapshot.len()
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

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

fn vectored_shared_position_test() {
    const THREADS: u64 = 4;
    const RECORDS: u64 = 128;
    let path = crate::temp_path("systest-vectored-position");
    let path_str = path.to_str().unwrap();

    let _ = std::fs::remove_file(&path);
    let fd = moto_rt::fs::open(
        path_str,
        moto_rt::fs::O_CREATE
            | moto_rt::fs::O_TRUNCATE
            | moto_rt::fs::O_READ
            | moto_rt::fs::O_WRITE,
    )
    .unwrap();
    moto_rt::net::set_nonblocking(fd, true).unwrap();

    assert_eq!(
        moto_rt::fs::write_vectored(fd, &[b"ab", b"", b"cd"]).unwrap(),
        4
    );
    assert_eq!(moto_rt::fs::seek(fd, 0, moto_rt::fs::SEEK_SET).unwrap(), 0);
    let mut first = [0_u8; 1];
    let mut empty = [];
    let mut rest = [0_u8; 3];
    let mut bufs: [&mut [u8]; 3] = [&mut first, &mut empty, &mut rest];
    assert_eq!(moto_rt::fs::read_vectored(fd, &mut bufs).unwrap(), 4);
    assert_eq!([first.as_slice(), rest.as_slice()].concat(), b"abcd");

    moto_rt::fs::truncate(fd, 0).unwrap();
    assert_eq!(moto_rt::fs::seek(fd, 0, moto_rt::fs::SEEK_SET).unwrap(), 0);

    let mut threads = Vec::new();
    for thread_id in 0..THREADS {
        let duplicate = moto_rt::fs::duplicate(fd).unwrap();
        threads.push(std::thread::spawn(move || {
            for record_id in 0..RECORDS {
                let value = (thread_id << 32) | record_id;
                let first = value.to_le_bytes();
                let second = (!value).to_le_bytes();
                assert_eq!(
                    moto_rt::fs::write_vectored(duplicate, &[&first, &second]).unwrap(),
                    16
                );
            }
            moto_rt::fs::close(duplicate).unwrap();
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }

    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), (THREADS * RECORDS * 16) as usize);
    let mut records = std::collections::HashSet::new();
    for record in bytes.chunks(16) {
        let value = u64::from_le_bytes(record[..8].try_into().unwrap());
        let complement = u64::from_le_bytes(record[8..].try_into().unwrap());
        assert_eq!(complement, !value, "vectored write was interleaved");
        assert!(records.insert(value), "shared position overwrote a record");
    }
    assert_eq!(records.len(), (THREADS * RECORDS) as usize);

    moto_rt::net::set_nonblocking(fd, false).unwrap();
    moto_rt::fs::close(fd).unwrap();
    std::fs::remove_file(&path).unwrap();
    println!("    ---- FS: vectored_shared_position_test PASS");
}

fn readdir_error_exhausts_stream_test() {
    let root = temp_dir().join("readdir-error-exhausts-stream");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let first_path = root.join("first");
    let second_path = root.join("second");
    std::fs::write(&first_path, b"").unwrap();
    std::fs::write(&second_path, b"").unwrap();

    let fd = moto_rt::fs::opendir(root.to_str().unwrap()).unwrap();
    let returned = moto_rt::fs::readdir(fd).unwrap().unwrap();
    let returned_name =
        std::str::from_utf8(&returned.fname[..returned.fname_size as usize]).unwrap();
    let prefetched = match returned_name {
        "first" => &second_path,
        "second" => &first_path,
        name => panic!("unexpected directory entry {name:?}"),
    };

    // readdir() prefetched this entry as its cursor. Removing it makes the
    // next cursor lookup fail; the error must be returned once, then EOF.
    std::fs::remove_file(prefetched).unwrap();
    assert!(moto_rt::fs::readdir(fd).is_err());
    assert!(moto_rt::fs::readdir(fd).unwrap().is_none());
    moto_rt::fs::closedir(fd).unwrap();

    std::fs::remove_dir_all(&root).unwrap();
    println!("    ---- FS: readdir_error_exhausts_stream_test PASS");
}

fn move_noreplace_test() {
    let root = temp_dir();
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let source = root.join("move_noreplace_source");
    let target = root.join("move_noreplace_target");
    std::fs::write(&source, b"source").unwrap();
    std::fs::write(&target, b"target").unwrap();

    assert_eq!(
        moto_rt::fs::move_noreplace(source.to_str().unwrap(), target.to_str().unwrap()),
        Err(moto_rt::Error::AlreadyInUse)
    );
    assert_eq!(std::fs::read(&source).unwrap(), b"source");
    assert_eq!(std::fs::read(&target).unwrap(), b"target");

    std::fs::remove_file(&target).unwrap();
    moto_rt::fs::move_noreplace(source.to_str().unwrap(), target.to_str().unwrap()).unwrap();
    assert!(!std::fs::exists(&source).unwrap());
    assert_eq!(std::fs::read(&target).unwrap(), b"source");

    let source_dir = root.join("move_noreplace_source_dir");
    let target_dir = root.join("move_noreplace_target_dir");
    std::fs::create_dir(&source_dir).unwrap();
    std::fs::create_dir(&target_dir).unwrap();
    assert_eq!(
        moto_rt::fs::move_noreplace(source_dir.to_str().unwrap(), target_dir.to_str().unwrap()),
        Err(moto_rt::Error::AlreadyInUse)
    );
    std::fs::remove_dir(&target_dir).unwrap();
    moto_rt::fs::move_noreplace(source_dir.to_str().unwrap(), target_dir.to_str().unwrap())
        .unwrap();
    assert!(!std::fs::exists(&source_dir).unwrap());
    assert!(std::fs::metadata(&target_dir).unwrap().is_dir());

    competing_move_noreplace_test(&root);
    std::fs::remove_dir_all(&root).unwrap();
    println!("    ---- FS: move_noreplace_test PASS");
}

fn competing_move_noreplace_test(root: &std::path::Path) {
    let target = root.join("published");
    let start = root.join("publish-start");
    let mut children = Vec::new();
    for name in ["first", "second"] {
        let source = root.join(format!("{name}-source"));
        let ready = root.join(format!("{name}-ready"));
        let result = root.join(format!("{name}-result"));
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("value"), name).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "move-noreplace-child",
                source.to_str().unwrap(),
                target.to_str().unwrap(),
                ready.to_str().unwrap(),
                start.to_str().unwrap(),
                result.to_str().unwrap(),
            ])
            .spawn()
            .unwrap();
        children.push((name, child, ready, result));
    }
    for (_, _, ready, _) in &children {
        while !ready.exists() {
            std::thread::yield_now();
        }
    }
    std::fs::write(&start, b"go").unwrap();

    let mut winners = Vec::new();
    for (name, mut child, _, result) in children {
        assert!(child.wait().unwrap().success());
        if std::fs::read_to_string(result).unwrap() == "won" {
            winners.push(name);
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(
        std::fs::read_to_string(target.join("value")).unwrap(),
        winners[0]
    );
}

pub fn move_noreplace_child(args: &[String]) {
    assert_eq!(args.len(), 7);
    let source = &args[2];
    let target = &args[3];
    let ready = &args[4];
    let start = &args[5];
    let result = &args[6];
    std::fs::write(ready, b"ready").unwrap();
    while !std::path::Path::new(start).exists() {
        std::thread::yield_now();
    }
    let outcome = match moto_rt::fs::move_noreplace(source, target) {
        Ok(()) => "won",
        Err(moto_rt::Error::AlreadyInUse) => "lost",
        Err(error) => panic!("competing move_noreplace failed: {error}"),
    };
    std::fs::write(result, outcome).unwrap();
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
    let foo = crate::temp_path("systest-fs-foo");
    let bar = crate::temp_path("systest-fs-bar");
    if std::fs::metadata(&foo).is_ok() {
        std::fs::remove_file(&foo).unwrap();
    }
    if std::fs::metadata(&bar).is_ok() {
        std::fs::remove_file(&bar).unwrap();
    }

    assert_eq!(
        std::fs::metadata(&foo).err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        std::fs::metadata(&bar).err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );

    std::fs::write(&foo, "bar").expect("async write failed");
    let bytes = std::fs::read(&foo).expect("async read failed");
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

    let stats_before = read_sys_io_fs_metrics(&sys_io_provider);

    // WRITE.
    let ts0 = std::time::Instant::now();
    std::fs::write(&bar, bytes.as_slice()).unwrap();
    let dur_write = ts0.elapsed();
    let cpu_usage_write = crate::mpmc::get_cpu_usage();

    // Sleep to let async writes to flush and not pollute read time/stats.
    std::thread::sleep(std::time::Duration::from_millis(100));

    // READ.
    run_pstat("before");
    let ts1 = std::time::Instant::now();
    let bytes_back = std::fs::read(&bar).unwrap();
    let dur_read = ts1.elapsed();
    let cpu_usage_read = crate::mpmc::get_cpu_usage();
    run_pstat("after");

    let stats_after = read_sys_io_fs_metrics(&sys_io_provider);

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
    let metadata = std::fs::metadata(&bar).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), bytes.len() as u64);

    std::fs::remove_file(&foo).unwrap();
    std::fs::remove_file(&bar).unwrap();

    assert_eq!(
        std::fs::metadata(&foo).err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        std::fs::metadata(&bar).err().unwrap().kind(),
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
    let path = crate::temp_path("systest-fs-hot");
    std::fs::write(&path, bytes.as_slice()).unwrap();

    // Warm the cache; also verifies the content.
    let bytes_back = std::fs::read(&path).unwrap();
    assert_eq!(
        moto_rt::fnv1a_hash_64(bytes.as_slice()),
        moto_rt::fnv1a_hash_64(bytes_back.as_slice())
    );

    let sys_io_provider = moto_stats::Collector::providers()
        .into_iter()
        .find(|p| p.id == 2)
        .unwrap();

    let stats_before = read_sys_io_fs_metrics(&sys_io_provider);

    run_pstat("hot before");
    let ts = std::time::Instant::now();
    let mut total_read = 0_usize;
    for _ in 0..PASSES {
        total_read += std::fs::read(&path).unwrap().len();
    }
    let dur = ts.elapsed();
    let cpu_usage = crate::mpmc::get_cpu_usage();
    run_pstat("hot after");

    let stats_after = read_sys_io_fs_metrics(&sys_io_provider);

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

    // The timed loop above measures throughput and so only sums lengths; a
    // cache handing back a right-sized wrong page would pass it. Re-verify
    // the content once the measurement is done.
    let bytes_back = std::fs::read(&path).unwrap();
    assert_eq!(
        moto_rt::fnv1a_hash_64(bytes.as_slice()),
        moto_rt::fnv1a_hash_64(bytes_back.as_slice()),
        "hot cache returned wrong content after {PASSES} passes"
    );

    std::fs::remove_file(&path).unwrap();
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

    let path = crate::temp_path("systest-fs-resize");
    std::fs::write(&path, bytes.as_slice()).unwrap();
    let file = std::fs::File::open(&path).unwrap();
    assert_eq!(file.metadata().unwrap().len(), LEN as u64);

    println!("    ---- FS: resize_test resizing...");
    file.set_len(8192 + 11).unwrap();

    drop(file);
    std::fs::remove_file(&path).unwrap();
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
    /// Wall-clock cap on the stress loop.
    ///
    /// The iteration count alone is not a bound on duration: this loop is
    /// throughput-limited by sys-io's FS runtime, so on a host that
    /// oversubscribes vCPUs (the stress-soak configuration) it runs roughly 25x
    /// slower and 4000 iterations take ~5.5 min -- past the soak's 240s
    /// per-suite timeout, which then killed systest mid-test and reported it as
    /// a hang. Stop early instead; the race this guards (the flush-batch
    /// double-borrow) is hit thousands of times either way.
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(45);

    // Per-thread progress, so a stall here is distinguishable from mere
    // slowness (this test is the heaviest fs load systest generates).
    let progress: std::sync::Arc<Vec<std::sync::atomic::AtomicUsize>> =
        std::sync::Arc::new((0..THREADS).map(|_| Default::default()).collect());
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog = {
        let (progress, done) = (progress.clone(), done.clone());
        std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while !done.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(5));
                if done.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let counts: Vec<usize> = progress
                    .iter()
                    .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                    .collect();
                println!(
                    "    ---- FS: concurrent_flush_stress_test +{}s: {counts:?} of {ITERS}",
                    start.elapsed().as_secs()
                );
            }
        })
    };

    let started = std::time::Instant::now();
    let mut handles = Vec::with_capacity(THREADS);
    for t in 0..THREADS {
        let progress = progress.clone();
        handles.push(std::thread::spawn(move || {
            let path = crate::temp_path(&format!("systest-flush-stress-{t}"));
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
                progress[t].store(i + 1, std::sync::atomic::Ordering::Relaxed);

                if (i & 63) == 63 && started.elapsed() > BUDGET {
                    break;
                }
            }

            drop(file);
            let _ = std::fs::remove_file(&path);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = watchdog.join();

    let iters: Vec<usize> = progress
        .iter()
        .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
        .collect();
    println!(
        "    ---- FS: concurrent_flush_stress_test PASS ({}ms, {iters:?} of {ITERS} per thread)",
        started.elapsed().as_millis()
    );
}

fn permissions_vdso_test() {
    use std::os::fd::AsRawFd;

    const RWX: u64 = moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE | moto_rt::fs::PERM_EXEC;
    const RX: u64 = moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC;

    let path = crate::temp_path("systest-permissions-vdso");
    let path_str = path.to_str().unwrap();
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, b"permissions").unwrap();

    assert_eq!(moto_rt::fs::stat(path_str).unwrap().perm, RWX);
    moto_rt::fs::set_perm(path_str, RX).unwrap();
    assert_eq!(moto_rt::fs::stat(path_str).unwrap().perm, RX);

    let file = std::fs::File::open(&path).unwrap();
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
        moto_rt::fs::set_perm(path_str, moto_rt::fs::PERM_WRITE),
        Err(moto_rt::Error::InvalidArgument)
    );
    assert_eq!(
        moto_rt::fs::set_file_perm(-1, moto_rt::fs::PERM_READ),
        Err(moto_rt::Error::BadHandle)
    );

    drop(file);
    std::fs::remove_file(&path).unwrap();
    println!("    ---- FS: permissions_vdso_test PASS");
}

// ---------------------------------------------------------------------------
// Concurrent large-file reads.
//
// Every other FS test here reads a file from a single thread of a single
// process, at idle, and the largest of them is 19 MB. That leaves the read
// path's concurrent behaviour untested: the shared block cache, the B+tree
// lookup cursors, readahead, and multi-page read responses are all global to
// sys-io and only interesting when several readers stream at once. It also
// leaves wrong-data reads undetectable where they are checked at all --
// `hot_cache_read_test` asserts only the length it read back.
//
// The file below is written with a self-describing pattern: the u64 at offset
// `o` is `o`. A reader therefore validates position as well as content, and a
// block served from the wrong place in the file names its true origin in the
// assertion instead of just reporting a mismatch.
// ---------------------------------------------------------------------------

/// Three times sys-io's 16 MB block cache, so most reads miss it and reach
/// the device. A multiple of [`PATTERN_CHUNK`].
const PATTERN_FILE_LEN: u64 = 48 * 1024 * 1024;
const PATTERN_CHUNK: usize = 64 * 1024;
fn write_pattern_file(path: &str, len: u64) {
    use std::io::Write;

    let mut file = std::fs::File::create(path).unwrap();
    let mut chunk = vec![0_u8; PATTERN_CHUNK];
    let mut offset = 0_u64;
    while offset < len {
        let this = ((len - offset) as usize).min(PATTERN_CHUNK);
        for idx in (0..this).step_by(8) {
            chunk[idx..idx + 8].copy_from_slice(&(offset + idx as u64).to_le_bytes());
        }
        file.write_all(&chunk[..this]).unwrap();
        offset += this as u64;
    }
    file.flush().unwrap();
}

fn check_pattern(buf: &[u8], file_offset: u64, label: &str) {
    for idx in (0..buf.len()).step_by(8) {
        let got = u64::from_le_bytes(buf[idx..idx + 8].try_into().unwrap());
        let want = file_offset + idx as u64;
        assert_eq!(
            got, want,
            "{label}: wrong data at offset {want}: this block belongs at offset {got}"
        );
    }
}

/// Stream the whole file and verify every byte, then re-read a few
/// non-block-aligned ranges. Used by both the in-process threads and the
/// child processes below.
pub fn verify_pattern_file(path: &str, len: u64, label: &str) {
    use std::io::Read;

    let mut file = std::fs::File::open(path).unwrap();
    let mut buf = vec![0_u8; PATTERN_CHUNK];
    for chunk_idx in 0..(len / PATTERN_CHUNK as u64) {
        file.read_exact(&mut buf).unwrap();
        check_pattern(&buf, chunk_idx * PATTERN_CHUNK as u64, label);
    }

    // Odd offsets and lengths: nothing else in this file reads at a
    // non-block-aligned position.
    let mut small = [0_u8; 8 * 16];
    for offset in [8_u64, 4088, 4096 + 24, 1024 * 1024 + 512, len - 1024] {
        file.seek(std::io::SeekFrom::Start(offset)).unwrap();
        if let Err(err) = file.read_exact(&mut small) {
            panic!(
                "{label}: reading {} bytes at offset {offset} failed: {err}",
                small.len()
            );
        }
        check_pattern(&small, offset, label);
    }
}

/// Several processes and threads stream the same large file at once and
/// verify its contents.
fn concurrent_large_file_read_test() {
    let path = crate::temp_path("systest-concurrent-read");
    let path_str = path.to_str().unwrap();
    if std::fs::metadata(&path).is_ok() {
        std::fs::remove_file(&path).unwrap();
    }
    write_pattern_file(path_str, PATTERN_FILE_LEN);

    let mut children = Vec::new();
    for idx in 0..2 {
        children.push(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "concurrent-read-child",
                    path_str,
                    &PATTERN_FILE_LEN.to_string(),
                    &format!("child-{idx}"),
                ])
                .spawn()
                .unwrap(),
        );
    }

    let threads: Vec<_> = (0..std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(4)
        .max(2))
        .map(|idx| {
            let path = path.clone();
            std::thread::spawn(move || {
                verify_pattern_file(
                    path.to_str().unwrap(),
                    PATTERN_FILE_LEN,
                    &format!("thread-{idx}"),
                )
            })
        })
        .collect();

    for thread in threads {
        thread.join().unwrap();
    }
    for mut child in children {
        assert!(
            child.wait().unwrap().success(),
            "a concurrent reader process failed"
        );
    }

    std::fs::remove_file(&path).unwrap();
    println!("    ---- FS: concurrent_large_file_read_test PASS");
}

pub fn run_tests() {
    println!("running FS tests ...");
    permissions_vdso_test();
    concurrent_flush_stress_test();
    concurrent_large_file_read_test();
    vectored_shared_position_test();
    move_noreplace_test();
    smoke_test();
    hot_cache_read_test();
    copy_test();
    readdir_error_exhausts_stream_test();
    remove_dir_all_test();
    resize_test();

    println!("FS tests PASS");
}
