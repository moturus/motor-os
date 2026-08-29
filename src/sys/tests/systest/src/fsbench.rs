//! FS latency/throughput profiler (perf run 2026-08-28). Not a test:
//! `systest fs-bench` prints per-phase latency, throughput, and the
//! sys-io / kernel counters that explain them.
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::Instant;

const KB: usize = 1024;
const MB: usize = 1024 * 1024;

// pid -> per-cpu (kernel, user) tsc.
struct CpuSnap(HashMap<u64, Vec<(u64, u64)>>);

fn cpu_snap() -> CpuSnap {
    let s = moto_sys::stats::CpuStatsV1::new();
    let n = s.num_cpus() as usize;
    let mut map = HashMap::new();
    for i in 0..s.num_entries() as usize {
        let e = s.entry(i);
        let v: Vec<(u64, u64)> = (0..n)
            .map(|c| (e.percpu_entries[c].kernel, e.percpu_entries[c].uspace))
            .collect();
        map.insert(e.pid, v);
    }
    CpuSnap(map)
}

const KM: [(u32, &str); 10] = [
    (8, "waits"),
    (9, "wakes"),
    (7, "cpu_calls"),
    (4, "mem_calls"),
    (16, "irq"),
    (18, "irq_wakeup"),
    (19, "irq_tlb"),
    (21, "irq_custom0"),
    (5, "mem_maps"),
    (6, "mem_unmaps"),
];

struct Probe {
    t: Instant,
    cpu: CpuSnap,
    sysio: [u64; 10],
    me: [u64; 10],
    kern: [u64; 10],
    fs: [u64; 12],
}

fn probe(fs_provider: &moto_stats::ProviderInfo) -> Probe {
    let kernel = moto_stats::Collector::kernel();
    let me_pid = moto_sys::current_pid();
    let rd = |scope: u64| -> [u64; 10] {
        let mut out = [0_u64; 10];
        for (i, (m, _)) in KM.iter().enumerate() {
            out[i] = moto_stats::Collector::read(&kernel, *m, scope).unwrap_or(0);
        }
        out
    };
    Probe {
        fs: crate::fs::read_sys_io_fs_metrics(fs_provider),
        sysio: rd(2),
        me: rd(me_pid),
        kern: rd(1),
        cpu: cpu_snap(),
        t: Instant::now(),
    }
}

fn cpu_line(before: &CpuSnap, after: &CpuSnap, pid: u64, secs: f64) -> String {
    let tsc_in_sec = moto_sys::KernelStaticPage::get().tsc_in_sec as f64;
    let (Some(b), Some(a)) = (before.0.get(&pid), after.0.get(&pid)) else {
        return "n/a".to_owned();
    };
    let mut s = String::new();
    let mut total = 0.0;
    for c in 0..a.len() {
        let k = (a[c].0.saturating_sub(b[c].0)) as f64 / tsc_in_sec / secs * 100.0;
        let u = (a[c].1.saturating_sub(b[c].1)) as f64 / tsc_in_sec / secs * 100.0;
        total += k + u;
        s += &format!("cpu{c}:{:.0}k+{:.0}u ", k, u);
    }
    format!("{s}= {:.0}%", total)
}

fn report(name: &str, b: &Probe, a: &Probe, ops: u64, bytes: u64) {
    let secs = a.t.duration_since(b.t).as_secs_f64();
    let us_op = secs * 1e6 / (ops.max(1) as f64);
    let mbps = bytes as f64 / secs / (MB as f64);
    println!(
        "== {name}: {ops} ops, {:.2} MB in {:.1} ms: {us_op:.1} us/op, {mbps:.1} MB/s",
        bytes as f64 / MB as f64,
        secs * 1e3
    );
    let d = |x: &[u64; 10], y: &[u64; 10], i: usize| y[i].saturating_sub(x[i]);
    let per = |v: u64| v as f64 / ops.max(1) as f64;
    println!(
        "   sys-io: waits {} ({:.2}/op) wakes {} ({:.2}/op) syscalls {} mem_calls {} maps {} unmaps {}",
        d(&b.sysio, &a.sysio, 0),
        per(d(&b.sysio, &a.sysio, 0)),
        d(&b.sysio, &a.sysio, 1),
        per(d(&b.sysio, &a.sysio, 1)),
        d(&b.sysio, &a.sysio, 2),
        d(&b.sysio, &a.sysio, 3),
        d(&b.sysio, &a.sysio, 8),
        d(&b.sysio, &a.sysio, 9),
    );
    println!(
        "   self:   waits {} ({:.2}/op) wakes {} ({:.2}/op) syscalls {} mem_calls {}",
        d(&b.me, &a.me, 0),
        per(d(&b.me, &a.me, 0)),
        d(&b.me, &a.me, 1),
        per(d(&b.me, &a.me, 1)),
        d(&b.me, &a.me, 2),
        d(&b.me, &a.me, 3),
    );
    println!(
        "   kernel: irqs {} wakeup_ipis {} ({:.2}/op) tlb_ipis {} virtio_irq0 {}",
        d(&b.kern, &a.kern, 4),
        d(&b.kern, &a.kern, 5),
        per(d(&b.kern, &a.kern, 5)),
        d(&b.kern, &a.kern, 6),
        d(&b.kern, &a.kern, 7),
    );
    let f = |i: usize| a.fs[i].saturating_sub(b.fs[i]);
    println!(
        "   fs: read_msgs {} write_msgs {} cache hits {} misses {} dedup {} readahead {} dev_reads {} ({} blocks) dev_writes {} ({} blocks)",
        f(3),
        f(9),
        f(0),
        f(1),
        f(2),
        f(5),
        f(6),
        f(10),
        f(8),
        f(11)
    );
    if f(3) > 0 {
        println!(
            "   sys-io on_cmd_read: {:.1} us/msg (TIMINGS on)",
            f(4) as f64 / 1000.0 / f(3) as f64
        );
    }
    println!("   cpu sys-io: {}", cpu_line(&b.cpu, &a.cpu, 2, secs));
    println!(
        "   cpu self:   {}",
        cpu_line(&b.cpu, &a.cpu, moto_sys::current_pid(), secs)
    );
}

fn settle() {
    std::thread::sleep(std::time::Duration::from_millis(300));
}

fn write_file(path: &str, total: usize, chunk: usize, pattern: u8) -> u64 {
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::File::create(path).unwrap();
    let buf = vec![pattern; chunk];
    let mut written = 0;
    while written < total {
        let n = chunk.min(total - written);
        f.write_all(&buf[..n]).unwrap();
        written += n;
    }
    f.flush().unwrap();
    written as u64
}

fn read_seq(path: &str, chunk: usize, passes: usize) -> (u64, u64) {
    let mut f = std::fs::File::open(path).unwrap();
    let mut buf = vec![0_u8; chunk];
    let (mut ops, mut bytes) = (0_u64, 0_u64);
    for _ in 0..passes {
        f.seek(SeekFrom::Start(0)).unwrap();
        loop {
            let n = f.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            ops += 1;
            bytes += n as u64;
        }
    }
    (ops, bytes)
}

fn read_rand(path: &str, file_len: usize, chunk: usize, count: usize, seed: u64) -> (u64, u64) {
    let mut f = std::fs::File::open(path).unwrap();
    let mut buf = vec![0_u8; chunk];
    let mut x = seed | 1;
    let blocks = (file_len / chunk) as u64;
    for _ in 0..count {
        // xorshift64
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let off = (x % blocks) * chunk as u64;
        f.seek(SeekFrom::Start(off)).unwrap();
        f.read_exact(&mut buf).unwrap();
    }
    (count as u64, (count * chunk) as u64)
}

pub fn run(args: &[String]) {
    let dir = std::env::temp_dir();
    let p = |n: &str| format!("{}/fsbench-{n}", dir.display());
    let fs_provider = moto_stats::Collector::providers()
        .into_iter()
        .find(|p| p.id == 2)
        .unwrap();
    let only: Option<&str> = args.get(2).map(String::as_str);
    let want = |name: &str| only.is_none_or(|o| name.starts_with(o));

    println!(
        "fs-bench: tmp {} cpus {}",
        dir.display(),
        moto_sys::KernelStaticPage::get().num_cpus
    );

    // Hot phases: a 1 MB file that stays in sys-io's block cache.
    let hot = p("hot");
    write_file(&hot, MB, 64 * KB, 0xa5);
    read_seq(&hot, MB, 1); // warm the cache
    settle();

    let phases: &[(&str, usize, usize)] = &[
        ("hot_seq_4k", 4 * KB, 4),
        ("hot_seq_16k", 16 * KB, 8),
        ("hot_seq_64k", 64 * KB, 16),
        ("hot_seq_1m", MB, 32),
    ];
    for (name, chunk, passes) in phases {
        if !want(name) {
            continue;
        }
        let b = probe(&fs_provider);
        let (ops, bytes) = read_seq(&hot, *chunk, *passes);
        let a = probe(&fs_provider);
        report(name, &b, &a, ops, bytes);
        settle();
    }
    if want("hot_rand_4k") {
        let b = probe(&fs_provider);
        let (ops, bytes) = read_rand(&hot, MB, 4 * KB, 1024, 7);
        let a = probe(&fs_provider);
        report("hot_rand_4k", &b, &a, ops, bytes);
        settle();
    }

    // Writes. Each file is larger than the block cache, so the later cold
    // reads below really hit the device.
    let big_a = p("big-a");
    let big_b = p("big-b");
    let big_c = p("big-c");
    let writes: &[(&str, &str, usize, usize)] = &[
        ("write_1m", &big_a, 20 * MB, MB),
        ("write_64k", &big_b, 16 * MB, 64 * KB),
        ("write_4k", &big_c, 4 * MB, 4 * KB),
    ];
    for (name, path, total, chunk) in writes {
        if !want(name) && !name.starts_with("write_1m") && !name.starts_with("write_64k") {
            continue;
        }
        let b = probe(&fs_provider);
        let bytes = write_file(path, *total, *chunk, 0x5a);
        let a = probe(&fs_provider);
        report(name, &b, &a, (*total / *chunk) as u64, bytes);
        settle();
    }

    if want("cold_seq_4k") {
        let b = probe(&fs_provider);
        let (ops, bytes) = read_seq(&big_a, 4 * KB, 1);
        let a = probe(&fs_provider);
        report("cold_seq_4k", &b, &a, ops, bytes);
        settle();
    }
    if want("cold_seq_1m") {
        let b = probe(&fs_provider);
        let (ops, bytes) = read_seq(&big_b, MB, 1);
        let a = probe(&fs_provider);
        report("cold_seq_1m", &b, &a, ops, bytes);
        settle();
    }
    if want("cold_fs_read") {
        // std::fs::read: one read call for the whole file (as systest's smoke test).
        write_file(&big_c, 4 * MB, 4 * KB, 0x33); // evict big-b's tail
        let b = probe(&fs_provider);
        let bytes = std::fs::read(&big_b).unwrap().len() as u64;
        let a = probe(&fs_provider);
        report("cold_fs_read", &b, &a, 1, bytes);
        settle();
    }
    if want("cold_rand_4k") {
        let b = probe(&fs_provider);
        let (ops, bytes) = read_rand(&big_a, 20 * MB, 4 * KB, 500, 11);
        let a = probe(&fs_provider);
        report("cold_rand_4k", &b, &a, ops, bytes);
        settle();
    }
    if want("open_close") {
        let b = probe(&fs_provider);
        for _ in 0..1000 {
            let _ = std::fs::File::open(&hot).unwrap();
        }
        let a = probe(&fs_provider);
        report("open_close", &b, &a, 1000, 0);
        settle();
    }
    if want("stat") {
        let b = probe(&fs_provider);
        for _ in 0..1000 {
            let _ = std::fs::metadata(&hot).unwrap();
        }
        let a = probe(&fs_provider);
        report("stat", &b, &a, 1000, 0);
    }
    for f in [&hot, &big_a, &big_b, &big_c] {
        let _ = std::fs::remove_file(f);
    }
    println!("fs-bench done");
}
