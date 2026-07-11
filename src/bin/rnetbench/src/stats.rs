// Per-phase performance metrics on Motor OS (no-op on other targets).
//
// Around each benchmark phase, snapshot sys-io's net counters and the
// kernel's per-process CPU/wait metrics, and print the deltas: message
// counts and page fill, packet counts and poll batching, sys-io CPU. This
// makes each run show *where* the time went, not just MiB/s.
//
// Metric ids are resolved by name at runtime (the federated stats protocol
// hardcodes no ids). The counters are sys-io-global: with parallel streams
// (-P) or unrelated network activity, deltas include that traffic too.

pub use imp::PhaseSnapshot;

#[cfg(not(target_os = "motor"))]
mod imp {
    pub struct PhaseSnapshot;

    impl PhaseSnapshot {
        pub fn take() -> Self {
            PhaseSnapshot
        }

        pub fn report(self, _phase: &str) {}
    }
}

#[cfg(target_os = "motor")]
mod imp {
    use std::time::Instant;

    use moto_stats::{Collector, MetricEntry, ProviderInfo};

    // Kernel per-process metrics sampled for sys-io and for this process.
    const KERNEL_METRICS: [&str; 3] = ["cpu_usage", "sys_cpu_waits", "sys_cpu_wakes"];
    const CPU_USAGE: usize = 0; // In TSC ticks.
    const WAITS: usize = 1;
    const WAKES: usize = 2;

    const IO_PAGE_SIZE: f64 = 4096.0; // One io_page per TcpStream Rx/Tx message.

    pub struct PhaseSnapshot {
        stats: Option<Stats>,
        start: Instant, // Taken after the queries so their cost doesn't count.
    }

    struct Stats {
        sys_io: ProviderInfo,
        net: Vec<MetricEntry>,
        sys_io_kernel: [u64; KERNEL_METRICS.len()],
        self_kernel: [u64; KERNEL_METRICS.len()],
    }

    impl PhaseSnapshot {
        pub fn take() -> Self {
            let stats = Stats::take();
            if stats.is_none() {
                static WARN_ONCE: std::sync::Once = std::sync::Once::new();
                WARN_ONCE.call_once(|| {
                    eprintln!("warning: sys-io stats unavailable; metric reports disabled")
                });
            }
            PhaseSnapshot {
                stats,
                start: Instant::now(),
            }
        }

        pub fn report(self, phase: &str) {
            let elapsed = self.start.elapsed().as_secs_f64();
            let Some(before) = self.stats else { return };
            let Some(after) = Stats::take() else { return };

            let names = Collector::describe(&after.sys_io).unwrap_or_default();
            let name_of = |metric: u32| {
                names
                    .iter()
                    .find(|d| d.id == metric)
                    .map(|d| d.name.as_str())
                    .unwrap_or("?")
            };

            println!("--- sys-io metrics for '{phase}' ({elapsed:.2}s) ---");

            let tsc_in_sec = moto_sys::KernelStaticPage::get().tsc_in_sec as f64;
            let cpu_pct = |b: &[u64; 3], a: &[u64; 3]| {
                (a[CPU_USAGE].saturating_sub(b[CPU_USAGE]) as f64) / tsc_in_sec / elapsed * 100.0
            };
            println!(
                "  cpu (of one core): sys-io {:.1}%  rnetbench {:.1}%",
                cpu_pct(&before.sys_io_kernel, &after.sys_io_kernel),
                cpu_pct(&before.self_kernel, &after.self_kernel),
            );
            println!(
                "  waits/wakes: sys-io {}/{}  rnetbench {}/{}",
                after.sys_io_kernel[WAITS].saturating_sub(before.sys_io_kernel[WAITS]),
                after.sys_io_kernel[WAKES].saturating_sub(before.sys_io_kernel[WAKES]),
                after.self_kernel[WAITS].saturating_sub(before.self_kernel[WAITS]),
                after.self_kernel[WAKES].saturating_sub(before.self_kernel[WAKES]),
            );

            // Raw deltas of every sys-io net metric that moved.
            for entry in &after.net {
                let Some(prev) = before.net.iter().find(|e| e.metric == entry.metric) else {
                    continue;
                };
                let delta = entry.value as i64 - prev.value as i64;
                if delta == 0 {
                    continue;
                }
                println!(
                    "  {:<26} {delta:>12}  ({:.0}/s)",
                    name_of(entry.metric),
                    delta as f64 / elapsed
                );
            }

            let net_delta = |name: &str| -> f64 {
                let Some(id) = names.iter().find(|d| d.name == name).map(|d| d.id) else {
                    return 0.0;
                };
                let value =
                    |entries: &[MetricEntry]| entries.iter().find(|e| e.metric == id).map(|e| e.value);
                match (value(&after.net), value(&before.net)) {
                    (Some(a), Some(b)) => a.saturating_sub(b) as f64,
                    _ => 0.0,
                }
            };

            let tx_msgs = net_delta("net.tcp.tx_msgs");
            if tx_msgs > 0.0 {
                let tx_bytes = net_delta("net.tcp.tx_bytes");
                println!(
                    "  tcp tx: {:.0} B/msg ({:.1}% page fill), {:.0} msgs/sec",
                    tx_bytes / tx_msgs,
                    tx_bytes / (tx_msgs * IO_PAGE_SIZE) * 100.0,
                    tx_msgs / elapsed
                );
            }
            let rx_msgs = net_delta("net.tcp.rx_msgs");
            if rx_msgs > 0.0 {
                let rx_bytes = net_delta("net.tcp.rx_bytes");
                println!(
                    "  tcp rx: {:.0} B/msg ({:.1}% page fill), {:.0} msgs/sec, alloc waits/msg {:.2}",
                    rx_bytes / rx_msgs,
                    rx_bytes / (rx_msgs * IO_PAGE_SIZE) * 100.0,
                    rx_msgs / elapsed,
                    net_delta("net.tcp.rx_alloc_waits") / rx_msgs
                );
            }
            let rx_pkts = net_delta("net.device.rx_packets");
            if rx_pkts > 0.0 {
                println!(
                    "  device rx: {:.0} B/pkt",
                    net_delta("net.device.rx_bytes") / rx_pkts
                );
            }
            let tx_pkts = net_delta("net.device.tx_packets");
            if tx_pkts > 0.0 {
                println!(
                    "  device tx: {:.0} B/pkt",
                    net_delta("net.device.tx_bytes") / tx_pkts
                );
            }
            let polls = net_delta("net.poll_runs");
            if polls > 0.0 {
                println!("  pkts/poll: {:.2}", (rx_pkts + tx_pkts) / polls);
            }
            let msgs = tx_msgs + rx_msgs;
            if msgs > 0.0 {
                let sys_io_cpu_usec = after.sys_io_kernel[CPU_USAGE]
                    .saturating_sub(before.sys_io_kernel[CPU_USAGE])
                    as f64
                    / tsc_in_sec
                    * 1_000_000.0;
                println!("  sys-io cpu/msg: {:.1} usec", sys_io_cpu_usec / msgs);
            }
        }
    }

    impl Stats {
        fn take() -> Option<Stats> {
            let sys_io = Collector::provider_by_name("sys-io")?;
            let net = Collector::query(&sys_io).ok()?;

            let kernel = Collector::kernel();
            let descs = Collector::describe(&kernel).ok()?;
            let mut ids = [0_u32; KERNEL_METRICS.len()];
            for (idx, name) in KERNEL_METRICS.iter().enumerate() {
                ids[idx] = descs.iter().find(|d| d.name == *name)?.id;
            }

            // A userspace provider's id is its PID, which is also its kernel scope.
            let sys_io_kernel = read_scope(&kernel, &ids, sys_io.id)?;
            let self_kernel = read_scope(&kernel, &ids, moto_sys::current_pid())?;

            Some(Stats {
                sys_io,
                net,
                sys_io_kernel,
                self_kernel,
            })
        }
    }

    fn read_scope(
        kernel: &ProviderInfo,
        ids: &[u32; KERNEL_METRICS.len()],
        scope: u64,
    ) -> Option<[u64; KERNEL_METRICS.len()]> {
        let entries = Collector::query_scoped(kernel, scope).ok()?;
        let mut out = [0_u64; KERNEL_METRICS.len()];
        for (slot, id) in out.iter_mut().zip(ids) {
            *slot = entries
                .iter()
                .find(|e| e.metric == *id && e.scope == scope)?
                .value;
        }
        Some(out)
    }
}
