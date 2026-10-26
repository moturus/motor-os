//! Matched remote benchmarks; rnetbench already reports sys-io and client cost.
use moto_sdk::stats::{Collector, ProviderInfo};

fn process_metrics(pid: u64) -> [u64; 3] {
    if pid == 0 {
        return [0; 3];
    }
    let kernel = Collector::kernel();
    let descriptions = Collector::describe(&kernel).unwrap();
    let values = Collector::query_scoped(&kernel, pid).unwrap();
    ["cpu_usage", "sys_cpu_waits", "sys_cpu_wakes"].map(|name| {
        let id = descriptions
            .iter()
            .find(|metric| metric.name == name)
            .unwrap()
            .id;
        values
            .iter()
            .find(|metric| metric.metric == id && metric.scope == pid)
            .unwrap()
            .value
    })
}

fn packet_metrics(provider: &ProviderInfo) {
    let descriptions = Collector::describe(provider).unwrap();
    let values = Collector::query(provider).unwrap();
    for description in descriptions {
        if description.name.starts_with("net.ip_device.") {
            let value = values
                .iter()
                .find(|metric| metric.metric == description.id)
                .unwrap()
                .value;
            println!("packet metric {}={value}", description.name);
        }
    }
}

pub fn run(pid: &str, endpoint: &str) {
    let pid = pid.parse().unwrap();
    let binary = std::env::current_exe().unwrap().with_file_name("rnetbench");
    // SSH can become ready before the stats service's delayed registration.
    // Use the suite's service-readiness check, then its fixed service identity.
    crate::tcp::read_sys_io_metric("net.num_devices");
    let sys_io = ProviderInfo {
        id: moto_sys::stats::PID_SYS_IO,
        name: "sys-io".into(),
        url: "sys-io-stats".into(),
    };
    for size in [64, 65536] {
        let before = process_metrics(pid);
        let started = std::time::Instant::now();
        let status = std::process::Command::new(&binary)
            .args([
                "--client",
                endpoint,
                "--time",
                "2",
                "--buf-size",
                &size.to_string(),
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let elapsed = started.elapsed().as_secs_f64();
        let after = process_metrics(pid);
        let ticks = moto_sys::KernelStaticPage::get().tsc_in_sec as f64;
        println!(
            "provider metrics pid={pid} buffer={size} elapsed={elapsed:.3}s cpu={:.2}% waits={} wakes={}",
            (after[0] - before[0]) as f64 / ticks / elapsed * 100.0,
            after[1] - before[1],
            after[2] - before[2]
        );
        packet_metrics(&sys_io);
    }
}
