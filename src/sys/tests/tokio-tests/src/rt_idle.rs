#[cfg(target_os = "motor")]
use std::time::{Duration, Instant};

#[cfg(target_os = "motor")]
fn test_idle_parking_lot_runtime_parks_workers() {
    use moto_stats::Collector;

    const SAMPLE_TIME: Duration = Duration::from_millis(250);

    let kernel = Collector::kernel();
    let cpu_metric = Collector::describe(&kernel)
        .unwrap()
        .iter()
        .find(|metric| metric.name == "cpu_usage")
        .expect("kernel cpu_usage metric")
        .id;
    let pid = std::process::id() as u64;
    let workers = std::thread::available_parallelism().unwrap().get();
    // A pending timer drives Tokio through the parking_lot-backed timed parker.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .unwrap();

    // Runtime metrics exclude CPU spent inside the parker, so sample the process.
    let observer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        let cpu_before = Collector::read(&kernel, cpu_metric, pid).unwrap();
        let wall_start = Instant::now();
        std::thread::sleep(SAMPLE_TIME);
        let wall_elapsed = wall_start.elapsed();
        let cpu_after = Collector::read(&kernel, cpu_metric, pid).unwrap();
        (cpu_before, cpu_after, wall_elapsed)
    });

    runtime.block_on(async { tokio::time::sleep(SAMPLE_TIME + SAMPLE_TIME).await });
    let (cpu_before, cpu_after, wall_elapsed) = observer.join().unwrap();
    drop(runtime);

    let tsc_per_second = moto_sys::KernelStaticPage::get().tsc_in_sec as u128;
    let cpu_ns = (cpu_after - cpu_before) as u128 * 1_000_000_000 / tsc_per_second;
    let wall_ns = wall_elapsed.as_nanos();
    println!(
        "idle Tokio runtime: workers={workers} wall={wall_elapsed:?} cpu={:?}",
        Duration::from_nanos(cpu_ns.try_into().unwrap_or(u64::MAX))
    );

    assert!(
        cpu_ns < wall_ns / 2,
        "idle multi-thread runtime consumed more than half of one CPU: \
         cpu_ns={cpu_ns}, wall_ns={wall_ns}, workers={workers}"
    );
}

pub fn run_all_tests() {
    #[cfg(target_os = "motor")]
    test_idle_parking_lot_runtime_parks_workers();

    #[cfg(not(target_os = "motor"))]
    println!("test_idle_parking_lot_runtime_parks_workers: SKIP (Motor OS only)");
}
