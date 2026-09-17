use std::time::Duration;

pub fn report(label: &str, samples: &[Duration]) {
    let mut nanos: Vec<_> = samples.iter().map(Duration::as_nanos).collect();
    nanos.sort_unstable();
    println!(
        "{label}: n={} mean={:.2}us p50={:.2}us p95={:.2}us",
        nanos.len(),
        nanos.iter().sum::<u128>() as f64 / nanos.len() as f64 / 1000.0,
        nanos[nanos.len() / 2] as f64 / 1000.0,
        nanos[nanos.len() * 95 / 100] as f64 / 1000.0,
    );
}
