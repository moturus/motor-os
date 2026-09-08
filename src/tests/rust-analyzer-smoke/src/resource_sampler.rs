#[cfg(not(target_os = "motor"))]
fn main() {
    eprintln!("the resource sampler runs only on Motor OS");
    std::process::exit(2);
}

#[cfg(target_os = "motor")]
fn main() -> std::io::Result<()> {
    native::run()
}

#[cfg(target_os = "motor")]
mod native {
    use std::io::{self, Read};
    use std::sync::mpsc::{self, TryRecvError};
    use std::time::{Duration, Instant};

    use moto_stats::{Collector, MetricEntry};
    use moto_sys::stats::{MemoryStats, ProcessInfoV1};
    use rust_analyzer_smoke::transport::write_frame;
    use serde_json::json;

    const INTERVAL: Duration = Duration::from_millis(100);
    const LIMIT: Duration = Duration::from_secs(90);
    const MAX_ROWS: usize = 32_768;

    fn error(value: impl std::fmt::Debug) -> io::Error {
        io::Error::other(format!("native resource sampler: {value:?}"))
    }

    fn value(entries: &[MetricEntry], id: u32) -> io::Result<Option<u64>> {
        // A process may disappear between enumeration and its metric query.
        if entries.is_empty() {
            return Ok(None);
        }
        entries
            .iter()
            .find(|entry| entry.metric == id)
            .map(|entry| Some(entry.value))
            .ok_or_else(|| error("nonempty process metrics omit a required field"))
    }

    pub fn run() -> io::Result<()> {
        let kernel = Collector::kernel();
        let catalog = Collector::describe(&kernel).map_err(error)?;
        let metric = |name| {
            catalog
                .iter()
                .find(|entry| entry.name == name)
                .map(|entry| entry.id)
                .ok_or_else(|| error(format!("missing metric {name}")))
        };
        let memory_id = metric("memory_usage")?;
        let threads_id = metric("active_threads")?;
        let (sender, stop) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let result = io::stdin().read(&mut [0]).and_then(|count| {
                if count == 0 {
                    Ok(())
                } else {
                    Err(error("expected stdin EOF"))
                }
            });
            let _ = sender.send(result);
        });
        let start = Instant::now();
        let mut samples = Vec::new();
        let mut rows = 0;
        loop {
            let stopping = match stop.try_recv() {
                Ok(result) => {
                    result?;
                    true
                }
                Err(TryRecvError::Empty) => false,
                Err(TryRecvError::Disconnected) => return Err(error("stdin reader disconnected")),
            };
            if start.elapsed() >= LIMIT {
                return Err(error("sampling deadline expired"));
            }
            let memory = MemoryStats::get().map_err(error)?;
            let mut processes = Vec::new();
            let mut next = 1;
            loop {
                let mut page = [ProcessInfoV1::default(); 64];
                let count = ProcessInfoV1::list(next, &mut page).map_err(error)?;
                if count == 0 {
                    break;
                }
                for process in &page[..count] {
                    rows += 1;
                    if rows > MAX_ROWS {
                        return Err(error("sample row bound exceeded"));
                    }
                    let entries = Collector::query_scoped(&kernel, process.pid).map_err(error)?;
                    processes.push((
                        process.pid,
                        process.parent_pid,
                        process.active,
                        value(&entries, memory_id)?,
                        value(&entries, threads_id)?,
                        process.debug_name().to_owned(),
                    ));
                }
                next = page[count - 1].pid + 1;
                if count < page.len() {
                    break;
                }
            }
            samples.push(json!({"elapsed_us": start.elapsed().as_micros(),
                "physical_total": memory.available, "physical_used": memory.used(),
                "processes": processes}));
            if samples.len() == 1 {
                write_frame(io::stdout(), &json!({"ready": true}))?;
            }
            // Include one observation after the host has confirmed server exit.
            if stopping {
                break;
            }
            std::thread::sleep(INTERVAL);
        }
        reader.join().map_err(|_| error("stdin reader panicked"))?;
        write_frame(
            io::stdout(),
            &json!({
                "interval_ms": INTERVAL.as_millis(), "max_rows": MAX_ROWS,
                "process_columns": ["pid", "ppid", "active", "virtual_bytes", "active_threads", "debug_name"],
                "limitations": "sampled maxima, not exact peaks or RSS; process names are truncated and enumeration is not an execution audit",
                "samples": samples
            }),
        )
    }
}
