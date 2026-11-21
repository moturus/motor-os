use std::collections::{BTreeMap, BTreeSet};
use std::io;

use serde_json::{Value, json};

fn invalid() -> io::Error {
    io::Error::other("invalid or incomplete native resource report")
}

pub fn summarize(report: &Value, server: &str) -> io::Result<Value> {
    summarize_for_lorry(report, server, "/user/bin/dev/lorry")
}

pub fn summarize_for_lorry(report: &Value, server: &str, lorry: &str) -> io::Result<Value> {
    let samples = report["samples"].as_array().ok_or_else(invalid)?;
    if samples.is_empty() || report["interval_ms"] != 100 {
        return Err(invalid());
    }
    let mut identities = BTreeMap::new();
    let mut roots = BTreeSet::new();
    for sample in samples {
        for row in sample["processes"].as_array().ok_or_else(invalid)? {
            let pid = row[0].as_u64().ok_or_else(invalid)?;
            let parent = row[1].as_u64().ok_or_else(invalid)?;
            let name = row[5].as_str().ok_or_else(invalid)?;
            identities.entry(pid).or_insert((parent, name));
            if name == server {
                roots.insert(pid);
            }
        }
    }
    if roots.len() != 1 {
        return Err(invalid());
    }
    let root = *roots.first().unwrap();
    let mut descendants = roots.clone();
    loop {
        let previous = descendants.len();
        for (&pid, &(parent, _)) in &identities {
            if descendants.contains(&parent) {
                descendants.insert(pid);
            }
        }
        if descendants.len() == previous {
            break;
        }
    }
    let mut maxima: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    let mut physical_max = 0;
    let mut missing = 0;
    let mut previous_time = 0;
    let mut max_gap = 0;
    for sample in samples {
        let time = sample["elapsed_us"].as_u64().ok_or_else(invalid)?;
        if time < previous_time {
            return Err(invalid());
        }
        max_gap = max_gap.max(time - previous_time);
        previous_time = time;
        physical_max = physical_max.max(sample["physical_used"].as_u64().ok_or_else(invalid)?);
        for row in sample["processes"].as_array().ok_or_else(invalid)? {
            let pid = row[0].as_u64().ok_or_else(invalid)?;
            if !descendants.contains(&pid) {
                continue;
            }
            let (Some(memory), Some(threads)) = (row[3].as_u64(), row[4].as_u64()) else {
                if row[3].is_null() && row[4].is_null() {
                    missing += 1;
                    continue;
                }
                return Err(invalid());
            };
            let entry = maxima.entry(pid).or_default();
            entry.0 = entry.0.max(memory);
            entry.1 = entry.1.max(threads);
        }
    }
    let server_max = maxima.get(&root).ok_or_else(invalid)?;
    let observed = descendants
        .iter()
        .map(|pid| {
            let (parent, name) = identities[pid];
            json!({"pid": pid, "ppid": parent, "debug_name": name,
            "virtual_bytes_max": maxima.get(pid).map(|entry| entry.0),
            "threads_max": maxima.get(pid).map(|entry| entry.1)})
        })
        .collect::<Vec<_>>();
    let checks = observed
        .iter()
        .filter(|process| {
            process["debug_name"]
                .as_str()
                .is_some_and(|name| name.starts_with(&format!("{lorry} check")))
        })
        .collect::<Vec<_>>();
    if checks.is_empty() {
        return Err(io::Error::other(
            "sampler observed no descendant lorry check",
        ));
    }
    Ok(
        json!({"samples": samples.len(), "interval_ms": report["interval_ms"],
        "maximum_observed_gap_us": max_gap, "missing_process_measurements": missing,
        "server_virtual_bytes_max": server_max.0, "server_threads_max": server_max.1,
        "lorry_check_virtual_bytes_max": checks.iter().filter_map(|row| row["virtual_bytes_max"].as_u64()).max(),
        "lorry_check_threads_max": checks.iter().filter_map(|row| row["threads_max"].as_u64()).max(),
        "whole_vm_physical_bytes_max": physical_max, "observed_processes": observed,
        "limitations": report["limitations"]}),
    )
}

pub fn check_limits(summary: &Value) -> io::Result<()> {
    // Approved for the two-project acceptance fixture in the 8 GiB, four-CPU VM.
    for (field, limit) in [
        ("server_virtual_bytes_max", 2 * 1024 * 1024 * 1024),
        ("lorry_check_virtual_bytes_max", 64 * 1024 * 1024),
        ("lorry_check_threads_max", 16),
        ("whole_vm_physical_bytes_max", 3 * 1024 * 1024 * 1024),
    ] {
        let observed = summary[field].as_u64().ok_or_else(invalid)?;
        if observed > limit {
            return Err(io::Error::other(format!(
                "native resource regression: {field}={observed}, approved maximum={limit}"
            )));
        }
    }
    Ok(())
}

pub fn check_processes(
    summary: &Value,
    server: &str,
    lorry: &str,
    roots: &[&str],
) -> io::Result<()> {
    for process in summary["observed_processes"]
        .as_array()
        .ok_or_else(invalid)?
    {
        let name = process["debug_name"].as_str().ok_or_else(invalid)?;
        let tool = name.starts_with(&format!("{lorry} "))
            || [
                "/user/bin/dev/lorry ",
                "/user/lib/rust/bin/rustc ",
                "/user/lib/llvm/bin/llvm ",
                // Compiler launchers are Rush scripts.
                "/user/bin/rush /user/bin/dev/",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix));
        // Long admitted fixture paths may already be truncated before the
        // executable's basename. This is classification, not an execution audit.
        let fixture = roots.iter().any(|root| {
            name.starts_with(&format!("{root}/"))
                || name
                    .strip_suffix('…')
                    .is_some_and(|prefix| root.starts_with(prefix))
        });
        if name != server && !tool && !fixture {
            return Err(io::Error::other(format!(
                "unexpected sampled analyzer descendant: {process}"
            )));
        }
    }
    Ok(())
}
