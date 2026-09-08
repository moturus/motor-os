use std::collections::{BTreeMap, BTreeSet};
use std::io;

use serde_json::{Value, json};

fn invalid() -> io::Error {
    io::Error::other("invalid or incomplete native resource report")
}

pub fn summarize(report: &Value, server: &str) -> io::Result<Value> {
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
                .is_some_and(|name| name.starts_with("/devtools/bin/lorry check"))
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
        ("server_threads_max", 32),
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

pub fn check_processes(summary: &Value, server: &str, roots: &[&str]) -> io::Result<()> {
    for process in summary["observed_processes"]
        .as_array()
        .ok_or_else(invalid)?
    {
        let name = process["debug_name"].as_str().ok_or_else(invalid)?;
        let tool = [
            "/devtools/bin/lorry ",
            "/devtools/rust/bin/rustc ",
            "/devtools/llvm/bin/llvm ",
            "/system/bin/rush /devtools/bi",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Value {
        json!({"interval_ms": 100, "samples": [
            {"elapsed_us": 1000, "physical_used": 10000, "processes": [
                [10, 1, 1, 100, 4, "server"],
                [11, 10, 1, 50, 2, "/devtools/bin/lorry check…"],
                [99, 1, 1, 999999, 999, "unrelated"]]},
            {"elapsed_us": 101000, "physical_used": 20000, "processes": [
                [10, 1, 1, 200, 3, "server"],
                [11, 10, 0, null, null, "/devtools/bin/lorry check…"],
                [12, 11, 1, 500, 8, "rustc"]]}
        ]})
    }

    #[test]
    fn maxima_exclude_unrelated_processes_and_retain_observed_ancestry() {
        let result = summarize(&report(), "server").unwrap();
        assert_eq!(result["server_virtual_bytes_max"], 200);
        assert_eq!(result["server_threads_max"], 4);
        assert_eq!(result["lorry_check_virtual_bytes_max"], 50);
        assert_eq!(result["whole_vm_physical_bytes_max"], 20000);
        assert_eq!(result["maximum_observed_gap_us"], 100000);
        assert_eq!(result["missing_process_measurements"], 1);
        assert_eq!(result["observed_processes"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn missing_server_or_check_and_nonmonotonic_samples_fail() {
        assert!(summarize(&report(), "absent").is_err());
        let mut input = report();
        input["samples"][1]["elapsed_us"] = json!(0);
        assert!(summarize(&input, "server").is_err());
        let mut input = report();
        for sample in input["samples"].as_array_mut().unwrap() {
            sample["processes"]
                .as_array_mut()
                .unwrap()
                .retain(|row| row[0] == 10);
        }
        assert!(summarize(&input, "server").is_err());
    }

    #[test]
    fn approved_limits_accept_boundaries_and_reject_missing_or_excess_measurements() {
        let limits = json!({"server_virtual_bytes_max": 2147483648_u64,
            "server_threads_max": 32, "lorry_check_virtual_bytes_max": 67108864,
            "lorry_check_threads_max": 16, "whole_vm_physical_bytes_max": 3221225472_u64});
        check_limits(&limits).unwrap();
        check_limits(&summarize(&report(), "server").unwrap()).unwrap();
        for (field, value) in limits.as_object().unwrap() {
            for bad in [Value::Null, json!(value.as_u64().unwrap() + 1)] {
                let mut input = limits.clone();
                input[field] = bad;
                assert!(check_limits(&input).is_err(), "{field}");
            }
        }
    }

    #[test]
    fn descendant_classification_rejects_unexpected_tools() {
        let observed = |name| json!({"observed_processes": [{"debug_name": name}]});
        for name in [
            "server",
            "/devtools/bin/lorry check…",
            "/devtools/rust/bin/rustc --cr…",
            "/devtools/llvm/bin/llvm clang…",
            "/system/bin/rush /devtools/bi…",
            "/fixture/target/build-script",
            "/fixture/long-project…",
        ] {
            check_processes(
                &observed(name),
                "server",
                &["/fixture", "/fixture/long-project-name"],
            )
            .unwrap();
        }
        for name in [
            "/devtools/bin/cargo check",
            "/devtools/rust/bin/rust-analyzer-proc-macro-srv",
            "/fixture-unrelated/tool",
            "/user/bin/tool",
        ] {
            assert!(check_processes(&observed(name), "server", &["/fixture"]).is_err());
        }
    }
}
