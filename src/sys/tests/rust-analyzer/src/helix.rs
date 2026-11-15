//! Readiness from Helix's JSON transport records, including reloads and partial writes.
use std::collections::BTreeSet;

pub fn ready(log: &str) -> bool {
    let mut active = BTreeSet::new();
    let (mut loaded, mut scanned, mut checked) = (false, false, false);
    for line in log.lines() {
        let Some((_, json)) = line.split_once("helix_lsp::transport [INFO] rust-analyzer <- ")
        else {
            continue;
        };
        let Ok(message) = serde_json::from_str::<serde_json::Value>(json) else {
            return false;
        };
        if message["method"] != "$/progress" {
            continue;
        }
        let params = &message["params"];
        let Some(token) = params["token"].as_str() else {
            continue;
        };
        let value = &params["value"];
        let kind = value["kind"].as_str().unwrap_or("");
        match kind {
            "begin" => {
                active.insert(token.to_owned());
            }
            "end" => {
                active.remove(token);
            }
            _ => {}
        }
        if token == "rustAnalyzer/Roots Scanned" {
            if kind == "begin" {
                loaded = false;
                scanned = false;
            }
            if let Some(count) = value["message"]
                .as_str()
                .and_then(|s| s.split(':').next())
                .and_then(|s| s.split_once('/'))
            {
                if let (Ok(done), Ok(total)) = (count.0.parse::<u32>(), count.1.parse::<u32>()) {
                    loaded = done == total && total >= 2;
                }
            }
            if kind == "end" {
                scanned = loaded;
            }
        }
        if token.starts_with("rust-analyzer/flycheck/") && kind == "end" {
            checked = true;
        }
    }
    scanned && checked && active.is_empty()
}

#[cfg(test)]
mod tests {
    use super::ready;
    fn progress(token: &str, kind: &str, message: &str) -> String {
        format!(
            "helix_lsp::transport [INFO] rust-analyzer <- {}\n",
            serde_json::json!({
                "method":"$/progress", "params": {"token":token,"value":{"kind":kind,"message":message}}
            })
        )
    }
    fn scan(count: &str) -> String {
        [
            progress("rustAnalyzer/Roots Scanned", "begin", ""),
            progress("rustAnalyzer/Roots Scanned", "report", count),
            progress("rustAnalyzer/Roots Scanned", "end", ""),
        ]
        .concat()
    }
    fn check() -> String {
        progress("rust-analyzer/flycheck/0", "end", "")
    }
    #[test]
    fn compiler_check_and_project_only_scan_are_not_readiness() {
        assert!(!ready(&check()));
        assert!(!ready(&scan("2/2")));
        assert!(!ready(&(check() + &scan("1/1"))));
        assert!(ready(&(check() + &scan("2/2"))));
    }
    #[test]
    fn reload_and_indexing_must_finish() {
        let mut log = check() + &scan("2/2") + &progress("rustAnalyzer/cachePriming", "begin", "");
        assert!(!ready(&log));
        log += &progress("rustAnalyzer/Roots Scanned", "begin", "");
        log += &progress("rustAnalyzer/cachePriming", "end", "");
        assert!(!ready(&log));
        assert!(ready(&(log + &scan("2/2"))));
    }
    #[test]
    fn partial_json_waits_but_human_diagnostics_are_not_wire_records() {
        let log = check() + &scan("2/2");
        assert!(!ready(
            &(log.clone() + "helix_lsp::transport [INFO] rust-analyzer <- {")
        ));
        assert!(ready(
            &(log
                + "helix_lsp::transport [ERROR] rust-analyzer <- ServerError(-32801): content modified\n")
        ));
    }
}
