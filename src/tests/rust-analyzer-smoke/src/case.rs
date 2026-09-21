use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::semantic::{Toolchain, file_uri, position};
use crate::session::LspSession;

pub struct SemanticCase {
    session: LspSession,
    deadline: Instant,
}

impl SemanticCase {
    pub fn start(
        toolchain: &Toolchain,
        root: &Path,
        folders: &[(&str, &Path)],
        initialization_options: Value,
        timeout: Duration,
    ) -> io::Result<Self> {
        let deadline = Instant::now() + timeout;
        let mut command = Command::new(&toolchain.rust_analyzer);
        command
            .current_dir(root)
            .env("RUSTUP_TOOLCHAIN", &toolchain.name)
            .env_remove("RA_LOG");
        if let Ok(log) = std::env::var("MOTOR_RA_SMOKE_LOG") {
            command.env("RA_LOG", log);
        }
        Self::start_command(command, root, folders, initialization_options, deadline)
    }

    pub fn start_command(
        mut command: Command,
        root: &Path,
        folders: &[(&str, &Path)],
        initialization_options: Value,
        deadline: Instant,
    ) -> io::Result<Self> {
        let mut session = LspSession::spawn(&mut command)?;
        let workspace_folders: Vec<_> = folders
            .iter()
            .map(|(name, path)| json!({"name": name, "uri": file_uri(path)}))
            .collect();
        let response = session.request(
            "initialize",
            json!({
                "processId": null,
                "clientInfo": {"name": "motor-ra-smoke"},
                "rootUri": file_uri(root),
                "workspaceFolders": workspace_folders,
                "capabilities": {
                    "window": {"workDoneProgress": true},
                    "workspace": {"workspaceFolders": true},
                    "experimental": {
                        "colorDiagnosticOutput": true,
                        "serverStatusNotification": true
                    }
                },
                "initializationOptions": initialization_options
            }),
            deadline,
        )?;
        rpc_result(response)?;
        session.notify("initialized", Some(json!({})))?;
        Ok(Self { session, deadline })
    }

    pub fn wait_for_quiescence(&mut self) -> io::Result<()> {
        loop {
            for notification in self.session.notifications() {
                if notification.method != "experimental/serverStatus" {
                    continue;
                }
                if notification.params["health"] != "ok" {
                    return Err(invalid(format!(
                        "rust-analyzer workspace health is not ok: {}",
                        notification.params
                    )));
                }
                if notification.params["quiescent"] == true {
                    return Ok(());
                }
            }
            self.session.pump(self.deadline)?;
        }
    }

    // Wait until `expected` flychecks began and ended since the notification log
    // was last cleared, and none is running.
    pub fn wait_for_flychecks(&mut self, expected: usize) -> io::Result<()> {
        loop {
            let events = self.session.notifications().filter_map(|notification| {
                if notification.method != "$/progress" {
                    return None;
                }
                let token = notification.params["token"].as_str()?;
                let id = token.strip_prefix("rust-analyzer/flycheck/")?;
                Some((notification.params["value"]["kind"].as_str()?, id))
            });
            if flychecks_done(events, expected)? {
                return Ok(());
            }
            self.session.pump(self.deadline)?;
        }
    }

    pub fn open(&mut self, path: &Path) -> io::Result<String> {
        let text = fs::read_to_string(path)?;
        self.open_text(path, &text)
    }

    pub fn open_text(&mut self, path: &Path, text: &str) -> io::Result<String> {
        let uri = file_uri(path);
        self.session.notify(
            "textDocument/didOpen",
            Some(json!({
                "textDocument": {"uri": uri, "languageId": "rust", "version": 1, "text": text}
            })),
        )?;
        Ok(uri)
    }

    pub fn text_request(
        &mut self,
        method: &str,
        path: &Path,
        text: &str,
        needle: &str,
    ) -> io::Result<Value> {
        let result = self.session.request(
            method,
            json!({"textDocument": {"uri": file_uri(path)}, "position": position(text, needle)?}),
            self.deadline,
        ).and_then(rpc_result);
        result.map_err(|error| {
            io::Error::new(error.kind(), format!("{method} at {needle:?}: {error}"))
        })
    }

    // Call only after the previous check completed and the guest file was
    // written. Discard consumed events so a reused flycheck token is new work.
    pub fn save_text(&mut self, path: &Path, version: u32, text: &str) -> io::Result<()> {
        self.session.clear_notifications();
        let uri = file_uri(path);
        self.session.notify(
            "textDocument/didChange",
            Some(json!({
                "textDocument": {"uri": uri, "version": version},
                "contentChanges": [{"text": text}]
            })),
        )?;
        self.session.notify(
            "textDocument/didSave",
            Some(json!({
                "textDocument": {"uri": uri}
            })),
        )
    }

    pub fn wait_for_rustc_error(&mut self, uri: &str, present: bool) -> io::Result<()> {
        loop {
            if let Some(diagnostics) = self.latest_diagnostics(uri).and_then(Value::as_array) {
                let has_error = diagnostics.iter().any(|diagnostic| {
                    diagnostic["source"] == "rustc" && diagnostic["severity"] == 1
                });
                if has_error == present {
                    return Ok(());
                }
            }
            self.session.pump(self.deadline)?;
        }
    }

    pub fn definition(&mut self, path: &Path, needle: &str) -> io::Result<String> {
        let response = self.session.request(
            "textDocument/definition",
            json!({
                "textDocument": {"uri": file_uri(path)},
                "position": position(&fs::read_to_string(path)?, needle)?
            }),
            self.deadline,
        )?;
        definition_uri(rpc_result(response)?).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "{error}; rust-analyzer stderr: {}",
                    self.session.stderr_tail()
                ),
            )
        })
    }

    pub fn hover(&mut self, path: &Path, needle: &str) -> io::Result<Value> {
        let response = self.session.request(
            "textDocument/hover",
            json!({
                "textDocument": {"uri": file_uri(path)},
                "position": position(&fs::read_to_string(path)?, needle)?
            }),
            self.deadline,
        )?;
        let result = rpc_result(response)?;
        if result.is_null() {
            return Err(invalid("rust-analyzer returned no hover result"));
        }
        Ok(result)
    }

    pub fn latest_diagnostics(&self, uri: &str) -> Option<&Value> {
        self.session.notifications().rev().find_map(|notification| {
            (notification.method == "textDocument/publishDiagnostics"
                && notification.params["uri"] == uri)
                .then_some(&notification.params["diagnostics"])
        })
    }

    pub fn stderr_tail(&self) -> String {
        self.session.stderr_tail()
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        self.session.shutdown(self.deadline)
    }
}

fn rpc_result(mut response: Value) -> io::Result<Value> {
    if let Some(error) = response.get("error") {
        return Err(invalid(format!("LSP request failed: {error}")));
    }
    response
        .get_mut("result")
        .map(Value::take)
        .ok_or_else(|| invalid("LSP response has no result"))
}

fn definition_uri(result: Value) -> io::Result<String> {
    let location = result
        .as_array()
        .and_then(|locations| locations.first())
        .unwrap_or(&result);
    location
        .get("uri")
        .or_else(|| location.get("targetUri"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid("rust-analyzer returned no definition"))
}

// rust-analyzer also restarts flycheck by itself, when cache priming ends and
// whenever the workspace becomes quiescent, and a restart ends the running
// check. An `end` without a `begin` closes a check that began before the log
// was cleared: it is no event of this wait.
fn flychecks_done<'a>(
    events: impl Iterator<Item = (&'a str, &'a str)>,
    expected: usize,
) -> io::Result<bool> {
    let mut running = HashSet::new();
    let mut finished = HashSet::new();
    let mut sequence = Vec::new();
    for (kind, id) in events {
        match kind {
            "begin" => _ = running.insert(id),
            "end" if running.remove(id) => _ = finished.insert(id),
            "end" => {}
            _ => continue,
        }
        sequence.push(format!("{kind}:{id}"));
    }
    if running.union(&finished).count() > expected {
        return Err(invalid(format!(
            "rust-analyzer ran too many flychecks, expected {expected}: {sequence:?}"
        )));
    }
    Ok(finished.len() == expected && running.is_empty())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(test)]
mod tests {
    use super::flychecks_done;

    fn done(events: &[(&str, &str)], expected: usize) -> std::io::Result<bool> {
        flychecks_done(events.iter().copied(), expected)
    }

    #[test]
    fn a_restarted_flycheck_is_awaited_again() {
        let mut events = vec![("begin", "1"), ("begin", "0"), ("end", "0"), ("end", "1")];
        assert!(done(&events, 2).unwrap());
        // A second automatic restart: the first round was only cancelled.
        events.extend([("begin", "0"), ("begin", "1")]);
        assert!(!done(&events, 2).unwrap());
        events.extend([("report", "0"), ("end", "1"), ("end", "0")]);
        assert!(done(&events, 2).unwrap());
    }

    #[test]
    fn a_save_outlives_a_check_begun_before_it() {
        // The save cancels a check whose `begin` was cleared from the log.
        assert!(!done(&[("end", "0")], 1).unwrap());
        assert!(!done(&[("end", "0"), ("begin", "0"), ("end", "1")], 1).unwrap());
        assert!(
            done(
                &[("end", "0"), ("begin", "0"), ("end", "1"), ("end", "0")],
                1
            )
            .unwrap()
        );
    }

    #[test]
    fn a_save_checks_one_workspace() {
        assert!(done(&[("begin", "0"), ("begin", "1")], 1).is_err());
    }
}
