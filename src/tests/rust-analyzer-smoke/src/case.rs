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
                    "experimental": {"serverStatusNotification": true}
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

    pub fn wait_for_flychecks(&mut self, expected: usize) -> io::Result<()> {
        loop {
            let mut begun = HashSet::new();
            let mut ended = HashSet::new();
            for notification in self.session.notifications() {
                if notification.method != "$/progress" {
                    continue;
                }
                let Some(token) = notification.params["token"].as_str() else {
                    continue;
                };
                if !token.starts_with("rust-analyzer/flycheck/") {
                    continue;
                }
                match notification.params["value"]["kind"].as_str() {
                    Some("begin") => _ = begun.insert(token.to_owned()),
                    Some("end") => _ = ended.insert(token.to_owned()),
                    _ => {}
                }
            }
            if begun.len() > expected || ended.len() > expected {
                return Err(invalid("rust-analyzer ran too many flychecks"));
            }
            if ended.len() == expected {
                if begun == ended {
                    return Ok(());
                }
                return Err(invalid("flycheck ended without a matching begin"));
            }
            self.session.pump(self.deadline)?;
        }
    }

    pub fn open(&mut self, path: &Path) -> io::Result<String> {
        let uri = file_uri(path);
        let text = fs::read_to_string(path)?;
        self.session.notify(
            "textDocument/didOpen",
            Some(json!({
                "textDocument": {"uri": uri, "languageId": "rust", "version": 1, "text": text}
            })),
        )?;
        Ok(uri)
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

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
