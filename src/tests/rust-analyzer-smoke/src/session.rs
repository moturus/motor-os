use std::io;
use std::process::Command;
use std::time::Instant;

use serde_json::{Value, json};

use crate::process::ServerProcess;
use crate::transport::{Dispatcher, Notification};

pub struct LspSession {
    process: ServerProcess,
    dispatcher: Dispatcher,
}

impl LspSession {
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        Ok(Self {
            process: ServerProcess::spawn(command)?,
            dispatcher: Dispatcher::default(),
        })
    }

    pub fn request(&mut self, method: &str, params: Value, deadline: Instant) -> io::Result<Value> {
        let id = self
            .dispatcher
            .send_request(self.process.stdin()?, method, params)?;
        loop {
            if let Some(response) = self.dispatcher.take_response(id) {
                return Ok(response);
            }
            self.pump(deadline)?;
        }
    }

    pub fn notify(&mut self, method: &str, params: Option<Value>) -> io::Result<()> {
        let mut message = json!({"jsonrpc": "2.0", "method": method});
        if let Some(params) = params {
            message["params"] = params;
        }
        self.process.write(&message)
    }

    pub fn pump(&mut self, deadline: Instant) -> io::Result<()> {
        let message = self.process.read_until(deadline)?;
        if let Some(reply) = self.dispatcher.dispatch(message)? {
            self.process.write(&reply)?;
        }
        Ok(())
    }

    pub fn notifications(&self) -> impl DoubleEndedIterator<Item = &Notification> {
        self.dispatcher.notifications()
    }

    pub fn shutdown(&mut self, deadline: Instant) -> io::Result<()> {
        let response = self.request("shutdown", Value::Null, deadline)?;
        if response.get("error").is_some() {
            return Err(invalid("rust-analyzer rejected shutdown"));
        }
        self.notify("exit", None)?;
        self.process.close_stdin();
        let status = self.process.wait_until(deadline)?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "rust-analyzer exited with {status}; stderr: {}",
                self.process.stderr_tail()
            )));
        }
        Ok(())
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
