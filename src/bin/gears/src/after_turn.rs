//! One background command, stopped and joined before another writer starts.

use std::thread::JoinHandle;

use crate::process::{self, Cancellation, Output, Request, RunError};

#[derive(Default)]
pub struct Manager {
    running: Option<Running>,
}

struct Running {
    cancellation: Cancellation,
    thread: JoinHandle<Result<Output, RunError>>,
}

impl Manager {
    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }

    pub fn start(&mut self, request: Request) -> Result<(), String> {
        process::ensure_cleanup()?;
        if self.running.is_some() {
            return Err("after-turn command is already running".into());
        }
        let cancellation = Cancellation::new();
        let token = cancellation.clone();
        let thread = std::thread::Builder::new()
            .name("gears-after-turn".into())
            .spawn(move || process::run(&request, &token, &mut |_, _| {}))
            .map_err(|error| format!("cannot start after-turn command: {error}"))?;
        self.running = Some(Running {
            cancellation,
            thread,
        });
        Ok(())
    }

    pub fn poll(&mut self) -> Result<Vec<String>, String> {
        if self
            .running
            .as_ref()
            .is_some_and(|task| task.thread.is_finished())
        {
            self.finish(false)
        } else {
            Ok(Vec::new())
        }
    }

    pub fn stop(&mut self) -> Result<Vec<String>, String> {
        self.finish(true)
    }

    fn finish(&mut self, cancel: bool) -> Result<Vec<String>, String> {
        let Some(task) = self.running.take() else {
            process::ensure_cleanup()?;
            return Ok(Vec::new());
        };
        if cancel {
            task.cancellation.cancel();
        }
        let result = task.thread.join().map_err(|_| {
            process::mark_cleanup_failed();
            "after-turn runner panicked; child cleanup could not be confirmed".to_string()
        })?;
        let notice = match result {
            Ok(output) if output.cancelled => "after-turn command stopped".to_string(),
            Ok(output) if output.success() => {
                if output.stdout.is_empty() && output.stderr.is_empty() {
                    "after-turn command finished".to_string()
                } else {
                    format!("after-turn command output:\n{}", output.model_text(4096))
                }
            }
            Ok(output) => format!("after-turn command failed:\n{}", output.model_text(4096)),
            Err(error) => format!("after-turn command failed: {error}"),
        };
        process::ensure_cleanup().map_err(|error| format!("{notice}\n{error}"))?;
        Ok(vec![notice])
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            crate::trace::log(crate::trace::Level::Error, &error);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn request(command: &str) -> Request {
        Request {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), command.into()],
            cwd: std::env::temp_dir(),
            stdin: None,
            timeout: Duration::from_secs(5),
            max_output_bytes: 4096,
            env: Vec::new(),
            remove_env: Vec::new(),
        }
    }

    #[test]
    fn completed_commands_report_output_and_failures_once() {
        let mut manager = Manager::default();
        manager
            .start(request("printf result; printf diagnostic >&2; exit 7"))
            .unwrap();
        let notices = manager.finish(false).unwrap();
        assert_eq!(notices.len(), 1);
        assert!(notices[0].contains("failed"));
        assert!(notices[0].contains("result") && notices[0].contains("diagnostic"));
        assert!(manager.poll().unwrap().is_empty());
        assert!(manager.stop().unwrap().is_empty());
        let mut missing = request("");
        missing.program = "/no-such-gears-after-turn-command".into();
        manager.start(missing).unwrap();
        assert!(manager.finish(false).unwrap()[0].contains("cannot run"));
        process::ensure_cleanup().unwrap();
    }

    #[test]
    fn stopping_joins_the_runner_and_stops_its_grandchild() {
        let path =
            std::env::temp_dir().join(format!("gears-after-turn-pid-{}", std::process::id()));
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
        let mut task = request("sleep 30 & printf '%s' $! > \"$PID_FILE\"; wait");
        task.env
            .push(("PID_FILE".into(), path.display().to_string()));
        let mut manager = Manager::default();
        manager.start(task).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let pid = loop {
            if let Ok(text) = std::fs::read_to_string(&path)
                && let Ok(pid @ 2..) = text.parse::<u32>()
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "after-turn child did not start");
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(manager.start(request("printf must-not-run")).is_err());
        assert_eq!(manager.stop().unwrap(), ["after-turn command stopped"]);
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            let state = stat
                .rsplit_once(") ")
                .unwrap()
                .1
                .split_whitespace()
                .next()
                .unwrap();
            assert!(
                matches!(state, "Z" | "X" | "x"),
                "grandchild still running: {stat}"
            );
        }
        assert!(manager.running.is_none());
        std::fs::remove_file(path).unwrap();
    }
}
