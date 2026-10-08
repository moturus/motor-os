use std::fmt;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

static ACTIVE: Mutex<Option<State>> = Mutex::new(None);

fn active() -> MutexGuard<'static, Option<State>> {
    ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct State {
    started: Instant,
    previous: Instant,
}

/// Enables elapsed-time diagnostics for one command on every thread.
pub struct Session {
    previous: Option<State>,
    enabled: bool,
}

impl Session {
    pub fn new(enabled: bool, command: &str) -> Self {
        if !enabled {
            return Self {
                previous: None,
                enabled: false,
            };
        }
        let now = Instant::now();
        let previous = active().replace(State {
            started: now,
            previous: now,
        });
        eprintln!("{}", format_event(Duration::ZERO, Duration::ZERO, command));
        Self {
            previous,
            enabled: true,
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        event("command finished");
        *active() = self.previous.take();
    }
}

pub fn event(label: impl fmt::Display) {
    let mut active = active();
    let Some(state) = active.as_mut() else {
        return;
    };
    let now = Instant::now();
    eprintln!(
        "{}",
        format_event(
            now.duration_since(state.started),
            now.duration_since(state.previous),
            label,
        )
    );
    state.previous = now;
}

fn format_event(total: Duration, phase: Duration, label: impl fmt::Display) -> String {
    format!(
        "[lorry +{:.3}s] {label} ({:.3}s)",
        total.as_secs_f64(),
        phase.as_secs_f64()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_cumulative_and_phase_timestamps() {
        assert_eq!(
            format_event(
                Duration::from_millis(1_234),
                Duration::from_micros(56_789),
                "prepared dependencies",
            ),
            "[lorry +1.234s] prepared dependencies (0.057s)"
        );
    }

    #[test]
    fn records_events_from_other_threads() {
        let session = Session::new(true, "test started");
        let before = active().as_ref().unwrap().previous;
        std::thread::spawn(|| event("worker event")).join().unwrap();
        assert!(active().as_ref().unwrap().previous > before);
        drop(session);
    }
}
