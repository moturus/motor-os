use std::cell::RefCell;
use std::fmt;
use std::time::{Duration, Instant};

thread_local! {
    static ACTIVE: RefCell<Option<State>> = const { RefCell::new(None) };
}

struct State {
    started: Instant,
    previous: Instant,
}

/// Enables elapsed-time diagnostics for one command on the current thread.
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
        let previous = ACTIVE.with(|active| {
            active.replace(Some(State {
                started: now,
                previous: now,
            }))
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
        ACTIVE.with(|active| {
            active.replace(self.previous.take());
        });
    }
}

pub fn event(label: impl fmt::Display) {
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
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
    });
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
}
