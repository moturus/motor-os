//! A turn-wide cancellation signal shared by providers, hooks, and tools.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
        crate::platform::take_interrupt();
    }

    pub fn cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst) || crate::platform::interrupt_pending()
    }
}
