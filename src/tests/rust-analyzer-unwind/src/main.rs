use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Cleanup(Arc<AtomicUsize>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        assert!(std::thread::panicking());
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[inline(never)]
fn cancel(payload: usize, drops: &Arc<AtomicUsize>) {
    let _cleanup = Cleanup(drops.clone());
    // Salsa cancellation deliberately bypasses the panic hook.
    std::panic::resume_unwind(Box::new(payload));
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--abort") {
        // Explicit abort must still terminate, even inside catch_unwind.
        let _ = std::panic::catch_unwind(std::process::abort);
        panic!("abort unexpectedly returned");
    }
    let hooks = Arc::new(AtomicUsize::new(0));
    let counter = hooks.clone();
    std::panic::set_hook(Box::new(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    let drops = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for worker in 0..4 {
            let drops = &drops;
            scope.spawn(move || {
                for round in 0..32 {
                    let payload = worker * 32 + round;
                    let result = std::panic::catch_unwind(|| {
                        let _outer = Cleanup(drops.clone());
                        let result = std::panic::catch_unwind(|| cancel(payload, drops));
                        std::panic::resume_unwind(result.unwrap_err());
                    });
                    assert_eq!(*result.unwrap_err().downcast::<usize>().unwrap(), payload);
                    assert!(!std::thread::panicking());
                }
            });
        }
    });
    assert_eq!(drops.load(Ordering::SeqCst), 256);
    assert_eq!(hooks.load(Ordering::SeqCst), 0);
    let ordinary = std::panic::catch_unwind(|| panic!("ordinary panic"));
    assert!(ordinary.is_err());
    assert_eq!(hooks.load(Ordering::SeqCst), 1);
    assert!(!std::thread::panicking());
    let aborted = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--abort")
        .status()
        .unwrap();
    assert_eq!(aborted.code(), Some(-1));
    println!("native cancellation: payloads, nested cleanup, hooks, and threads PASS");
}
