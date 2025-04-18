use std::cell::RefCell;
use std::sync::atomic::*;
use std::time::Duration;

static TLS_COUNTER: AtomicU32 = AtomicU32::new(0);
static TLS_EXIT: AtomicBool = AtomicBool::new(false);

struct TlsTester {
    val: u64,
}

impl Drop for TlsTester {
    fn drop(&mut self) {
        TLS_COUNTER.fetch_sub(1, Ordering::Release);
    }
}

impl TlsTester {
    fn new() -> Self {
        TLS_COUNTER.fetch_add(1, Ordering::Release);
        Self { val: 0 }
    }

    fn wait(&self) {
        while !TLS_EXIT.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::new(0, 1000));
        }
    }
}

thread_local! {
    static TLS_TESTER : RefCell<TlsTester> = RefCell::new(TlsTester::new());
}

pub fn test_tls() {
    assert_eq!(0, TLS_COUNTER.load(Ordering::Acquire));
    TLS_EXIT.store(false, Ordering::Release);

    let thread_fn = || {
        TLS_TESTER.with_borrow_mut(|v| {
            v.val = 1;
            v.wait();
        });
    };

    let t1 = std::thread::spawn(thread_fn);
    let t2 = std::thread::spawn(thread_fn);
    let t3 = std::thread::spawn(thread_fn);

    while TLS_COUNTER.load(Ordering::Relaxed) != 3 {
        std::thread::sleep(Duration::new(0, 1000));
    }

    TLS_EXIT.store(true, Ordering::Relaxed);
    t1.join().unwrap();
    t2.join().unwrap();
    t3.join().unwrap();

    assert_eq!(0, TLS_COUNTER.load(Ordering::Acquire));
    println!("test_tls PASS");
}

// From https://github.com/rust-lang/rust/issues/74875.
struct TlsJoiner {
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TlsJoiner {
    fn new() -> Self {
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
        });

        Self {
            thread: Some(thread),
        }
    }
}

impl Drop for TlsJoiner {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

pub fn test_tls_join() {
    thread_local!(
        static R: TlsJoiner = TlsJoiner::new();
    );

    std::thread::spawn(|| {
        R.with(|_| {});
    })
    .join()
    .unwrap();

    println!("test_tls_join PASS");
}
