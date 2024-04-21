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

    println!("starting tls_test");

    let t1 = std::thread::spawn(thread_fn);
    let t2 = std::thread::spawn(thread_fn);
    let t3 = std::thread::spawn(thread_fn);

    println!("tls_test: spawned threads; waiting for the counter");
    while TLS_COUNTER.load(Ordering::Relaxed) != 3 {
        std::thread::sleep(Duration::new(0, 1000));
    }

    println!("tls_test: stopping threads");
    TLS_EXIT.store(true, Ordering::Relaxed);
    t1.join().unwrap();
    t2.join().unwrap();
    t3.join().unwrap();

    assert_eq!(0, TLS_COUNTER.load(Ordering::Acquire));
    println!("tls_test PASS");
}
