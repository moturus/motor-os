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

// Thread-exit destructors follow POSIX, as std's cleanup guard relies on: a
// value of 1 reaches its destructor, a destructor may set its own key again
// for a later round, and keys without a destructor stay readable meanwhile.
static EXIT_DTOR_SEEN: AtomicU32 = AtomicU32::new(0);
static PLAIN_KEY: AtomicUsize = AtomicUsize::new(0);
static DEFER_KEY: AtomicUsize = AtomicUsize::new(0);
static MARKER: u8 = 0;

unsafe extern "C" fn defer_dtor(value: *mut u8) {
    let plain = unsafe { moto_rt::tls::get(PLAIN_KEY.load(Ordering::Relaxed)) };
    let seen = match value.addr() {
        1 => {
            let again = std::ptr::without_provenance_mut(2);
            unsafe { moto_rt::tls::set(DEFER_KEY.load(Ordering::Relaxed), again) };
            1
        }
        2 => 2,
        _ => 4,
    };
    let seen = if std::ptr::eq(plain, &MARKER) {
        seen
    } else {
        8
    };
    EXIT_DTOR_SEEN.fetch_or(seen, Ordering::AcqRel);
}

pub fn test_tls_exit_dtors() {
    let plain = moto_rt::tls::create(None);
    let defer = moto_rt::tls::create(Some(defer_dtor));
    PLAIN_KEY.store(plain, Ordering::Relaxed);
    DEFER_KEY.store(defer, Ordering::Relaxed);
    EXIT_DTOR_SEEN.store(0, Ordering::Relaxed);

    std::thread::spawn(move || unsafe {
        moto_rt::tls::set(plain, (&raw const MARKER).cast_mut());
        moto_rt::tls::set(defer, std::ptr::without_provenance_mut(1));
    })
    .join()
    .unwrap();

    // Both rounds ran, and each still read the destructor-less value.
    assert_eq!(EXIT_DTOR_SEEN.load(Ordering::Acquire), 1 | 2);
    unsafe {
        moto_rt::tls::destroy(plain);
        moto_rt::tls::destroy(defer);
    }
    println!("test_tls_exit_dtors PASS");
}

static SET_DTOR_CALLS: AtomicU32 = AtomicU32::new(0);
static SET_DTOR_VALUE: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn set_dtor(value: *mut u8) {
    SET_DTOR_VALUE.store(value.addr(), Ordering::Relaxed);
    SET_DTOR_CALLS.fetch_add(1, Ordering::Relaxed);
}

pub fn test_tls_set_no_dtor() {
    let key = moto_rt::tls::create(Some(set_dtor));
    SET_DTOR_CALLS.store(0, Ordering::Relaxed);
    SET_DTOR_VALUE.store(0, Ordering::Relaxed);
    std::thread::spawn(move || unsafe {
        // Replacement, including writing the same value, leaves ownership
        // with the caller. Only the final value reaches the exit destructor.
        for value in [2, 3, 3, 0, 0, 4] {
            let ptr = std::ptr::without_provenance_mut(value);
            moto_rt::tls::set(key, ptr);
            assert_eq!(moto_rt::tls::get(key), ptr);
            assert_eq!(SET_DTOR_CALLS.load(Ordering::Relaxed), 0);
        }
    })
    .join()
    .unwrap();
    assert_eq!(SET_DTOR_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(SET_DTOR_VALUE.load(Ordering::Relaxed), 4);
    unsafe { moto_rt::tls::destroy(key) };
    println!("test_tls_set_no_dtor PASS");
}

static CURRENT_DTOR_CALLS: AtomicU32 = AtomicU32::new(0);

struct CurrentOnDrop(std::thread::ThreadId);

impl Drop for CurrentOnDrop {
    fn drop(&mut self) {
        let current = std::thread::current();
        assert_eq!(current.id(), self.0);
        assert_eq!(current.name(), Some("tls-current-on-drop"));
        CURRENT_DTOR_CALLS.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn test_tls_current_on_drop() {
    thread_local! {
        static FIRST: CurrentOnDrop = CurrentOnDrop(std::thread::current().id());
        static SECOND: CurrentOnDrop = CurrentOnDrop(std::thread::current().id());
    }
    CURRENT_DTOR_CALLS.store(0, Ordering::Relaxed);
    std::thread::Builder::new()
        .name("tls-current-on-drop".into())
        .spawn(|| {
            // The cleanup guard already exists when the first key is created.
            // FIRST's destructor resets RUN to DEFER; SECOND must still be
            // able to access the original current-thread handle afterwards.
            FIRST.with(|_| {});
            SECOND.with(|_| {});
        })
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(CURRENT_DTOR_CALLS.load(Ordering::Relaxed), 2);
    println!("test_tls_current_on_drop PASS");
}
