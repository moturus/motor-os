use std::fs::{File, OpenOptions, TryLockError};
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;

fn open() -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(crate::temp_path("systest-file-lock"))
        .unwrap()
}

pub fn run_tests() {
    crate::ensure_temp_dir();
    let path = crate::temp_path("systest-file-lock");
    let _ = std::fs::remove_file(&path);
    concurrent_duplicate_lock_test();
    drop_locked_file_in_async_context_test();
    let first = open();
    let second = open();

    first.lock_shared().unwrap();
    second.lock_shared().unwrap();
    first.unlock().unwrap();
    second.unlock().unwrap();

    first.lock().unwrap();
    assert!(matches!(second.try_lock(), Err(TryLockError::WouldBlock)));
    assert!(matches!(
        second.try_lock_shared(),
        Err(TryLockError::WouldBlock)
    ));
    assert_eq!(
        first.lock().unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );

    let duplicate = first.try_clone().unwrap();
    drop(first);
    assert!(matches!(second.try_lock(), Err(TryLockError::WouldBlock)));

    let waiter = open();
    let (started_tx, started_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        waiter.lock().unwrap();
        waiter.unlock().unwrap();
    });
    started_rx.recv().unwrap();
    std::fs::metadata(&path).unwrap(); // must not queue behind the blocking lock
    duplicate.unlock().unwrap();
    thread.join().unwrap();

    // Closing the final duplicate releases its open-description lock.
    duplicate.lock().unwrap();
    drop(duplicate);
    second.try_lock().unwrap();
    second.unlock().unwrap();
    second.unlock().unwrap();

    second.lock().unwrap();
    let renamed = crate::temp_path("systest-file-lock-renamed");
    let _ = std::fs::remove_file(&renamed);
    std::fs::rename(&path, &renamed).unwrap();
    let renamed_open = OpenOptions::new().read(true).open(&renamed).unwrap();
    assert!(matches!(
        renamed_open.try_lock(),
        Err(TryLockError::WouldBlock)
    ));
    std::fs::remove_file(&renamed).unwrap();
    let replacement = open();
    replacement.try_lock().unwrap();
    replacement.unlock().unwrap();
    second.unlock().unwrap();

    process_cleanup_test();
    println!("file locking tests PASS");
}

fn concurrent_duplicate_lock_test() {
    let blocker = open();
    blocker.lock().unwrap();

    let contender = open();
    let duplicate = contender.try_clone().unwrap();
    let unlocker = contender.try_clone().unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let (result_tx, result_rx) = mpsc::channel();
    let mut threads = Vec::new();

    for file in [contender, duplicate] {
        let barrier = barrier.clone();
        let result_tx = result_tx.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            result_tx.send(file.lock()).unwrap();
        }));
    }
    drop(result_tx);
    barrier.wait();

    let concurrent_result = result_rx.recv_timeout(Duration::from_secs(2));
    if concurrent_result.is_err() {
        blocker.unlock().unwrap();
        for thread in threads {
            thread.join().unwrap();
        }
        panic!("a concurrent lock call on a duplicate blocked behind the pending acquisition");
    }

    assert_eq!(
        concurrent_result.unwrap().unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    assert_eq!(
        unlocker.unlock().unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    blocker.unlock().unwrap();
    result_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    for thread in threads {
        thread.join().unwrap();
    }
}

fn drop_locked_file_in_async_context_test() {
    let file = open();
    file.lock().unwrap();
    moto_async::LocalRuntime::new().block_on(async move {
        drop(file);
    });

    let probe = open();
    probe.try_lock().unwrap();
    probe.unlock().unwrap();
}

fn process_cleanup_test() {
    let ready = crate::temp_path("systest-file-lock-ready");
    let _ = std::fs::remove_file(&ready);
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("file-lock-child")
        .spawn()
        .unwrap();
    while !ready.exists() {
        std::thread::yield_now();
    }
    let file = open();
    assert!(matches!(file.try_lock(), Err(TryLockError::WouldBlock)));
    child.kill().unwrap();
    child.wait().unwrap();
    file.lock().unwrap();
    file.unlock().unwrap();
    let _ = std::fs::remove_file(&ready);
}

pub fn child() -> ! {
    let file = open();
    file.lock().unwrap();
    File::create(crate::temp_path("systest-file-lock-ready")).unwrap();
    loop {
        std::thread::park();
    }
}
