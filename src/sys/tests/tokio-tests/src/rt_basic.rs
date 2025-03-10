use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tokio_test::{assert_err, assert_ok};

use tokio::time::Duration;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::thread;

fn test_spawned_task_does_not_progress_without_block_on() {
    let (tx, mut rx) = oneshot::channel();

    let rt = rt();

    rt.spawn(async move {
        assert_ok!(tx.send("hello"));
    });

    thread::sleep(Duration::from_millis(50));

    assert_err!(rx.try_recv());

    let out = rt.block_on(async { assert_ok!(rx.await) });

    assert_eq!(out, "hello");
    println!("\ttest_spawned_task_does_not_progress_without_block_on PASS");
}

fn test_no_extra_poll() {
    use pin_project_lite::pin_project;
    use std::pin::Pin;
    use std::sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Arc,
    };
    use std::task::{Context, Poll};
    use tokio_stream::{Stream, StreamExt};

    pin_project! {
        struct TrackPolls<S> {
            npolls: Arc<AtomicUsize>,
            #[pin]
            s: S,
        }
    }

    impl<S> Stream for TrackPolls<S>
    where
        S: Stream,
    {
        type Item = S::Item;
        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.project();
            this.npolls.fetch_add(1, SeqCst);
            this.s.poll_next(cx)
        }
    }

    let (tx, rx) = crate::support::mpsc_stream::unbounded_channel_stream::<()>();
    let rx = TrackPolls {
        npolls: Arc::new(AtomicUsize::new(0)),
        s: rx,
    };
    let npolls = Arc::clone(&rx.npolls);

    let rt = rt();

    // TODO: could probably avoid this, but why not.
    let mut rx = Box::pin(rx);

    rt.spawn(async move { while rx.next().await.is_some() {} });
    rt.block_on(async {
        tokio::task::yield_now().await;
    });

    // should have been polled exactly once: the initial poll
    assert_eq!(npolls.load(SeqCst), 1);

    tx.send(()).unwrap();
    rt.block_on(async {
        tokio::task::yield_now().await;
    });

    // should have been polled twice more: once to yield Some(), then once to yield Pending
    assert_eq!(npolls.load(SeqCst), 1 + 2);

    drop(tx);
    rt.block_on(async {
        tokio::task::yield_now().await;
    });

    // should have been polled once more: to yield None
    assert_eq!(npolls.load(SeqCst), 1 + 2 + 1);
    println!("\ttest_no_extra_poll PASS");
}

fn test_acquire_mutex_in_drop() {
    use futures::future::pending;
    use tokio::task;

    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();

    let rt = rt();

    rt.spawn(async move {
        let _ = rx2.await;
        unreachable!();
    });

    rt.spawn(async move {
        let _ = rx1.await;
        tx2.send(()).unwrap();
        unreachable!();
    });

    // Spawn a task that will never notify
    rt.spawn(async move {
        pending::<()>().await;
        tx1.send(()).unwrap();
    });

    // Tick the loop
    rt.block_on(async {
        task::yield_now().await;
    });

    // Drop the rt
    drop(rt);
    println!("\ttest_acquire_mutex_in_drop PASS");
}

fn test_drop_tasks_in_context() {
    static SUCCESS: AtomicBool = AtomicBool::new(false);

    struct ContextOnDrop;

    impl Future for ContextOnDrop {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            Poll::Pending
        }
    }

    impl Drop for ContextOnDrop {
        fn drop(&mut self) {
            if tokio::runtime::Handle::try_current().is_ok() {
                SUCCESS.store(true, Ordering::SeqCst);
            }
        }
    }

    let rt = rt();
    rt.spawn(ContextOnDrop);
    drop(rt);

    assert!(SUCCESS.load(Ordering::SeqCst));
    println!("\ttest_drop_tasks_in_context PASS");
}

fn test_spawn_two() {
    let rt = rt();

    let out = rt.block_on(async {
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            tokio::spawn(async move {
                tx.send("ZOMG").unwrap();
            });
        });

        assert_ok!(rx.await)
    });

    assert_eq!(out, "ZOMG");

    let metrics = rt.metrics();
    drop(rt);
    assert_eq!(0, metrics.remote_schedule_count());

    let mut local = 0;
    for i in 0..metrics.num_workers() {
        local += metrics.worker_local_schedule_count(i);
    }

    assert_eq!(2, local);
    println!("\ttest_spawn_two PASS");
}

fn test_spawn_remote() {
    let rt = rt();

    let out = rt.block_on(async {
        let (tx, rx) = oneshot::channel();

        let handle = tokio::spawn(async move {
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(10));
                tx.send("ZOMG").unwrap();
            });

            rx.await.unwrap()
        });

        handle.await.unwrap()
    });

    assert_eq!(out, "ZOMG");

    let metrics = rt.metrics();
    drop(rt);
    assert_eq!(1, metrics.remote_schedule_count());

    let mut local = 0;
    for i in 0..metrics.num_workers() {
        local += metrics.worker_local_schedule_count(i);
    }

    assert_eq!(1, local);
    println!("\ttest_spawn_remote PASS");
}

mod unstable {
    use tokio::runtime::RngSeed;

    pub fn test_rng_seed() {
        let seed = b"bytes used to generate seed";
        let rt1 = tokio::runtime::Builder::new_current_thread()
            .rng_seed(RngSeed::from_bytes(seed))
            .build()
            .unwrap();
        let rt1_values = rt1.block_on(async {
            let rand_1 = tokio::macros::support::thread_rng_n(100);
            let rand_2 = tokio::macros::support::thread_rng_n(100);

            (rand_1, rand_2)
        });

        let rt2 = tokio::runtime::Builder::new_current_thread()
            .rng_seed(RngSeed::from_bytes(seed))
            .build()
            .unwrap();
        let rt2_values = rt2.block_on(async {
            let rand_1 = tokio::macros::support::thread_rng_n(100);
            let rand_2 = tokio::macros::support::thread_rng_n(100);

            (rand_1, rand_2)
        });

        assert_eq!(rt1_values, rt2_values);
        println!("\tunstable::test_rng_seed PASS");
    }

    pub fn test_rng_seed_multi_enter() {
        let seed = b"bytes used to generate seed";

        fn two_rand_values() -> (u32, u32) {
            let rand_1 = tokio::macros::support::thread_rng_n(100);
            let rand_2 = tokio::macros::support::thread_rng_n(100);

            (rand_1, rand_2)
        }

        let rt1 = tokio::runtime::Builder::new_current_thread()
            .rng_seed(RngSeed::from_bytes(seed))
            .build()
            .unwrap();
        let rt1_values_1 = rt1.block_on(async { two_rand_values() });
        let rt1_values_2 = rt1.block_on(async { two_rand_values() });

        let rt2 = tokio::runtime::Builder::new_current_thread()
            .rng_seed(RngSeed::from_bytes(seed))
            .build()
            .unwrap();
        let rt2_values_1 = rt2.block_on(async { two_rand_values() });
        let rt2_values_2 = rt2.block_on(async { two_rand_values() });

        assert_eq!(rt1_values_1, rt2_values_1);
        assert_eq!(rt1_values_2, rt2_values_2);
        println!("\tunstable::test_rng_seed_multi_enter PASS");
    }
}

fn rt() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

pub fn run_all_tests() {
    println!("rt_basic tests start...");
    test_spawned_task_does_not_progress_without_block_on();
    test_no_extra_poll();
    test_acquire_mutex_in_drop();
    test_drop_tasks_in_context();
    test_spawn_two();
    test_spawn_remote();
    unstable::test_rng_seed();
    unstable::test_rng_seed_multi_enter();
    println!("rt_basic PASS");
}
