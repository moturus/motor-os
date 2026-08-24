mod process;
mod rt_basic;
mod rt_common;
mod rt_handle;

pub mod support {
    pub mod mpsc_stream;
}

// Diagnostic mode (tokio wedge round 2): repeatedly create, use, and drop a
// multi_thread runtime -- test_sleep_from_blocking's cycle with nothing else
// in the process. Records: docs/plans/networking-step-by-step.md (git
// history), Step 13.
fn rt_churn(iters: u64) -> ! {
    for i in 0..iters {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            tokio::task::spawn_blocking(|| std::thread::sleep(std::time::Duration::from_millis(1)))
                .await
                .unwrap();
        });
        drop(rt);
        if i % 100 == 0 {
            // The liveness beat a host watchdog keys on.
            println!("churn i={i}");
        }
    }
    println!("churn done");
    std::process::exit(0);
}

fn main() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("rt-churn") {
        let iters = args.next().and_then(|s| s.parse().ok()).unwrap_or(1 << 30);
        rt_churn(iters);
    }

    process::run_all_tests();
    rt_basic::run_all_tests();
    rt_common::run_all_tests();
    rt_handle::run_all_tests();

    println!("tokio-tests PASS");
    std::thread::sleep(std::time::Duration::from_millis(20));
}
