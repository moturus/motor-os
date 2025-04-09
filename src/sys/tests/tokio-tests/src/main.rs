// mod process_arg0;
mod rt_basic;
mod rt_common;
mod rt_handle;

pub mod support {
    pub mod mpsc_stream;
}

// Intercept Ctrl+C ourselves if the OS does not do it for us.
fn input_listener() {
    use std::io::Read;

    loop {
        let mut input = [0_u8; 16];
        let sz = std::io::stdin().read(&mut input).unwrap();
        for b in &input[0..sz] {
            if *b == 3 {
                println!("\ncaught ^C: exiting.");
                std::process::exit(0);
            }
        }
    }
}

fn main() {
    std::thread::spawn(input_listener);

    // process_arg0::arg0().await;

    rt_basic::run_all_tests();
    rt_common::run_all_tests();
    rt_handle::run_all_tests();

    println!("tokio-tests PASS");
}
