//! Most of the tests/files here are copied from mio/src/tests,
//! as cross-compiling and runnings tests is not very easy yet.

use std::time::Duration;
mod close_on_drop;
mod simple;
mod tcp;
mod tcp_listener;
mod tcp_stream;

#[macro_use]
mod util;

fn input_listener() {
    use std::io::Read;

    loop {
        let mut input = [0_u8; 16];
        let sz = std::io::stdin().read(&mut input).unwrap();
        for b in &input[0..sz] {
            if *b == 3 {
                println!("Caught ^C: exiting.");
                std::process::exit(1);
            }
        }
    }
}

fn main() {
    std::thread::Builder::new()
        .name("input_listener".to_string())
        .spawn(input_listener)
        .unwrap();

    tcp_stream::run_all_tests();
    tcp_listener::run_all_tests();
    tcp::run_all_tests();
    simple::test();
    close_on_drop::test_close_on_drop();

    std::thread::sleep(Duration::from_millis(10));
    println!("\nmio-test: ALL PASS\n");
    std::thread::sleep(Duration::from_millis(10));
}
