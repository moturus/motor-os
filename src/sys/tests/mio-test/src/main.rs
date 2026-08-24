//! Most of the tests/files here are copied from mio/src/tests,
//! as cross-compiling and runnings tests is not very easy yet.

use std::time::Duration;
mod close_on_drop;
mod poll;
mod simple;
mod tcp;
mod tcp_listener;
mod tcp_stream;
mod udp_socket;
mod waker;

#[macro_use]
mod util;

fn main() {
    env_logger::init();

    simple::test();
    poll::run_all_tests();
    waker::run_all_tests();
    tcp_stream::run_all_tests();
    tcp_listener::run_all_tests();
    tcp::run_all_tests();
    udp_socket::run_all_tests();
    close_on_drop::test_close_on_drop();

    std::thread::sleep(Duration::from_millis(100));
    moto_rt::internal_helper(0, 0, 0, 0, 0, 0); // Check the internal net state has been cleared.
    println!("\nmio-test: ALL PASS\n");
    std::thread::sleep(Duration::from_millis(10));
}
