#[cfg(target_os = "motor")]
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if wg::tool_protocol_tests::child(&args) {
        return;
    }
    let mode = &args[0];
    if mode == "tool" {
        wg::tool_tests::run();
        wg::tool_protocol_tests::run();
    } else if mode == "system" {
        wg::tool_protocol_tests::system();
    } else {
        wg::motor::native_tests::transport_invalidation(mode);
    }
}

#[cfg(not(target_os = "motor"))]
fn main() {
    panic!("wg-self-test runs inside Motor OS");
}
