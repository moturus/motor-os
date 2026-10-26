#[cfg(target_os = "motor")]
fn main() {
    wg::motor::native_tests::transport_invalidation(&std::env::args().nth(1).unwrap());
}

#[cfg(not(target_os = "motor"))]
fn main() {
    panic!("wg-self-test runs inside Motor OS");
}
