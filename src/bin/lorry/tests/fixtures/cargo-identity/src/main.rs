fn main() {
    println!("lorry cargo identity fixture");
}

#[test]
fn package_environment_is_set() {
    assert_eq!(env!("CARGO_PKG_NAME"), "lorry_identity");
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");
}
