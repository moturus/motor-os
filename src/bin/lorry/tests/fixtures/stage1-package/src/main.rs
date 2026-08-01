fn main() {
    println!("stage1 fixture");
}

#[test]
fn package_environment_is_set() {
    assert_eq!(env!("CARGO_PKG_NAME"), "red");
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.1.0");
}
