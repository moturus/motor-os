fn main() {
    println!("lorry cargo identity helper");
}

#[test]
fn binary_environment_is_set() {
    assert_eq!(env!("CARGO_BIN_NAME"), "helper");
}
