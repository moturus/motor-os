#[test]
#[cfg(target_os = "motor")]
fn installed_javy_and_wasmi() {
    javy_smoke::native::run().unwrap();
}
