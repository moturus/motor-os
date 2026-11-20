#[test]
#[cfg(target_os = "motor")]
fn installed_wasmtime() {
    wasmtime_smoke::native::run_native().unwrap();
}
