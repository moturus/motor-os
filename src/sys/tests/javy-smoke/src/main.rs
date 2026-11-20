#[cfg(target_os = "motor")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => javy_smoke::native::run(),
        [arg] if arg == "--linux-identity" => javy_smoke::native::compare_host_output(),
        _ => Err("usage: javy-smoke [--linux-identity]".into()),
    }
}
#[cfg(not(target_os = "motor"))]
fn main() {
    panic!("javy-smoke runs on Motor OS");
}
