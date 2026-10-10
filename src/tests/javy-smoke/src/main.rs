#[cfg(target_os = "motor")]
mod native;

#[cfg(target_os = "motor")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Repeat-for-identical-bytes and Linux identity checks depend on neither
    // image nor memory, so test-wasm.sh asks for them on its first VM only.
    let mut once = native::Once::default();
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--determinism" => once.determinism = true,
            "--linux-identity" => once.linux_identity = true,
            _ => {
                return Err(format!(
                    "usage: javy-smoke [--determinism] [--linux-identity], not {arg:?}"
                )
                .into());
            }
        }
    }
    native::run(once)
}

#[cfg(not(target_os = "motor"))]
fn main() {
    eprintln!("javy-smoke runs on Motor OS against installed Javy/Wasmi tools");
    std::process::exit(2);
}
