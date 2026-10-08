#[cfg(target_os = "motor")]
mod native;

#[cfg(target_os = "motor")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    native::run()
}

#[cfg(not(target_os = "motor"))]
fn main() {
    eprintln!("wasmtime-smoke runs on Motor OS against the installed wasmtime-rt");
    std::process::exit(2);
}
