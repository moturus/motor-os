#[cfg(target_os = "motor")]
mod native;

#[cfg(target_os = "motor")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    native::run()
}

#[cfg(not(target_os = "motor"))]
fn main() {
    eprintln!("javy-smoke runs on Motor OS against installed Javy/Wasmi tools");
    std::process::exit(2);
}
