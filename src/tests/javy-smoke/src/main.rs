#[cfg(target_os = "motor")]
mod native;

#[cfg(target_os = "motor")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The Linux identity checks run once per full-test-dev.sh, not on every boot.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let linux_identity = match args.as_slice() {
        [] => false,
        [flag] if flag == "--linux-identity" => true,
        _ => return Err(format!("usage: javy-smoke [--linux-identity], not {args:?}").into()),
    };
    native::run(linux_identity)
}

#[cfg(not(target_os = "motor"))]
fn main() {
    eprintln!("javy-smoke runs on Motor OS against installed Javy/Wasmi tools");
    std::process::exit(2);
}
