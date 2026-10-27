#[cfg(target_os = "motor")]
fn main() {
    if let Err(error) = wg::motor_tool::execute(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("wg-tool: {}", error.message);
        std::process::exit(error.code);
    }
}

#[cfg(not(target_os = "motor"))]
fn main() {
    eprintln!("wg-tool requires Motor OS");
    std::process::exit(1);
}
