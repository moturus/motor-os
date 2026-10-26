fn main() {
    let mut args = std::env::args_os().skip(1);
    let path = args.next();
    let Some(path) = path.filter(|_| args.next().is_none()) else {
        eprintln!("usage: wg <config.toml>");
        std::process::exit(1);
    };
    if let Err(error) = wg::config::Config::load(std::path::Path::new(&path)).and_then(start) {
        eprintln!("wg: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "motor")]
fn start(config: wg::config::Config) -> wg::config::Result<()> {
    wg::motor::run(&config)
}

#[cfg(not(target_os = "motor"))]
fn start(config: wg::config::Config) -> wg::config::Result<()> {
    println!(
        "{}: configuration valid ({} peers)",
        config.name,
        config.peers.len()
    );
    Ok(())
}
