fn main() {
    let mut args = std::env::args_os().skip(1);
    let path = args.next();
    let Some(path) = path.filter(|_| args.next().is_none()) else {
        eprintln!("usage: wg <config.toml>");
        std::process::exit(1);
    };
    match wg::config::Config::load(std::path::Path::new(&path)) {
        Ok(config) => println!(
            "{}: configuration valid ({} peers)",
            config.name,
            config.peers.len()
        ),
        Err(error) => {
            eprintln!("wg: {error}");
            std::process::exit(1);
        }
    }
}
