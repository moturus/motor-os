use russhd::client::args::select_applet;

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let program = args.first().cloned().unwrap_or_else(|| "ssh".to_owned());
    let applet = match select_applet(&mut args) {
        Ok(applet) => applet,
        Err(error) => {
            eprintln!("{program}: {error}");
            std::process::exit(255);
        }
    };
    match russhd::applets::run(applet, &args[1..]) {
        Ok(status) => std::process::exit(status),
        Err(error) => {
            eprintln!("{}: {error}", applet.name());
            std::process::exit(applet.error_status());
        }
    }
}
