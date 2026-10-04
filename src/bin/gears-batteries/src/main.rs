use std::io::Write;

fn main() {
    if let Err(error) = run() {
        eprintln!("gears-batteries: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [role] if role == "hook" => {
            let event = gears_batteries::read_event(std::io::stdin().lock())?;
            let response = gears_batteries::hook(event)?;
            let mut stdout = std::io::stdout().lock();
            serde_json::to_writer(&mut stdout, &response).map_err(|error| error.to_string())?;
            stdout.write_all(b"\n").map_err(|error| error.to_string())
        }
        [flag] if flag == "--help" || flag == "-h" => {
            println!("usage: gears-batteries hook\nOptional workflows for Gears.");
            Ok(())
        }
        _ => Err("usage: gears-batteries hook".into()),
    }
}
