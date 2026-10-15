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
        [role, name] if role == "tool" => {
            let context = gears::batteries::paths::ToolContext::from_env()?;
            let response = gears::batteries::tool::run(name, std::io::stdin().lock(), &context)?;
            serde_json::to_writer(std::io::stdout().lock(), &response)
                .map_err(|error| error.to_string())?;
            println!();
            Ok(())
        }
        [role, flag] if role == "eval" && matches!(flag.as_str(), "--help" | "-h") => {
            println!("{}", gears::batteries::eval_options::USAGE);
            Ok(())
        }
        [role, ..] if role == "eval" => {
            gears::batteries::eval_cli::run(&args, std::io::stdout().lock())
        }
        [role] if role == "review" => {
            let completed = gears::batteries::review_runner::from_env()?;
            if completed != 0 {
                println!("Completed {completed} review(s).");
            }
            Ok(())
        }
        [role] if role == "hook" => {
            let event = gears::batteries::read_event(std::io::stdin().lock())?;
            let response = gears::batteries::hook(event)?;
            let mut stdout = std::io::stdout().lock();
            serde_json::to_writer(&mut stdout, &response).map_err(|error| error.to_string())?;
            stdout.write_all(b"\n").map_err(|error| error.to_string())
        }
        [role, ..] if matches!(role.as_str(), "pending" | "history" | "status" | "cleanup") => {
            gears::batteries::memory_cli::run(
                &args,
                std::io::stdin().lock(),
                std::io::stdout().lock(),
            )
        }
        [flag] if flag == "--help" || flag == "-h" => {
            println!(
                "{}\n{}",
                gears::batteries::memory_options::USAGE,
                gears::batteries::eval_options::USAGE
            );
            Ok(())
        }
        _ => Err(gears::batteries::memory_options::USAGE.into()),
    }
}
