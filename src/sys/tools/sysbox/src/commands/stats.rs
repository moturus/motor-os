use moto_stats::{Collector, SCOPE_GLOBAL};

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("Query Motor OS system statistics (federated across the kernel and");
    eprintln!("userspace service providers, discovered dynamically).");
    eprintln!("usage:");
    eprintln!("\tsysbox stats list");
    eprintln!("\t\tDescribe every available stat: provider id, metric id, and names.");
    eprintln!("\tsysbox stats providers");
    eprintln!("\t\tList registered providers (id, name, transport).");
    eprintln!("\tsysbox stats get <provider_id>:<metric_id>[:<scope_id>]");
    eprintln!("\t\tRead one value. <scope_id> is a PID (default: 0, the aggregate).");
    eprintln!("\t\tExample: 'sysbox stats get 1:0' reads kernel metric 0 at scope 0.");
    std::thread::sleep(std::time::Duration::from_millis(10));
    std::process::exit(exit_code);
}

pub fn do_command(args: &[String]) {
    // args[0] == "stats".
    if args.len() < 2 {
        print_usage_and_exit(1);
    }

    match args[1].as_str() {
        "list" => do_list(&args[2..]),
        "providers" => do_providers(&args[2..]),
        "get" => do_get(&args[2..]),
        "--help" | "help" => print_usage_and_exit(0),
        _ => print_usage_and_exit(1),
    }
}

fn do_providers(args: &[String]) {
    if !args.is_empty() {
        print_usage_and_exit(1);
    }

    println!("{:>11} {:<20} TRANSPORT", "PROVIDER_ID", "NAME");
    for p in Collector::providers() {
        let transport = if p.url.is_empty() {
            "<syscall>"
        } else {
            &p.url
        };
        println!("{:>11} {:<20} {}", p.id, p.name, transport);
    }
}

/// Describe every stat (does not read values): provider id, metric id, names.
fn do_list(args: &[String]) {
    if !args.is_empty() {
        print_usage_and_exit(1);
    }

    println!(
        "{:>11} {:>9} {:<10} METRIC",
        "PROVIDER_ID", "METRIC_ID", "PROVIDER"
    );

    for provider in Collector::providers() {
        match Collector::describe(&provider) {
            Ok(metrics) => {
                for m in &metrics {
                    println!(
                        "{:>11} {:>9} {:<10} {}",
                        provider.id, m.id, provider.name, m.name
                    );
                }
            }
            Err(err) => {
                println!(
                    "{:>11} {:>9} {:<10} <unavailable: {err:?}>",
                    provider.id, "-", provider.name
                );
            }
        }
    }
}

/// Read one value, addressed by `<provider_id>:<metric_id>[:<scope_id>]`.
fn do_get(args: &[String]) {
    if args.len() != 1 {
        print_usage_and_exit(1);
    }

    let spec = &args[0];
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() < 2 || parts.len() > 3 {
        eprintln!("stats get: expected <provider_id>:<metric_id>[:<scope_id>], got '{spec}'");
        std::process::exit(1);
    }

    let provider_id = parse_field::<u64>(parts[0], "provider_id");
    let metric_id = parse_field::<u32>(parts[1], "metric_id");
    let scope = if parts.len() == 3 {
        parse_field::<u64>(parts[2], "scope_id")
    } else {
        SCOPE_GLOBAL
    };

    let Some(provider) = Collector::providers()
        .into_iter()
        .find(|p| p.id == provider_id)
    else {
        eprintln!("stats get: unknown provider id {provider_id}");
        std::process::exit(1);
    };

    match Collector::read(&provider, metric_id, scope) {
        Ok(value) => println!("{value}"),
        Err(err) => {
            eprintln!("stats get: {provider_id}:{metric_id}:{scope}: {err:?}");
            std::process::exit(1);
        }
    }
}

fn parse_field<T: std::str::FromStr>(s: &str, what: &str) -> T {
    s.parse::<T>().unwrap_or_else(|_| {
        eprintln!("stats get: invalid {what} '{s}'");
        std::process::exit(1);
    })
}
