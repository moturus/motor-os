use moto_stats::{Collector, ProviderInfo, SCOPE_GLOBAL};

fn print_usage_and_exit(exit_code: i32) -> ! {
    eprintln!("Query Motor OS system statistics (federated across the kernel and");
    eprintln!("userspace service providers, discovered dynamically).");
    eprintln!("usage:");
    eprintln!("\tsysbox stats list");
    eprintln!("\t\tDescribe every available stat: provider id, metric id, and names.");
    eprintln!("\tsysbox stats providers");
    eprintln!("\t\tList registered providers (id, name, transport).");
    eprintln!("\tsysbox stats get <provider_id>[:<metric_id>][:<scope_id>]");
    eprintln!("\t\tRead metric values. <scope_id> is a PID (default: 0, the aggregate).");
    eprintln!("\t\tWith <metric_id>, read one value (bare, script-friendly):");
    eprintln!("\t\t  'stats get 1:0'    reads kernel metric 0 at scope 0.");
    eprintln!("\t\t  'stats get 1:0:2'  reads kernel metric 0 at scope (PID) 2.");
    eprintln!("\t\tOmit <metric_id> to read every metric the provider exposes:");
    eprintln!("\t\t  'stats get 2'      reads all of provider 2's metrics (scope 0).");
    eprintln!("\t\t  'stats get 1::2'   reads all of provider 1's metrics at scope 2.");
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

/// Read metric values, addressed by `<provider_id>[:<metric_id>][:<scope_id>]`.
///
/// With a `<metric_id>`, read that one value (printed bare, for scripting). An
/// empty or omitted `<metric_id>` reads every metric the provider exposes at the
/// scope: `stats get 2` (all of provider 2, scope 0) or `stats get 1::2` (all of
/// provider 1 at scope 2).
fn do_get(args: &[String]) {
    if args.len() != 1 {
        print_usage_and_exit(1);
    }

    let spec = &args[0];
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() > 3 {
        eprintln!("stats get: expected <provider_id>[:<metric_id>][:<scope_id>], got '{spec}'");
        std::process::exit(1);
    }

    let provider_id = parse_field::<u64>(parts[0], "provider_id");

    // An empty or omitted metric id means "every metric this provider exposes".
    let metric = match parts.get(1) {
        Some(s) if !s.is_empty() => Some(parse_field::<u32>(s, "metric_id")),
        _ => None,
    };

    // An empty or omitted scope id defaults to the provider-wide aggregate.
    let scope = match parts.get(2) {
        Some(s) if !s.is_empty() => parse_field::<u64>(s, "scope_id"),
        _ => SCOPE_GLOBAL,
    };

    let Some(provider) = Collector::providers()
        .into_iter()
        .find(|p| p.id == provider_id)
    else {
        eprintln!("stats get: unknown provider id {provider_id}");
        std::process::exit(1);
    };

    match metric {
        Some(metric) => get_one(&provider, metric, scope),
        None => get_all(&provider, scope),
    }
}

/// Read and print a single metric value (bare, for scripting).
fn get_one(provider: &ProviderInfo, metric: u32, scope: u64) {
    match Collector::read(provider, metric, scope) {
        Ok(value) => println!("{value}"),
        Err(err) => {
            eprintln!("stats get: {}:{metric}:{scope}: {err:?}", provider.id);
            std::process::exit(1);
        }
    }
}

/// Read and print every metric a provider exposes at `scope`.
fn get_all(provider: &ProviderInfo, scope: u64) {
    let entries = match Collector::query_scoped(provider, scope) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("stats get: {}::{scope}: {err:?}", provider.id);
            std::process::exit(1);
        }
    };

    // Names come from the provider's own catalog (best effort: a missing
    // descriptor just leaves the metric unnamed).
    let descs = Collector::describe(provider).unwrap_or_default();

    println!("{:>9} {:<24} VALUE", "METRIC_ID", "METRIC");
    for e in &entries {
        // IPC providers ignore `scope` and report only their global metrics;
        // keep just the entries actually at the requested scope.
        if e.scope != scope {
            continue;
        }
        let name = descs
            .iter()
            .find(|d| d.id == e.metric)
            .map(|d| d.name.as_str())
            .unwrap_or("?");
        println!("{:>9} {:<24} {}", e.metric, name, e.value);
    }
}

fn parse_field<T: std::str::FromStr>(s: &str, what: &str) -> T {
    s.parse::<T>().unwrap_or_else(|_| {
        eprintln!("stats get: invalid {what} '{s}'");
        std::process::exit(1);
    })
}
