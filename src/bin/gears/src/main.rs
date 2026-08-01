use std::io::Write;
use std::process::ExitCode;

use gears::cli::{Action, Args};
use gears::config::Config;
use gears::net::{EgressPolicy, host_curl::HostCurl};
use gears::provider::{
    ApiKey, ChatMessage, ChatRequest, Endpoint, EventSink, KEY_ENV, ModelProvider, OpenAiCompat,
    UsageMeter,
};

fn main() -> ExitCode {
    // Before anything else, and while this process is still single-threaded:
    // a key in gears' own environment would be inherited by every tool it
    // later spawns, so it is taken out and passed to the transport by hand.
    let key_from_env = std::env::var(KEY_ENV).ok();
    if key_from_env.is_some() {
        // SAFETY: no other thread exists yet, so nothing can be reading the
        // environment concurrently.
        unsafe { std::env::remove_var(KEY_ENV) };
    }

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match Args::parse(&argv) {
        Ok(args) => args,
        Err(msg) => {
            eprintln!("gears: {msg}");
            eprintln!("Try 'gears --help'.");
            return ExitCode::from(2);
        }
    };

    match args.action {
        Action::Version => {
            println!("gears {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Action::Help => {
            print!("{}", gears::cli::USAGE);
            ExitCode::SUCCESS
        }
        Action::Run | Action::Ask => run(&args, key_from_env),
    }
}

fn run(args: &Args, key_from_env: Option<String>) -> ExitCode {
    let config = match Config::load(args.config.as_deref()) {
        Ok(config) => config,
        Err(msg) => {
            eprintln!("gears: config: {msg}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(path) = args.log_file.as_deref().or(config.log_file.as_deref()) {
        match gears::trace::Tracer::to_file(path, config.log_level) {
            Ok(tracer) => gears::trace::init(tracer),
            Err(e) => {
                eprintln!("gears: cannot open log file {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        }
        gears::trace::log(
            gears::trace::Level::Info,
            concat!("gears ", env!("CARGO_PKG_VERSION"), " starting"),
        );
    }

    if !gears::platform::install_interrupt_handler() {
        gears::trace::log(
            gears::trace::Level::Warn,
            "could not install the interrupt handler",
        );
    }

    if args.action == Action::Ask {
        return match ask(args, &config, key_from_env) {
            Ok(()) => ExitCode::SUCCESS,
            Err(msg) => {
                // Scrubbed: an endpoint that quotes the key back in its error
                // message must not get it onto the terminal.
                eprintln!("gears: {}", gears::trace::scrub(&msg));
                gears::trace::log(gears::trace::Level::Error, &msg);
                ExitCode::FAILURE
            }
        };
    }

    // The agent loop arrives in step 4 of the plan.
    eprintln!("gears: the interactive agent is not implemented yet");
    ExitCode::FAILURE
}

/// One prompt, one answer: the manual spot check for an endpoint, a key and a
/// model. Never part of `cargo test` against a real provider.
fn ask(args: &Args, config: &Config, key_from_env: Option<String>) -> Result<(), String> {
    let prompt = args.prompt.as_deref().expect("ask parsed a prompt");
    let model = args
        .model
        .clone()
        .or_else(|| config.model.clone())
        .ok_or("no model: pass -m MODEL or set provider.model in the config")?;
    let key = match key_from_env {
        Some(text) => ApiKey::parse(&text, KEY_ENV)?,
        None => ApiKey::load(config.key_file.as_deref())?,
    };

    let mut policy = EgressPolicy::new(&config.egress_allowlist);
    if config.allow_plain_http_loopback {
        policy = policy.allow_loopback_http_for_tests();
    }
    let http = HostCurl::new(policy)
        .map_err(|e| e.to_string())?
        .with_secret(KEY_ENV, key.expose());
    let endpoint = Endpoint::new(&config.base_url).map_err(|e| e.to_string())?;
    let provider = OpenAiCompat::new(http, endpoint);

    let request = ChatRequest::new(model, vec![ChatMessage::user(prompt)]);
    let mut printer = Printer::default();
    let completion = provider
        .complete(&request, &mut printer)
        .map_err(|e| e.to_string())?;

    if !printer.wrote_line {
        println!();
    }
    let mut meter = UsageMeter::new();
    meter.add(&completion.usage);
    eprintln!("gears: {}", meter.summary());
    Ok(())
}

/// Prints the answer as it streams. Reasoning goes to stderr so that stdout
/// is only ever the answer, and a `^C` between deltas ends the turn.
#[derive(Default)]
struct Printer {
    wrote_line: bool,
}

impl Printer {
    fn write(&mut self, text: &str, to_stdout: bool) -> std::io::Result<()> {
        if gears::platform::take_interrupt() {
            return Err(std::io::Error::other("interrupted"));
        }
        if to_stdout {
            self.wrote_line = text.ends_with('\n');
            print!("{text}");
            std::io::stdout().flush()?;
        } else {
            eprint!("{text}");
        }
        Ok(())
    }
}

impl EventSink for Printer {
    fn on_content(&mut self, text: &str) -> std::io::Result<()> {
        self.write(text, true)
    }

    fn on_reasoning(&mut self, text: &str) -> std::io::Result<()> {
        self.write(text, false)
    }
}
