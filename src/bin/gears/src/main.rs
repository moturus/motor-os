use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use gears::agent::gate::Gate;
use gears::agent::harness::{Harness, Setup};
use gears::cli::{Action, Args};
use gears::config::Config;
use gears::net::{EgressPolicy, host_curl::HostCurl};
use gears::provider::{
    ApiKey, ChatMessage, ChatRequest, Endpoint, EventSink, KEY_ENV, ModelProvider, OpenAiCompat,
    UsageMeter,
};
use gears::ui::terminal::{self, Terminal};

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

    let outcome = match args.action {
        Action::Ask => ask(args, &config, key_from_env).map(|()| ExitCode::SUCCESS),
        _ => agent(args, &config, key_from_env),
    };
    match outcome {
        Ok(code) => code,
        Err(msg) => {
            // Scrubbed: an endpoint that quotes the key back in its error
            // message must not get it onto the terminal.
            eprintln!("gears: {}", gears::trace::scrub(&msg));
            gears::trace::log(gears::trace::Level::Error, &msg);
            ExitCode::FAILURE
        }
    }
}

/// The agent: a workspace, a session, and either one prompt or a terminal
/// full of them.
fn agent(args: &Args, config: &Config, key_from_env: Option<String>) -> Result<ExitCode, String> {
    let workspace = match &args.workspace {
        Some(dir) => dir.clone(),
        None => std::env::current_dir().map_err(|e| format!("no working directory: {e}"))?,
    };
    let key = load_key(config, key_from_env)?;

    let mut setup = Setup::new(workspace.clone());
    setup.model = args.model.clone().or_else(|| config.model.clone());
    setup.resume = args.resume.clone();
    setup.run_timeout = config.run_timeout;
    setup.build_timeout = config.build_timeout;
    setup.tools = vec![fetcher(config)?];
    // The agent must not be able to read its own credentials, wherever they
    // happen to live.
    setup.deny = [config.key_file.clone(), ApiKey::default_path()]
        .into_iter()
        .flatten()
        .collect::<Vec<PathBuf>>();

    let provider = Box::new(connect(config, &key)?);
    let harness = Harness::start(setup, provider)?;

    let gate = Gate::load(harness.workspace(), config.permissions)?;
    let stdin = std::io::stdin();
    let mut ui = Terminal::new(
        std::io::stdout(),
        stdin.lock(),
        gate,
        // A one-shot run has nobody at the keyboard to answer a permission
        // question: it is scripted, or it is a pipe.
        args.prompt.is_none(),
    );
    Ok(match &args.prompt {
        Some(prompt) => terminal::once(&harness, &mut ui, prompt),
        None => terminal::interact(&harness, &mut ui),
    })
}

fn load_key(config: &Config, key_from_env: Option<String>) -> Result<ApiKey, String> {
    match key_from_env {
        Some(text) => ApiKey::parse(&text, KEY_ENV),
        None => ApiKey::load(config.key_file.as_deref()),
    }
}

fn egress(config: &Config) -> EgressPolicy {
    let policy = EgressPolicy::new(&config.egress_allowlist);
    match config.allow_plain_http_loopback {
        true => policy.allow_loopback_http_for_tests(),
        false => policy,
    }
}

fn connect(config: &Config, key: &ApiKey) -> Result<OpenAiCompat<HostCurl>, String> {
    let http = HostCurl::new(egress(config))
        .map_err(|e| e.to_string())?
        .with_secret(KEY_ENV, key.expose());
    let endpoint = Endpoint::new(&config.base_url).map_err(|e| e.to_string())?;
    Ok(OpenAiCompat::new(http, endpoint))
}

/// The `fetch` tool's own transport: its own policy, so a host the user allows
/// for a fetch does not widen what the provider connection may reach, and no
/// API key, so there is nothing for a fetched host to be told.
fn fetcher(config: &Config) -> Result<Box<dyn gears::tools::Tool>, String> {
    let policy = egress(config);
    let client = HostCurl::new(policy.clone()).map_err(|e| e.to_string())?;
    Ok(gears::tools::fetch::tool(Box::new(client), policy))
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
    let key = load_key(config, key_from_env)?;
    let provider = connect(config, &key)?;

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
