use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;

use gears::cancellation::Cancellation;
use gears::cli::{Action, Args, SessionStart};
use gears::config::Config;
use gears::net::EgressPolicy;
#[cfg(unix)]
use gears::net::host_curl::HostCurl as HttpBackend;
#[cfg(not(unix))]
use gears::net::motor_curl::MotorCurl as HttpBackend;
use gears::provider::{
    ApiKey, Endpoint, EventSink, KEY_ENV, Message, OpenAiCompat, Provider, Request, StreamEvent,
};
use gears::runtime::Runtime;
use gears::session::{Session, Store};

fn main() -> ExitCode {
    let key_from_env = std::env::var(KEY_ENV).ok();
    if key_from_env.is_some() {
        // SAFETY: process startup is still single-threaded.
        unsafe { std::env::remove_var(KEY_ENV) };
    }
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let args = match Args::parse(&arguments) {
        Ok(args) => args,
        Err(error) => {
            diagnostic(&error);
            eprintln!("Try gears --help.");
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
        Action::Run | Action::Ask => run(args, key_from_env),
    }
}

fn run(args: Args, key_from_env: Option<String>) -> ExitCode {
    let config = match Config::load_user(args.config.as_deref()) {
        Ok(config) => config,
        Err(error) => {
            diagnostic(&format!("config: {error}"));
            return ExitCode::FAILURE;
        }
    };
    if let Some(path) = args.log_file.as_deref().or(config.log_file.as_deref()) {
        match gears::trace::Tracer::to_file(path, config.log_level) {
            Ok(tracer) => gears::trace::init(tracer),
            Err(error) => {
                diagnostic(&format!("cannot open log file {}: {error}", path.display()));
                return ExitCode::FAILURE;
            }
        }
    }
    gears::trace::log(
        gears::trace::Level::Info,
        concat!("gears ", env!("CARGO_PKG_VERSION"), " starting"),
    );
    if !gears::platform::install_interrupt_handler() {
        gears::trace::log(
            gears::trace::Level::Warn,
            "could not install the interrupt handler",
        );
    }
    let result = match args.action {
        Action::Ask => ask(&args, &config, key_from_env),
        Action::Run => agent(&args, &config, key_from_env),
        Action::Version | Action::Help => unreachable!(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            diagnostic(&gears::trace::scrub(&error));
            gears::trace::log(gears::trace::Level::Error, &error);
            ExitCode::FAILURE
        }
    }
}

fn agent(args: &Args, config: &Config, key_from_env: Option<String>) -> Result<(), String> {
    let workspace = args.workspace.clone().map_or_else(
        || std::env::current_dir().map_err(|error| format!("current directory: {error}")),
        Ok,
    )?;
    let one_shot = args.prompt.is_some();
    let selected = gears::ui::select::choose(args.ui, one_shot, || {
        (
            std::io::stdin().is_terminal(),
            std::io::stdout().is_terminal(),
        )
    })?;
    let key = load_key(config, key_from_env)?;
    let provider: Arc<dyn Provider> = Arc::new(connect(config, &key, args.verbosity)?);
    let store = Store::new(&workspace)?;
    let session = open_session(&store, args)?;
    let model = args
        .model
        .clone()
        .or_else(|| session.model())
        .or_else(|| config.model.clone())
        .or_else(|| config.models.first().cloned())
        .ok_or("no model selected; use --model or provider.model in the config")?;
    let mut runtime = Runtime::new(provider, store, session, config, model)?;
    let interactive = !one_shot;
    let result = match selected {
        gears::ui::select::Selected::Line => gears::ui::line::run(
            &mut runtime,
            args.prompt.clone(),
            interactive,
            &config.models,
        ),
        gears::ui::select::Selected::Tui => gears::ui::tui::run(
            &mut runtime,
            args.prompt.clone(),
            interactive,
            &config.models,
        ),
    };
    for notice in runtime.close() {
        diagnostic(&notice);
    }
    result
}

fn open_session(store: &Store, args: &Args) -> Result<Session, String> {
    match &args.session {
        SessionStart::New => store.create(false, args.name.as_deref()),
        SessionStart::Ephemeral => store.create(true, args.name.as_deref()),
        SessionStart::Continue => store.continue_recent(),
        SessionStart::Resume(selector) => store.open(selector),
        SessionStart::Fork(selector) => {
            let source = store.open(selector)?;
            store.clone_active(&source)
        }
    }
}

fn ask(args: &Args, config: &Config, key_from_env: Option<String>) -> Result<(), String> {
    let model = args
        .model
        .clone()
        .or_else(|| config.model.clone())
        .or_else(|| config.models.first().cloned())
        .ok_or("gears ask needs a model; use --model or provider.model in the config")?;
    let key = load_key(config, key_from_env)?;
    let provider = connect(config, &key, args.verbosity)?;
    let request = Request::new(
        model,
        vec![Message::user(
            args.prompt.as_deref().expect("ask was validated"),
        )],
    )
    .with_cancellation(Cancellation::new());
    let mut sink = AskSink;
    provider
        .complete(&request, &mut sink)
        .map_err(|error| error.to_string())?;
    println!();
    Ok(())
}

struct AskSink;

impl EventSink for AskSink {
    fn on_event(&mut self, event: StreamEvent) -> std::io::Result<()> {
        match event {
            StreamEvent::Text(text) => {
                print!("{text}");
                std::io::stdout().flush()
            }
            StreamEvent::Reasoning(text) => {
                eprint!("{text}");
                std::io::stderr().flush()
            }
        }
    }
}

fn load_key(config: &Config, from_env: Option<String>) -> Result<ApiKey, String> {
    match from_env {
        Some(key) => ApiKey::parse(&key, KEY_ENV),
        None => ApiKey::load(config.key_file.as_deref()),
    }
}

fn connect(
    config: &Config,
    key: &ApiKey,
    verbosity: u8,
) -> Result<OpenAiCompat<HttpBackend>, String> {
    let mut policy = EgressPolicy::new(&config.egress_allowlist);
    if config.allow_plain_http_loopback {
        policy = policy.allow_loopback_http_for_tests();
    }
    let http = HttpBackend::new(policy)
        .map_err(|error| error.to_string())?
        .with_verbosity(verbosity)
        .with_secret(KEY_ENV, key.expose());
    let http = match config.ca_cert.as_deref() {
        Some(path) => http.with_ca_cert(path).map_err(|error| error.to_string())?,
        None => http,
    };
    let endpoint = Endpoint::new(&config.base_url).map_err(|error| error.to_string())?;
    Ok(OpenAiCompat::new(http, endpoint))
}

fn diagnostic(message: &str) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "gears: {message}");
    let _ = stderr.flush();
}
