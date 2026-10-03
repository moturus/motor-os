use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;

use gears::cancellation::Cancellation;
use gears::cli::{Action, Args, SessionStart};
use gears::config::{Config, NamedProvider};
use gears::net::EgressPolicy;
#[cfg(unix)]
use gears::net::host_curl::HostCurl as HttpBackend;
#[cfg(not(unix))]
use gears::net::motor_curl::MotorCurl as HttpBackend;
use gears::provider::{
    ApiKey, Endpoint, EventSink, KEY_ENV, Message, OpenAiCompat, Provider, Request, StreamEvent,
};
use gears::provider_choice::ProviderChoice;
use gears::run_lock::DirectoryLock;
use gears::runtime::{ProviderFactory, Runtime};
use gears::session::{Session, Store};
use gears::tools::Registry;

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
    let tools = match Registry::load_config(&config) {
        Ok(tools) => tools,
        Err(error) => {
            diagnostic(&format!("tools: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let directory_lock = match DirectoryLock::acquire_default() {
        Ok(lock) => lock,
        Err(error) => {
            diagnostic(&error);
            return ExitCode::FAILURE;
        }
    };
    match directory_lock.cleanup_temporaries() {
        Ok(0) => {}
        Ok(count) => diagnostic(&format!("removed {count} abandoned state temporary files")),
        Err(error) => {
            diagnostic(&format!("state cleanup: {error}"));
            return ExitCode::FAILURE;
        }
    }
    // SAFETY: startup has not spawned any threads; descendants inherit this
    // owner so nested Gears can verify and use its ancestor's lock.
    unsafe { directory_lock.export_owner() };
    let choice = match ProviderChoice::load_default() {
        Ok(choice) => choice,
        Err(error) => {
            diagnostic(&format!("provider choice: {error}"));
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
        Action::Ask => ask(&args, &config, choice.as_ref(), key_from_env),
        Action::Run => agent(&args, &config, choice.as_ref(), key_from_env, tools),
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

fn agent(
    args: &Args,
    config: &Config,
    choice: Option<&ProviderChoice>,
    key_from_env: Option<String>,
    tools: Registry,
) -> Result<(), String> {
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
    let store = Store::new(&workspace)?;
    let mut session = open_session(&store, args)?;
    let provider_name = args
        .provider
        .clone()
        .or_else(|| session.provider())
        .or_else(|| choice.map(|choice| choice.provider.clone()))
        .unwrap_or_else(|| config.default_provider.clone());
    let selected_provider = config
        .provider(&provider_name)
        .ok_or_else(|| format!("unknown provider {provider_name:?}"))?;
    let key = load_key(&selected_provider, key_from_env.clone())?;
    let provider: Arc<dyn Provider> = Arc::new(connect(
        config,
        &provider_name,
        &selected_provider,
        &key,
        args.verbosity,
    )?);
    if session.provider().as_deref() != Some(&provider_name) {
        session.set_provider(&provider_name)?;
    }
    let model = args
        .model
        .clone()
        .or_else(|| session.model())
        .or_else(|| {
            choice
                .filter(|choice| choice.provider == provider_name)
                .map(|choice| choice.model.clone())
        })
        .or_else(|| config.default_model.clone())
        .or_else(|| selected_provider.model.clone())
        .or_else(|| config.models.first().cloned())
        .ok_or("no model selected; use --model or provider.model in the config")?;
    let mut runtime = Runtime::new_with_registry(provider, store, session, config, model, tools)?;
    let factory_config = config.clone();
    let verbosity = args.verbosity;
    let factory: ProviderFactory = Arc::new(move |name| {
        let selected = factory_config
            .provider(name)
            .ok_or_else(|| format!("unknown provider {name:?}"))?;
        let key = load_key(&selected, key_from_env.clone())?;
        Ok(
            Arc::new(connect(&factory_config, name, &selected, &key, verbosity)?)
                as Arc<dyn Provider>,
        )
    });
    runtime.install_provider_factory(factory);
    let mut provider_names = vec!["default".to_string()];
    provider_names.extend(config.providers.keys().cloned());
    let interactive = !one_shot;
    let result = match selected {
        gears::ui::select::Selected::Line => gears::ui::line::run(
            &mut runtime,
            args.prompt.clone(),
            interactive,
            &config.models,
            &provider_names,
        ),
        gears::ui::select::Selected::Tui => gears::ui::tui::run(
            &mut runtime,
            args.prompt.clone(),
            interactive,
            &config.models,
            &provider_names,
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

fn ask(
    args: &Args,
    config: &Config,
    choice: Option<&ProviderChoice>,
    key_from_env: Option<String>,
) -> Result<(), String> {
    let provider_name = args
        .provider
        .as_deref()
        .or_else(|| choice.map(|choice| choice.provider.as_str()))
        .unwrap_or(&config.default_provider);
    let selected_provider = config
        .provider(provider_name)
        .ok_or_else(|| format!("unknown provider {provider_name:?}"))?;
    let model = args
        .model
        .clone()
        .or_else(|| {
            choice
                .filter(|choice| choice.provider == provider_name)
                .map(|choice| choice.model.clone())
        })
        .or_else(|| config.default_model.clone())
        .or_else(|| selected_provider.model.clone())
        .or_else(|| config.models.first().cloned())
        .ok_or("gears ask needs a model; use --model or provider.model in the config")?;
    let key = load_key(&selected_provider, key_from_env)?;
    let provider = connect(
        config,
        provider_name,
        &selected_provider,
        &key,
        args.verbosity,
    )?;
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
            StreamEvent::Notice(text) => {
                eprintln!("gears: {text}");
                Ok(())
            }
        }
    }
}

fn load_key(provider: &NamedProvider, from_env: Option<String>) -> Result<ApiKey, String> {
    match from_env {
        Some(key) => ApiKey::parse(&key, KEY_ENV),
        // A cloud credential in the default file must not leak in the clear
        // just because base_url changed.
        None if provider.plain_http && provider.key_file.is_none() => Err(format!(
            "plain HTTP cannot use the implicit default key file; \
             set provider.api_key_file or {KEY_ENV} explicitly"
        )),
        None => ApiKey::load(provider.key_file.as_deref()),
    }
}

fn connect(
    config: &Config,
    provider_name: &str,
    provider: &NamedProvider,
    key: &ApiKey,
    verbosity: u8,
) -> Result<OpenAiCompat<HttpBackend>, String> {
    let policy = EgressPolicy::new(&config.egress_allowlist)
        .with_plain_http_allowlist(&config.plain_http_allowlist);
    let http = HttpBackend::new(policy)
        .map_err(|error| error.to_string())?
        .with_verbosity(verbosity)
        .with_secret(KEY_ENV, key.expose());
    let http = match provider.ca_cert.as_deref() {
        Some(path) => http.with_ca_cert(path).map_err(|error| error.to_string())?,
        None => http,
    };
    let endpoint = Endpoint::new(&provider.base_url)
        .map_err(|error| error.to_string())?
        .with_reasoning_echo(provider.reasoning_echo);
    Ok(OpenAiCompat::new(http, endpoint).with_cache_identity(provider_name))
}

fn diagnostic(message: &str) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "gears: {message}");
    let _ = stderr.flush();
}
