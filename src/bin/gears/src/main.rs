use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;

use gears::cancellation::Cancellation;
use gears::cli::{Action, Args, Output, SessionStart};
use gears::config::{Config, Found, NamedProvider};
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
use gears::runtime::{Options, ProviderFactory, Runtime};
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
        Action::Reset => reset(&args),
        Action::Run | Action::Ask => run(args, key_from_env),
    }
}

/// Runs before the configuration loads, so a broken setup can be reset too.
fn reset(args: &Args) -> ExitCode {
    let result = (|| {
        let lock = DirectoryLock::acquire_default()?;
        if !lock.owns_directory() {
            return Err("gears reset cannot run inside another Gears".to_string());
        }
        let workspace = match &args.workspace {
            Some(workspace) => workspace.clone(),
            None => {
                std::env::current_dir().map_err(|error| format!("current directory: {error}"))?
            }
        };
        print!("{} Continue? [yes/no] ", gears::reset::DESCRIPTION);
        std::io::stdout()
            .flush()
            .map_err(|error| error.to_string())?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|error| error.to_string())?;
        if !matches!(answer.trim(), "yes" | "y") {
            return Ok(None);
        }
        gears::reset::reset(&gears::directory::default_root()?, &workspace).map(Some)
    })();
    match result {
        Ok(Some(removed)) => {
            println!("Gears was reset; {removed} entries removed.");
            ExitCode::SUCCESS
        }
        Ok(None) => {
            println!("Reset cancelled.");
            ExitCode::FAILURE
        }
        Err(error) => {
            diagnostic(&error);
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args, key_from_env: Option<String>) -> ExitCode {
    // Only an interactive agent run asks setup questions.
    let setup_ui =
        match (args.action == Action::Run && args.prompt.is_none() && args.output == Output::Text)
            .then(|| {
                gears::ui::select::choose(args.ui, false, || {
                    (
                        std::io::stdin().is_terminal(),
                        std::io::stdout().is_terminal(),
                    )
                })
            })
            .transpose()
        {
            Ok(ui) => ui,
            Err(error) => {
                diagnostic(&error);
                return ExitCode::FAILURE;
            }
        };
    let mut config = match load_config(&args, setup_ui) {
        Ok(Some(config)) => config,
        Ok(None) => return ExitCode::SUCCESS,
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
        Ok(count) => diagnostic(&format!(
            "removed {count} abandoned temporary state entries"
        )),
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
    if let Some(choice) = &choice
        && let Err(error) = config.apply_urls(&choice.urls)
    {
        diagnostic(&format!("provider choice: {error}"));
        return ExitCode::FAILURE;
    }
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
        Action::Run => agent(
            &args,
            &config,
            choice.as_ref(),
            key_from_env,
            tools,
            setup_ui,
        ),
        Action::Version | Action::Help | Action::Reset => unreachable!(),
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

/// `--config`, else what `Found::detect` finds. With both the user's and the
/// source tree's, an interactive run asks; `None` if the user cancelled.
fn load_config(
    args: &Args,
    setup_ui: Option<gears::ui::select::Selected>,
) -> Result<Option<Config>, String> {
    if args.config.is_some() {
        return Config::load_user(args.config.as_deref()).map(Some);
    }
    let found = Found::detect();
    let source_tree = match (&found, setup_ui) {
        (Found::Both { user, package }, Some(ui)) => {
            match gears::setup::ask_settings(asker(ui)?.as_mut(), user, package)? {
                Some(source_tree) => source_tree,
                None => return Ok(None),
            }
        }
        _ => false,
    };
    Config::load_found(&found, source_tree).map(Some)
}

/// Setup questions in the UI the session will use; closed before it starts.
fn asker(ui: gears::ui::select::Selected) -> Result<Box<dyn gears::setup::Ask>, String> {
    Ok(match ui {
        gears::ui::select::Selected::Tui => Box::new(gears::ui::tui::SetupScreen::enter()?),
        gears::ui::select::Selected::Line => Box::new(gears::ui::line::SetupPrompts::new()?),
    })
}

fn agent(
    args: &Args,
    config: &Config,
    choice: Option<&ProviderChoice>,
    key_from_env: Option<String>,
    tools: Registry,
    setup_ui: Option<gears::ui::select::Selected>,
) -> Result<(), String> {
    let mut config = config.clone();
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
    let (provider_name, selected_provider, model) = select(args, &config, choice, Some(&session))?;
    let missing_key = key_from_env.is_none()
        && selected_provider
            .key_file
            .as_ref()
            .is_some_and(|path| !path.exists());
    let (provider_name, selected_provider, model) = match (setup_ui, model) {
        (Some(ui), None) => {
            let directory = gears::directory::default_root()?;
            let chosen = gears::setup::run(&config, &directory, asker(ui)?.as_mut())?
                .ok_or("setup cancelled")?;
            if let Some(saved) = ProviderChoice::load_default()? {
                config.apply_urls(&saved.urls)?;
            }
            let provider = config
                .provider(&chosen.provider)
                .ok_or_else(|| format!("unknown provider {:?}", chosen.provider))?;
            (chosen.provider, provider, chosen.model)
        }
        (Some(ui), Some(model)) if missing_key => {
            if !gears::setup::ask_key(asker(ui)?.as_mut(), &provider_name, &selected_provider)? {
                return Err("setup cancelled".into());
            }
            (provider_name, selected_provider, model)
        }
        (_, model) => (provider_name, selected_provider, model.ok_or(NO_MODEL)?),
    };
    let config = &config;
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
    let options = Options {
        tools: Some(tools),
        ..Options::default()
    };
    let mut runtime = Runtime::with_options(provider, store, session, config, model, options)?;
    let factory_config = config.clone();
    let verbosity = args.verbosity;
    let factory: ProviderFactory = Arc::new(move |name| {
        // `/setup` may have saved a new address since startup.
        let mut factory_config = factory_config.clone();
        if let Some(saved) = ProviderChoice::load_default()? {
            factory_config.apply_urls(&saved.urls)?;
        }
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
    if args.output == Output::Jsonl {
        return gears::ui::jsonl::run(
            &mut runtime,
            args.prompt.clone().expect("JSONL requires a prompt"),
            std::io::stdout().lock(),
        );
    }
    let interactive = !one_shot;
    let result = match selected {
        gears::ui::select::Selected::Line => {
            gears::ui::line::run(&mut runtime, args.prompt.clone(), interactive, config)
        }
        gears::ui::select::Selected::Tui => {
            gears::ui::tui::run(&mut runtime, args.prompt.clone(), interactive, config)
        }
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
        SessionStart::Fork(selector) | SessionStart::ForkEphemeral(selector) => {
            let source = store.read(selector)?;
            let source = match &args.fork_entry {
                Some(entry) => source.at(entry)?,
                None => source,
            };
            store.clone_active_with_options(
                &source,
                matches!(args.session, SessionStart::ForkEphemeral(_)),
            )
        }
    }
}

fn ask(
    args: &Args,
    config: &Config,
    choice: Option<&ProviderChoice>,
    key_from_env: Option<String>,
) -> Result<(), String> {
    let (provider_name, selected_provider, model) = select(args, config, choice, None)?;
    let model = model.ok_or(NO_MODEL)?;
    let key = load_key(&selected_provider, key_from_env)?;
    let provider = connect(
        config,
        &provider_name,
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

/// The provider and model, preferring the command line, then the session,
/// then the saved choice, then the configuration's defaults.
const NO_MODEL: &str =
    "no model selected; run gears without -p to choose a provider and model, or pass --model";

fn select(
    args: &Args,
    config: &Config,
    choice: Option<&ProviderChoice>,
    session: Option<&Session>,
) -> Result<(String, NamedProvider, Option<String>), String> {
    let provider_name = args
        .provider
        .clone()
        .or_else(|| session.and_then(Session::provider))
        .or_else(|| choice.map(|choice| choice.provider.clone()))
        .unwrap_or_else(|| config.default_provider.clone());
    let provider = config
        .provider(&provider_name)
        .ok_or_else(|| format!("unknown provider {provider_name:?}"))?;
    let model = args
        .model
        .clone()
        .or_else(|| session.and_then(Session::model))
        .or_else(|| {
            choice
                .filter(|choice| choice.provider == provider_name)
                .map(|choice| choice.model.clone())
        })
        .or_else(|| config.default_model.clone())
        .or_else(|| provider.model.clone())
        .or_else(|| config.models.first().cloned());
    Ok((provider_name, provider, model))
}

/// `None` for a provider without a key file: it gets no key, not even one
/// from the environment, so a cloud key never reaches a local server.
fn load_key(provider: &NamedProvider, from_env: Option<String>) -> Result<Option<ApiKey>, String> {
    match (&provider.key_file, from_env) {
        (None, _) => Ok(None),
        (Some(_), Some(key)) => ApiKey::parse(&key, KEY_ENV).map(Some),
        (Some(path), None) => ApiKey::from_file(path).map(Some),
    }
}

fn connect(
    config: &Config,
    provider_name: &str,
    provider: &NamedProvider,
    key: &Option<ApiKey>,
    verbosity: u8,
) -> Result<OpenAiCompat<HttpBackend>, String> {
    let policy = EgressPolicy::new(&config.egress_allowlist)
        .with_plain_http_allowlist(&config.plain_http_allowlist);
    let mut http = HttpBackend::new(policy)
        .map_err(|error| error.to_string())?
        .with_verbosity(verbosity);
    if let Some(key) = key {
        http = http.with_secret(KEY_ENV, key.expose());
    }
    let http = match provider.ca_cert.as_deref() {
        Some(path) => http.with_ca_cert(path).map_err(|error| error.to_string())?,
        None => http,
    };
    let endpoint = Endpoint::new(&provider.base_url)
        .map_err(|error| error.to_string())?
        .with_reasoning_echo(provider.reasoning_echo);
    let client = OpenAiCompat::new(http, endpoint).with_cache_identity(provider_name);
    Ok(if key.is_some() {
        client
    } else {
        client.without_key()
    })
}

fn diagnostic(message: &str) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "gears: {message}");
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_forks_select_the_saved_entry_before_later_compaction() {
        let base = std::env::temp_dir().join(format!("gears-cli-entry-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        let store = Store::with_root(&base, base.join("state")).unwrap();
        let mut parent = store.create(false, None).unwrap();
        parent
            .append_message(&Message::user("Original task"))
            .unwrap();
        let entry = parent
            .append_message(&Message::assistant("Original answer"))
            .unwrap();
        let messages = parent.context_messages().unwrap();
        parent
            .append_compaction(&gears::session::Compaction {
                summary: "Later summary".into(),
                retained_tail: Vec::new(),
                tokens_before: 100,
            })
            .unwrap();
        parent.append_message(&Message::user("Later task")).unwrap();
        let path = parent.path().unwrap().to_path_buf();
        let before = std::fs::read(&path).unwrap();
        for ephemeral in [false, true] {
            let mut argv = vec!["--fork", parent.id(), "--fork-entry", &entry];
            if ephemeral {
                argv.push("--ephemeral");
            }
            let child = open_session(&store, &Args::parse(&argv).unwrap()).unwrap();
            assert_eq!(child.is_ephemeral(), ephemeral);
            assert_eq!(child.context_messages().unwrap(), messages);
        }
        let args = Args::parse(&["--fork", parent.id(), "--fork-entry", "missing"]).unwrap();
        assert!(open_session(&store, &args).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        parent
            .append_message(&Message::assistant("Parent continued"))
            .unwrap();
        drop(parent);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn startup_forks_read_a_live_parent_and_preserve_the_selected_storage_mode() {
        let base = std::env::temp_dir().join(format!("gears-cli-fork-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        let store = Store::with_root(&base, base.join("state")).unwrap();
        let mut parent = store.create(false, None).unwrap();
        parent
            .append_message(&Message::user("parent work"))
            .unwrap();
        let source = parent.path().unwrap();
        let before = std::fs::read(source).unwrap();
        let args = Args::parse(&["--fork", source.to_str().unwrap(), "--ephemeral"]).unwrap();
        let mut child = open_session(&store, &args).unwrap();
        assert!(child.is_ephemeral());
        assert_eq!(
            child.context_messages().unwrap(),
            [Message::user("parent work")]
        );
        child.append_message(&Message::assistant("review")).unwrap();
        assert_eq!(std::fs::read(source).unwrap(), before);
        assert_eq!(store.list().unwrap().len(), 1);
        let args = Args::parse(&["--fork", parent.id()]).unwrap();
        let saved = open_session(&store, &args).unwrap();
        assert!(!saved.is_ephemeral());
        assert_eq!(
            saved.context_messages().unwrap(),
            [Message::user("parent work")]
        );
        assert_eq!(store.list().unwrap().len(), 2);
        drop(saved);
        drop(child);
        parent
            .append_message(&Message::assistant("parent done"))
            .unwrap();
        drop(parent);
        std::fs::remove_dir_all(base).unwrap();
    }
}
