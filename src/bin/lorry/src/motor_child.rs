//! The caller owns configuration, approval and execution; a constrained child
//! owns acquisition or compilation. Package code never runs in the parent.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::motor::process::ChildExt;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};
use std::sync::{Mutex, OnceLock};

use moto_sdk::ipc::sync::{ChannelSize, ClientConnection, LocalServer};
use moto_sdk::sys::{ProcessStaticPage, SysHandle, caps};
use serde::{Deserialize, Serialize};

use crate::cli::{Cli, Command};
use crate::config::Config;
use crate::diagnostic::{Error, Result};

mod rpc;

pub(crate) const CHILD_ARGUMENT: &str = "--lorry-motor-child";
const CONFIG_LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Start {
    config: Config,
    parent_pid: u64,
    parent_caps: u64,
    endpoint: String,
    interactive: bool,
}

struct Child {
    start: Start,
    connection: Mutex<ClientConnection>,
}

static CHILD: OnceLock<Child> = OnceLock::new();

#[derive(Serialize, Deserialize)]
enum Request {
    Redirect {
        source: String,
        destination: String,
    },
    Approve {
        report: Vec<u8>,
        mode: crate::change_review::Mode,
    },
    Decisions(crate::workspace_trust::DecisionUpdate),
    Run {
        program: String,
        arguments: Vec<String>,
        directory: PathBuf,
        environment: BTreeMap<String, String>,
        kind: crate::process::ChildKind,
        verbose: bool,
    },
}

pub(crate) fn own_caps() -> u64 {
    ProcessStaticPage::get().capabilities
}

pub(crate) fn build_caps(own: u64) -> u64 {
    own & (caps::CAP_SPAWN | caps::CAP_FS_WRITE)
}

fn command_caps(command: &Command, own: u64) -> Option<u64> {
    let offline = match command {
        Command::Fetch(options) => Some(options.offline),
        Command::Vendor(options) => Some(options.offline),
        _ => None,
    };
    if let Some(offline) = offline {
        return Some(
            own & !caps::CAP_SPAWN_DETACHED & if offline { !caps::CAP_NET } else { u64::MAX },
        );
    }
    matches!(
        command,
        Command::Build(_)
            | Command::Check(_)
            | Command::Run(_)
            | Command::Test(_)
            | Command::Metadata(_)
            | Command::Tree(_)
            | Command::Review
    )
    .then(|| build_caps(own))
}

pub(crate) fn is_child() -> bool {
    CHILD.get().is_some()
}

pub(crate) fn interactive() -> Option<bool> {
    CHILD.get().map(|child| child.start.interactive)
}

pub(crate) fn caller_role() -> crate::role::Role {
    let caps = CHILD
        .get()
        .map_or_else(own_caps, |child| child.start.parent_caps);
    if caps & caps::CAP_INTERACTIVE != 0 {
        crate::role::Role::Interactive
    } else {
        crate::role::Role::None
    }
}

pub(crate) fn configuration(workspace: &Path) -> Result<Option<Config>> {
    let Some(child) = CHILD.get() else {
        return Ok(None);
    };
    if child.start.config.policy.workspace.as_deref() != Some(workspace) {
        return Err(Error::failure(
            "Lorry worker configuration belongs to another workspace",
        ));
    }
    Ok(Some(child.start.config.clone()))
}

pub(crate) fn child_main(arguments: Vec<String>) -> i32 {
    let messages = Cli::lorry_messages_requested(&arguments);
    let result = (|| {
        crate::role::refuse_system()?;
        let cli = Cli::parse(arguments)?;
        crate::prompt::set_machine_messages(cli.lorry_messages);
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(CONFIG_LIMIT + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > CONFIG_LIMIT {
            return Err(Error::failure("Lorry worker configuration exceeds 16 MiB"));
        }
        let start: Start = serde_json::from_slice(&bytes).map_err(rpc::failure)?;
        if start.parent_caps & caps::CAP_SYS != 0
            || command_caps(&cli.command, start.parent_caps) != Some(own_caps())
        {
            return Err(Error::failure(
                "Lorry worker capabilities do not match its command",
            ));
        }
        let mut connection = ClientConnection::new(ChannelSize::Small).map_err(rpc::failure)?;
        connection.connect(&start.endpoint).map_err(rpc::failure)?;
        rpc::authenticate(connection.handle(), start.parent_pid, start.parent_caps)?;
        CHILD
            .set(Child {
                start,
                connection: Mutex::new(connection),
            })
            .map_err(|_| Error::failure("Lorry worker was initialized twice"))?;
        crate::run(cli)
    })();
    result.unwrap_or_else(|error| crate::report_error(error, messages))
}

pub(crate) fn execute(cli: &Cli) -> Result<Option<i32>> {
    let Some(mask) = command_caps(&cli.command, own_caps()) else {
        return Ok(None);
    };
    let current = std::env::current_dir()?;
    let workspace = crate::manifest::SourceWorkspace::load(
        &current,
        cli.manifest_path.as_deref().map(Path::new),
    )?;
    let config = Config::load_source_workspace(&current, &workspace, cli.max_packages)?;
    crate::motor_fs::require_workspace(&workspace.root)?;
    if let Some(options) = cli.command.build_options() {
        let target =
            config.target_directory(&current, &workspace.root, options.target_dir.as_deref());
        let existing = target
            .ancestors()
            .find(|path| path.exists())
            .ok_or_else(|| Error::failure("target directory has no existing parent"))?;
        crate::motor_fs::require_workspace(existing)?;
    }
    let endpoint = format!("lorry-worker-{}", std::process::id());
    let mut server = LocalServer::new(&endpoint, ChannelSize::Small, 1, 1).map_err(rpc::failure)?;
    let start = Start {
        config,
        parent_pid: std::process::id().into(),
        parent_caps: own_caps(),
        endpoint,
        interactive: crate::prompt::interactive(),
    };
    let bytes = serde_json::to_vec(&start).map_err(rpc::failure)?;
    let role = if mask & caps::CAP_INTERACTIVE != 0 {
        crate::role::Role::Interactive
    } else {
        crate::role::Role::None
    };
    let mut child = Process::new(std::env::current_exe()?)
        .arg(CHILD_ARGUMENT)
        .args(std::env::args_os().skip(1))
        .env("MOTOR_OS_CAPS", format!("{mask:#x}"))
        .env("TMPDIR", role.temp_directory())
        // The parent answers prompts; an inherited terminal relay would
        // consume its input while the worker is running.
        .env(moto_sdk::rt::process::STDIO_NO_TERMINAL_ENV_KEY, "true")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let child_pid = u64::from(child.id());
    let child_handle = SysHandle::from_u64(child.sys_handle());
    let result = (|| {
        child.stdin.take().unwrap().write_all(&bytes)?;
        let mut receiver = rpc::Receiver::default();
        let mut redirects = None;
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(crate::process::exit_status_code(status));
            }
            let handles = server
                .wait(SysHandle::NONE, &[child_handle])
                .unwrap_or_else(|closed| closed);
            for handle in handles {
                let Some(connection) = server.get_connection(handle) else {
                    continue;
                };
                if rpc::authenticate(handle, child_pid, mask).is_err() {
                    connection.disconnect();
                    continue;
                }
                if !connection.have_req() {
                    continue;
                }
                let result = receiver.request(connection).and_then(|request| {
                    request
                        .map(|request| handle_request(cli, &start.config, &mut redirects, request))
                        .transpose()
                });
                rpc::respond(connection, &result)?;
            }
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result.map(Some)
}

fn handle_request(
    cli: &Cli,
    config: &Config,
    redirects: &mut Option<crate::redirect::TrustPolicy>,
    request: Request,
) -> Result<i32> {
    match request {
        Request::Redirect {
            source,
            destination,
        } => {
            if !matches!(cli.command, Command::Fetch(_) | Command::Vendor(_)) {
                return Err(Error::failure(
                    "only an acquisition worker may request redirect approval",
                ));
            }
            if redirects.is_none() {
                *redirects = Some(crate::redirect::TrustPolicy::load_default()?);
            }
            redirects.as_mut().unwrap().authorize(
                &crate::redirect::HttpsUrl::parse(&source)?,
                &crate::redirect::HttpsUrl::parse(&destination)?,
            )?;
            Ok(0)
        }
        Request::Approve { report, mode } => {
            let Command::Vendor(options) = &cli.command else {
                return Err(Error::failure("only a vendor worker may request approval"));
            };
            if matches!(mode, crate::change_review::Mode::AcceptAll)
                && !options.accept_all
                && !config.policy.accept_all
            {
                return Err(Error::failure(
                    "worker requested an unapproved --accept-all",
                ));
            }
            crate::change_review::approve_report(
                &report,
                mode,
                crate::prompt::interactive(),
                &mut std::io::stdin().lock(),
                &mut std::io::stderr().lock(),
            )?;
            Ok(0)
        }
        Request::Decisions(update) => {
            if !matches!(cli.command, Command::Vendor(_)) {
                return Err(Error::failure("only a vendor worker may record approvals"));
            }
            update.record(
                config
                    .policy
                    .workspace
                    .as_deref()
                    .ok_or_else(|| Error::failure("worker has no workspace"))?,
            )?;
            Ok(0)
        }
        Request::Run {
            program,
            arguments,
            directory,
            mut environment,
            kind,
            verbose,
        } => {
            if !matches!(cli.command, Command::Run(_) | Command::Test(_)) {
                return Err(Error::failure(
                    "this Lorry worker may not run programs in its parent",
                ));
            }
            environment.insert("MOTOR_OS_CAPS".to_owned(), format!("{:#x}", own_caps()));
            crate::process::run_child(
                OsStr::new(&program),
                &arguments
                    .into_iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>(),
                &directory,
                &environment
                    .into_iter()
                    .map(|(name, value)| (name, value.into()))
                    .collect(),
                kind,
                verbose,
            )
        }
    }
}

pub(crate) fn run_program(
    program: &OsStr,
    arguments: &[OsString],
    directory: &Path,
    environment: &BTreeMap<String, OsString>,
    kind: crate::process::ChildKind,
    verbose: bool,
) -> Result<i32> {
    call(Request::Run {
        program: text(program)?,
        arguments: arguments
            .iter()
            .map(|value| text(value))
            .collect::<Result<_>>()?,
        directory: directory.to_owned(),
        environment: environment
            .iter()
            .map(|(name, value)| Ok((name.clone(), text(value)?)))
            .collect::<Result<_>>()?,
        kind,
        verbose,
    })
}

fn text(value: &OsStr) -> Result<String> {
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::failure("Motor process input is not Unicode"))
}

pub(crate) fn approve(report: &[u8], mode: crate::change_review::Mode) -> Result<()> {
    call(Request::Approve {
        report: report.to_owned(),
        mode,
    })
    .map(|_| ())
}

pub(crate) fn authorize_redirect(source: &str, destination: &str) -> Result<()> {
    call(Request::Redirect {
        source: source.to_owned(),
        destination: destination.to_owned(),
    })
    .map(|_| ())
}

pub(crate) fn record_decisions(update: crate::workspace_trust::DecisionUpdate) -> Result<()> {
    call(Request::Decisions(update)).map(|_| ())
}

fn call(request: Request) -> Result<i32> {
    let mut client = CHILD
        .get()
        .ok_or_else(|| Error::failure("Lorry is not a worker"))?
        .connection
        .lock()
        .map_err(|_| Error::failure("Lorry worker connection was poisoned"))?;
    rpc::call(&mut client, &request)
}

#[cfg(test)]
#[path = "../tests/unit/motor-children.rs"]
mod tests;
