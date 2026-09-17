use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};

mod log;

use motor_gix::{
    Result, add, cancellation, clone, commit, diff, fetch, init, network, recover, refs,
    repository, restore, status, switch, unstage,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let was_cancelled = cancellation::was_cancelled(err.as_ref());
            let mut stderr = io::stderr().lock();
            _ = writeln!(stderr, "gix: {err}");
            let mut source = err.source();
            while let Some(err) = source {
                _ = writeln!(stderr, "  caused by: {err}");
                source = err.source();
            }
            if was_cancelled {
                ExitCode::from(130)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run() -> Result {
    let matches = Command::new("gix")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Git for Motor OS")
        .disable_help_subcommand(true)
        .subcommand_required(true)
        .arg(
            Arg::new("repository")
                .short('r')
                .long("repository")
                .value_name("REPOSITORY")
                .value_parser(value_parser!(PathBuf))
                .default_value(".")
                .global(true),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .value_name("key=value")
                .action(ArgAction::Append)
                .global(true),
        )
        .arg(
            Arg::new("config-paths")
                .long("config-paths")
                .help("Report configuration files used while opening the repository")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .subcommand(
            Command::new("add")
                .about("Stage worktree changes")
                .arg(
                    Arg::new("all")
                        .short('A')
                        .long("all")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("paths"),
                )
                .arg(
                    Arg::new("paths")
                        .value_name("PATH")
                        .action(ArgAction::Append)
                        .num_args(1..)
                        .required_unless_present("all"),
                ),
        )
        .subcommand(
            Command::new("diff")
                .about("Show worktree or staged changes")
                .arg(Arg::new("staged").long("staged").action(ArgAction::SetTrue))
                .arg(
                    Arg::new("paths")
                        .value_name("PATH")
                        .action(ArgAction::Append)
                        .num_args(1..),
                ),
        )
        .subcommand(
            Command::new("unstage")
                .about("Restore index entries from HEAD without changing the worktree")
                .arg(
                    Arg::new("paths")
                        .value_name("PATH")
                        .action(ArgAction::Append)
                        .num_args(1..)
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("restore")
                .about("Restore worktree files from the index")
                .arg(
                    Arg::new("paths")
                        .value_name("PATH")
                        .action(ArgAction::Append)
                        .num_args(1..)
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("commit").about("Commit the staged index").arg(
                Arg::new("message")
                    .short('m')
                    .required(true)
                    .value_name("MSG"),
            ),
        )
        .subcommand(
            Command::new("clone")
                .about("Clone an anonymous HTTPS repository into a new directory")
                .arg(Arg::new("url").required(true).value_name("URL"))
                .arg(
                    Arg::new("directory")
                        .required(true)
                        .value_name("DIR")
                        .value_parser(value_parser!(PathBuf)),
                ),
        )
        .subcommand(
            Command::new("init")
                .about("Initialize an ordinary SHA-1 worktree repository")
                .arg(
                    Arg::new("directory")
                        .default_value(".")
                        .value_name("DIR")
                        .value_parser(value_parser!(PathBuf)),
                ),
        )
        .subcommand(
            Command::new("fetch")
                .about("Fetch a configured remote without changing the worktree")
                .arg(
                    Arg::new("remote")
                        .default_value("origin")
                        .value_name("REMOTE"),
                ),
        )
        .subcommand(reference_command("branch", "Manage local branches"))
        .subcommand(reference_command("tag", "Manage lightweight tags"))
        .subcommand(Command::new("log").about("Show commit history"))
        .subcommand(Command::new("status").about("Show worktree status"))
        .subcommand(
            Command::new("switch")
                .about("Switch a clean worktree to an existing local branch")
                .arg(Arg::new("branch").required(true).value_name("BRANCH")),
        )
        .subcommand(Command::new("recover").about("Repair a recorded interrupted operation"))
        .get_matches();

    let cancellation = cancellation::Cancellation::install()?;

    let path = matches
        .get_one::<PathBuf>("repository")
        .expect("the repository path has a default");
    let overrides = matches
        .get_many::<String>("config")
        .into_iter()
        .flatten()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if let Some(("init", command)) = matches.subcommand() {
        let result = init::run(
            command
                .get_one::<PathBuf>("directory")
                .expect("the init directory has a default"),
            &overrides,
            matches.get_flag("config-paths"),
            &cancellation,
        );
        result?;
        return cancellation.check();
    }
    if let Some(("clone", command)) = matches.subcommand() {
        let result = clone::run(
            command.get_one::<String>("url").expect("required URL"),
            command
                .get_one::<PathBuf>("directory")
                .expect("required destination"),
            &overrides,
            matches.get_flag("config-paths"),
            &cancellation,
        );
        result?;
        return cancellation.check();
    }
    let opened = repository::open(path, &overrides, matches.get_flag("config-paths"));
    let mut opened = opened?;
    cancellation.check()?;

    let result = match matches.subcommand_name() {
        Some("add") => {
            let command = matches.subcommand_matches("add").expect("matched add");
            let paths = command
                .get_many::<String>("paths")
                .into_iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>();
            add::run(&opened, command.get_flag("all"), &paths, &cancellation)
        }
        Some("branch") => reference_run(
            &mut opened,
            matches
                .subcommand_matches("branch")
                .expect("matched branch"),
            refs::Kind::Branch,
            &cancellation,
        ),
        Some("commit") => commit::run(
            &opened,
            matches
                .subcommand_matches("commit")
                .expect("matched commit")
                .get_one::<String>("message")
                .expect("required message"),
            &cancellation,
        ),
        Some("diff") => {
            let command = matches.subcommand_matches("diff").expect("matched diff");
            let paths = command
                .get_many::<String>("paths")
                .into_iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>();
            diff::run(
                &opened,
                command.get_flag("staged"),
                &paths,
                &cancellation,
                io::stdout().lock(),
            )
        }
        Some("fetch") => {
            let policy = network::Policy::new(&overrides, &cancellation)?;
            fetch::run(
                &mut opened,
                matches
                    .subcommand_matches("fetch")
                    .expect("matched fetch")
                    .get_one::<String>("remote")
                    .expect("default remote"),
                &policy,
                &cancellation,
            )
        }
        Some("log") => log::show(&opened.repo, &cancellation),
        Some("recover") => {
            let action = recover::run(&opened, &cancellation)?;
            let mut out = io::stdout().lock();
            writeln!(out, "{action}")?;
            out.flush()?;
            Ok(())
        }
        Some("switch") => switch::run(
            &mut opened,
            matches
                .subcommand_matches("switch")
                .expect("matched switch")
                .get_one::<String>("branch")
                .expect("required branch"),
            &cancellation,
        ),
        Some("restore") => {
            let command = matches
                .subcommand_matches("restore")
                .expect("matched restore");
            let paths = command
                .get_many::<String>("paths")
                .expect("required paths")
                .cloned()
                .collect::<Vec<_>>();
            restore::run(&opened, &paths, &cancellation)
        }
        Some("unstage") => {
            let command = matches
                .subcommand_matches("unstage")
                .expect("matched unstage");
            let paths = command
                .get_many::<String>("paths")
                .expect("required paths")
                .cloned()
                .collect::<Vec<_>>();
            unstage::run(&opened, &paths, &cancellation)
        }
        Some("tag") => reference_run(
            &mut opened,
            matches.subcommand_matches("tag").expect("matched tag"),
            refs::Kind::Tag,
            &cancellation,
        ),
        Some("status") => status::collect(&opened, &cancellation)
            .and_then(|report| report.write_to(io::stdout().lock(), &cancellation)),
        _ => unreachable!("clap accepts only declared subcommands"),
    };
    result?;
    cancellation.check()
}

fn reference_command(name: &'static str, about: &'static str) -> Command {
    Command::new(name)
        .about(about)
        .subcommand_required(true)
        .subcommand(Command::new("list").about("List names"))
        .subcommand(
            Command::new("create")
                .about("Create without replacing an existing reference")
                .arg(Arg::new("name").required(true).value_name("NAME"))
                .arg(Arg::new("revision").value_name("REV")),
        )
}

fn reference_run(
    opened: &mut repository::OpenedRepository,
    command: &ArgMatches,
    kind: refs::Kind,
    cancellation: &cancellation::Cancellation,
) -> Result {
    match command.subcommand() {
        Some(("list", _)) => refs::list(&opened.repo, kind, io::stdout().lock(), cancellation),
        Some(("create", create)) => refs::create(
            opened,
            kind,
            create.get_one::<String>("name").expect("required name"),
            create.get_one::<String>("revision").map(String::as_str),
            cancellation,
        ),
        _ => unreachable!("clap requires a declared reference subcommand"),
    }
}
