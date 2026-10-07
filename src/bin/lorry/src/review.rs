use std::env;
use std::io::{self, Write};

use crate::admission_state::CompactState;
use crate::atomic::AtomicDirectory;
use crate::cli::Cli;
use crate::config::Config;
use crate::dependency::{self, RegistrySource, ReviewInputs};
use crate::diagnostic::{Error, Result};
use crate::engine;
use crate::manifest::{Manifest, SourceWorkspace};
use crate::repository::RepositorySet;
use crate::toolchain::Toolchain;

pub fn execute(cli: &Cli) -> Result<i32> {
    cli.features.require_default()?;
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let mut workspace = SourceWorkspace::load(
        &current,
        cli.manifest_path.as_deref().map(std::path::Path::new),
    )?;
    cli.selection.select(
        workspace
            .packages
            .iter()
            .map(|member| (member.name.as_str(), &member.version, member.root.as_path())),
        workspace.default_members.iter().map(|root| root.as_path()),
    )?;
    Manifest::report_warnings(&workspace.packages, cli.verbosity);
    let compact = CompactState::load(&workspace.root)?.ok_or_else(|| {
        Error::failure("dependency review requires workspace-root Lorry admission").with_help(
            "run workspace-root `lorry vendor --locked` to review and migrate member records",
        )
    })?;
    workspace.load_locked_context()?;
    let manifest = &workspace.packages[0];
    let mut config = Config::load_workspace(
        &current,
        &workspace.root,
        workspace
            .packages
            .iter()
            .map(|member| member.root.as_path()),
    )?;
    config.apply_max_packages(cli.max_packages)?;
    let toolchain = Toolchain::discover(cli.toolchain.as_deref(), &config, false)?;
    let options = dependency::resolver_options(manifest, &config, &toolchain)?;
    let staging = AtomicDirectory::new(&env::temp_dir(), "lorry-review")?;
    let repositories = RepositorySet::open(
        &config.repositories,
        engine::repository_tree_limits(&config.policy.limits)?,
        config.policy.limits.max_package_bytes,
    )?;
    let review = dependency::workspace::admission::verify(
        &ReviewInputs {
            manifest,
            config: &config,
            source: RegistrySource::Lorry(&repositories),
            toolchain: &toolchain,
            options: &options,
            staging_parent: staging.path(),
            direct: None,
            prepare_context: None,
        },
        &compact,
    )?
    .into_review();
    let report = review.render()?;
    io::stdout()
        .lock()
        .write_all(&report)
        .map_err(|error| Error::failure(format!("failed to write dependency review: {error}")))?;
    Ok(0)
}
