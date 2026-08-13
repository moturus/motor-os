use std::env;
use std::io::{self, Write};

use crate::admission_state::CompactState;
use crate::atomic::AtomicDirectory;
use crate::cli::Cli;
use crate::config::Config;
use crate::dependency::{self, RegistrySource, ReviewInputs};
use crate::diagnostic::{Error, Result};
use crate::engine;
use crate::manifest::Manifest;
use crate::repository::RepositorySet;
use crate::toolchain::Toolchain;

pub fn execute(cli: &Cli) -> Result<i32> {
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    crate::admission_state::require_no_transaction(&current)?;
    let manifest = Manifest::load(&current)?;
    let compact = CompactState::load(&manifest.root)?.ok_or_else(|| {
        Error::failure("dependency review requires generated Lorry dependency state")
            .with_help("run `lorry vendor` once to create `.lorry/dependencies-v2.toml`")
    })?;
    let config = Config::load(&manifest.root)?;
    let toolchain = Toolchain::discover(cli.toolchain.as_deref(), &config)?;
    engine::check_rust_version(&manifest, &toolchain)?;
    let options = dependency::resolver_options(&manifest, &config, &toolchain)?;
    let staging = AtomicDirectory::new(&env::temp_dir(), "lorry-review")?;
    let repositories = RepositorySet::open(
        &config.repositories,
        engine::repository_tree_limits(&config.policy.limits)?,
        config.policy.limits.max_package_bytes,
    )?;
    let review = dependency::verify_compact_admission(
        &ReviewInputs {
            manifest: &manifest,
            config: &config,
            source: RegistrySource::Lorry(&repositories),
            toolchain: &toolchain,
            options: &options,
            staging_parent: staging.path(),
        },
        &compact,
    )?;
    let report = review.render()?;
    io::stdout()
        .lock()
        .write_all(&report)
        .map_err(|error| Error::failure(format!("failed to write dependency review: {error}")))?;
    Ok(0)
}
