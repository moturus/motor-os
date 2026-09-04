use crate::cli::{Cli, RustcQueryKind, RustcQueryOptions};
use crate::config::{Config, TargetSelector, effective_rustflags};
use crate::diagnostic::{Error, Result};
use crate::manifest::Manifest;
use crate::process;
use crate::toolchain::Toolchain;
use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn locate_project(manifest_path: &str) -> Result<i32> {
    let manifest = Manifest::load_selected_or_manifest_path(
        Path::new("."),
        Some(Path::new(manifest_path)),
        None,
        false,
    )?;
    let path = manifest
        .path
        .to_str()
        .ok_or_else(|| Error::failure("selected manifest path is not Unicode"))?;
    println!("{}", serde_json::json!({ "root": path }));
    Ok(0)
}

pub fn rustc_query(cli: &Cli, options: &RustcQueryOptions) -> Result<i32> {
    let current = env::current_dir()
        .map_err(|error| Error::failure(format!("failed to read current directory: {error}")))?;
    let manifest = Manifest::load_for_vendor_selected(&current, cli.package.as_deref())?;
    let config = Config::load(&manifest.root)?;
    let toolchain = Toolchain::discover(cli.toolchain.as_deref(), &config)?;
    let target = toolchain.target_info(Some(&options.target))?;
    manifest.require_supported_target(&target)?;
    let selectors = config.targets.keys().filter_map(|selector| match selector {
        TargetSelector::Cfg(expression) => Some(expression.as_str()),
        TargetSelector::Triple(_) => None,
    });
    let matching = target.cfg.matching_selectors(selectors)?;
    let target_options = config.target_options(&target.triple, &matching)?;
    let flags = effective_rustflags(&config, &target_options)?;

    let mut arguments = vec![OsString::from("--print")];
    match options.kind {
        RustcQueryKind::Cfg => {
            arguments.push("cfg".into());
            arguments.push("-O".into());
        }
        RustcQueryKind::TargetSpecJson => arguments.push("target-spec-json".into()),
    }
    arguments.extend([OsString::from("--target"), options.target.clone().into()]);
    if options.kind == RustcQueryKind::TargetSpecJson {
        arguments.extend([OsString::from("-Z"), OsString::from("unstable-options")]);
    }
    arguments.extend(flags.into_iter().map(OsString::from));

    let mut command = Command::new(&toolchain.rustc);
    process::remove_cargo_client_environment(&mut command);
    command
        .args(arguments)
        .env_remove("RUSTC_BOOTSTRAP")
        .current_dir(&manifest.root)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if options.kind == RustcQueryKind::TargetSpecJson {
        command.env("RUSTC_BOOTSTRAP", "1");
    }
    let status = command.status().map_err(|error| {
        Error::failure(format!(
            "failed to execute rustc query `{}`: {error}",
            toolchain.rustc.display()
        ))
    })?;
    Ok(process::exit_status_code(status))
}
