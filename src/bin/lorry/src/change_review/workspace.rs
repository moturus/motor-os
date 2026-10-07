use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Write};

use crate::admission_state::Review;
use crate::diagnostic::{Error, Result};
use crate::resolver::{PackageKey, Resolution};

pub(crate) fn approve(
    previous: Option<&Review>,
    next: &Review,
    report: &[u8],
    mode: super::Mode,
    terminal: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    if previous == Some(next) && matches!(mode, super::Mode::Change) {
        return Ok(());
    }
    output.write_all(report).map_err(|error| {
        Error::failure(format!(
            "failed to write workspace dependency review: {error}"
        ))
    })?;
    super::confirm(mode, terminal, input, output)
}

pub(crate) fn render(
    previous: Option<&Review>,
    previous_commitment: Option<&str>,
    next: &Review,
    resolution: &Resolution,
) -> Result<Vec<u8>> {
    next.validate()?;
    let users = member_users(resolution);
    let mut output = Vec::new();
    write(&mut output, previous, previous_commitment, next, &users).map_err(|error| {
        Error::failure(format!(
            "failed to render workspace dependency review: {error}"
        ))
    })?;
    Ok(output)
}

// Walk each selected member's units separately so shared transitive packages
// list all member users, including a member selected as both root and dependency.
fn member_users(resolution: &Resolution) -> BTreeMap<PackageKey, BTreeSet<String>> {
    let packages = resolution
        .packages
        .iter()
        .map(|package| (&package.key, package))
        .collect::<BTreeMap<_, _>>();
    let mut users = BTreeMap::<PackageKey, BTreeSet<String>>::new();
    for root in &resolution.root_edges {
        let mut seen = BTreeSet::new();
        let mut pending = vec![(root.package.clone(), root.compile_kind)];
        while let Some((key, kind)) = pending.pop() {
            if !seen.insert((key.clone(), kind)) {
                continue;
            }
            users
                .entry(key.clone())
                .or_default()
                .insert(root.package.name.clone());
            if let Some(package) = packages.get(&key) {
                for edge in &package.edges {
                    if edge.parent_compile_kind == Some(kind) {
                        pending.push((edge.package.clone(), edge.compile_kind));
                    }
                }
            }
        }
    }
    users
}

fn write(
    output: &mut impl Write,
    previous: Option<&Review>,
    previous_commitment: Option<&str>,
    next: &Review,
    users: &BTreeMap<PackageKey, BTreeSet<String>>,
) -> io::Result<()> {
    writeln!(output, "Workspace dependency admission review:")?;
    if let Some(commitment) = previous_commitment {
        writeln!(output, "  Previous commitment: {commitment}")?;
        if previous.is_none() {
            writeln!(
                output,
                "  Previous review cannot be reconstructed; showing the complete candidate."
            )?;
        }
    }
    writeln!(output, "  {}", next.scope.description())?;
    writeln!(output, "  Contexts: {:?}", next.contexts)?;
    if let Some(previous) = previous
        && previous.contexts != next.contexts
    {
        writeln!(output, "  Previous contexts: {:?}", previous.contexts)?;
    }
    writeln!(
        output,
        "  Resolver: {}; {} locked registry/Git packages; {} grants",
        next.resolver_version,
        next.locked_registry.len() + next.locked_git.len(),
        next.capabilities.len()
    )?;
    writeln!(
        output,
        "  Reviewed source additions: {}; removals: {}; grant additions: {}; removals: {}",
        additions(
            previous.map(|old| old.registry_sources.as_slice()),
            &next.registry_sources
        ) + additions(
            previous.map(|old| old.git_sources.as_slice()),
            &next.git_sources
        ),
        previous.map_or(0, |old| additions(
            Some(&next.registry_sources),
            &old.registry_sources
        ) + additions(
            Some(&next.git_sources),
            &old.git_sources
        )),
        additions(
            previous.map(|old| old.capabilities.as_slice()),
            &next.capabilities
        ),
        previous.map_or(0, |old| additions(
            Some(&next.capabilities),
            &old.capabilities
        ))
    )?;
    if let Some(previous) = previous {
        for package in previous
            .locked_registry
            .iter()
            .filter(|package| !next.locked_registry.contains(package))
        {
            writeln!(output, "  - locked package: {package:?}")?;
        }
        for package in previous
            .locked_git
            .iter()
            .filter(|package| !next.locked_git.contains(package))
        {
            writeln!(output, "  - locked Git package: {package:?}")?;
        }
        for capability in previous
            .capabilities
            .iter()
            .filter(|value| !next.capabilities.contains(value))
        {
            writeln!(output, "  - capability: {capability:?}")?;
        }
    }
    for capability in next
        .capabilities
        .iter()
        .filter(|value| previous.is_none_or(|old| !old.capabilities.contains(value)))
    {
        writeln!(output, "  + capability: {capability:?}")?;
    }
    for package in &next.locked_registry {
        writeln!(
            output,
            "\n  Package: {} {} (crates.io)",
            package.name, package.version
        )?;
        writeln!(output, "    checksum: {}", package.checksum)?;
        write_users(output, users, &package.name, &package.version, None)?;
        writeln!(
            output,
            "    locked dependencies: {:?}",
            package.dependencies
        )?;
        if let Some(source) = next.registry_sources.iter().find(|source| {
            source.name == package.name
                && source.version == package.version
                && source.checksum == package.checksum
        }) {
            writeln!(
                output,
                "    tree: {}; license: {:?}; build script: {}; procedural macro: {}",
                source.source_tree_sha256, source.license, source.build_script, source.proc_macro
            )?;
        } else {
            writeln!(
                output,
                "    Source lies outside the reviewed feature/platform closure."
            )?;
        }
        let contexts = next
            .context_registry
            .iter()
            .filter(|context| {
                context.name == package.name
                    && context.version == package.version
                    && context.checksum == package.checksum
            })
            .collect::<Vec<_>>();
        if let Some(previous) = previous {
            let old = previous
                .context_registry
                .iter()
                .filter(|context| {
                    context.name == package.name
                        && context.version == package.version
                        && context.checksum == package.checksum
                })
                .collect::<Vec<_>>();
            if old != contexts {
                for context in old {
                    writeln!(
                        output,
                        "    previous {} -> {}: {:?}; host {:?}; target {:?}",
                        context.host,
                        context.target,
                        context.compile_kinds,
                        context.host_features,
                        context.target_features
                    )?;
                }
            }
        }
        for context in contexts {
            writeln!(
                output,
                "    {} -> {}: {:?}; host {:?}; target {:?}",
                context.host,
                context.target,
                context.compile_kinds,
                context.host_features,
                context.target_features
            )?;
        }
    }
    for package in &next.locked_git {
        writeln!(
            output,
            "\n  Package: {} {} ({})",
            package.name, package.version, package.source
        )?;
        write_users(
            output,
            users,
            &package.name,
            &package.version,
            Some(&package.source),
        )?;
        writeln!(
            output,
            "    locked dependencies: {:?}",
            package.dependencies
        )?;
        if let Some(source) = next.git_sources.iter().find(|source| {
            source.name == package.name
                && source.version == package.version
                && source.source == package.source
        }) {
            writeln!(
                output,
                "    tree: {}; license: {:?}; build script: {}; procedural macro: {}",
                source.source_tree_sha256, source.license, source.build_script, source.proc_macro
            )?;
        } else {
            writeln!(
                output,
                "    Source lies outside the reviewed feature/platform closure."
            )?;
        }
        let contexts = next
            .context_git
            .iter()
            .filter(|context| {
                context.name == package.name
                    && context.version == package.version
                    && context.source == package.source
            })
            .collect::<Vec<_>>();
        if let Some(previous) = previous {
            let old = previous
                .context_git
                .iter()
                .filter(|context| {
                    context.name == package.name
                        && context.version == package.version
                        && context.source == package.source
                })
                .collect::<Vec<_>>();
            if old != contexts {
                for context in old {
                    writeln!(
                        output,
                        "    previous {} -> {}: {:?}; host {:?}; target {:?}",
                        context.host,
                        context.target,
                        context.compile_kinds,
                        context.host_features,
                        context.target_features
                    )?;
                }
            }
        }
        for context in contexts {
            writeln!(
                output,
                "    {} -> {}: {:?}; host {:?}; target {:?}",
                context.host,
                context.target,
                context.compile_kinds,
                context.host_features,
                context.target_features
            )?;
        }
    }
    Ok(())
}

fn additions<T: PartialEq>(previous: Option<&[T]>, next: &[T]) -> usize {
    next.iter()
        .filter(|value| previous.is_none_or(|old| !old.contains(value)))
        .count()
}

fn write_users(
    output: &mut impl Write,
    users: &BTreeMap<PackageKey, BTreeSet<String>>,
    name: &str,
    version: &str,
    source: Option<&str>,
) -> io::Result<()> {
    let names = users
        .iter()
        .filter(|(key, _)| {
            key.name == name
                && key.version.to_string() == version
                && match (&key.source, source) {
                    (crate::resolver::PackageSourceKey::CratesIo, None) => true,
                    (crate::resolver::PackageSourceKey::Git(locked), Some(source)) => {
                        locked == source
                    }
                    _ => false,
                }
        })
        .flat_map(|(_, names)| names.iter().cloned())
        .collect::<BTreeSet<_>>();
    writeln!(
        output,
        "    member users: {}",
        names.into_iter().collect::<Vec<_>>().join(", ")
    )
}
