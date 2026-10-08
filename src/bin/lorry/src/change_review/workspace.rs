use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, Write};

use crate::admission_state::{
    Capability, Context, ContextPackage, Review, UnitKind, native_tool_name,
};
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
    Ok(escape_controls(&output))
}

/// Package metadata such as a license is third-party text. Escaping its
/// control characters keeps it from moving the cursor or rewriting earlier
/// review lines before the approval prompt.
fn escape_controls(text: &[u8]) -> Vec<u8> {
    let mut escaped = String::with_capacity(text.len());
    for character in String::from_utf8_lossy(text).chars() {
        if character.is_control() && character != '\n' {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped.into_bytes()
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
    writeln!(output, "  Contexts: {}", contexts(&next.contexts))?;
    if let Some(previous) = previous
        && previous.contexts != next.contexts
    {
        writeln!(
            output,
            "  Previous contexts: {}",
            contexts(&previous.contexts)
        )?;
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
            writeln!(
                output,
                "  - locked package: {} {} (crates.io); checksum: {}; dependencies: {}",
                package.name,
                package.version,
                package.id,
                list(&package.dependencies)
            )?;
        }
        for package in previous
            .locked_git
            .iter()
            .filter(|package| !next.locked_git.contains(package))
        {
            writeln!(
                output,
                "  - locked Git package: {} {} ({}); dependencies: {}",
                package.name,
                package.version,
                package.id,
                list(&package.dependencies)
            )?;
        }
        for capability in previous
            .capabilities
            .iter()
            .filter(|value| !next.capabilities.contains(value))
        {
            writeln!(output, "  - capability: {}", grant(capability))?;
        }
    }
    for capability in next
        .capabilities
        .iter()
        .filter(|value| previous.is_none_or(|old| !old.capabilities.contains(value)))
    {
        writeln!(output, "  + capability: {}", grant(capability))?;
    }
    for package in &next.locked_registry {
        writeln!(
            output,
            "\n  Package: {} {} (crates.io)",
            package.name, package.version
        )?;
        writeln!(output, "    checksum: {}", package.id)?;
        write_users(output, users, &package.name, &package.version, None)?;
        writeln!(
            output,
            "    locked dependencies: {}",
            list(&package.dependencies)
        )?;
        let source = next.registry_sources.iter().find(|source| {
            source.name == package.name
                && source.version == package.version
                && source.id == package.id
        });
        write_source(
            output,
            source.map(|source| {
                (
                    source.source_tree_sha256.as_str(),
                    source.license.as_str(),
                    source.build_script,
                    source.proc_macro,
                )
            }),
        )?;
        let rows = |selected| context_rows(selected, &package.name, &package.version, &package.id);
        write_contexts(
            output,
            previous.map(|old| rows(&old.context_registry)),
            rows(&next.context_registry),
        )?;
    }
    for package in &next.locked_git {
        writeln!(
            output,
            "\n  Package: {} {} ({})",
            package.name, package.version, package.id
        )?;
        write_users(
            output,
            users,
            &package.name,
            &package.version,
            Some(&package.id),
        )?;
        writeln!(
            output,
            "    locked dependencies: {}",
            list(&package.dependencies)
        )?;
        let source = next.git_sources.iter().find(|source| {
            source.name == package.name
                && source.version == package.version
                && source.id == package.id
        });
        write_source(
            output,
            source.map(|source| {
                (
                    source.source_tree_sha256.as_str(),
                    source.license.as_str(),
                    source.build_script,
                    source.proc_macro,
                )
            }),
        )?;
        let rows = |selected| context_rows(selected, &package.name, &package.version, &package.id);
        write_contexts(
            output,
            previous.map(|old| rows(&old.context_git)),
            rows(&next.context_git),
        )?;
    }
    Ok(())
}

/// Comma-separated values, or `none`.
fn list<T: std::fmt::Display>(values: &[T]) -> String {
    if values.is_empty() {
        return "none".to_owned();
    }
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn contexts(values: &[Context]) -> String {
    let values = values
        .iter()
        .map(|context| format!("{} -> {}", context.host, context.target))
        .collect::<Vec<_>>();
    list(&values)
}

fn grant(capability: &Capability) -> String {
    let tools = capability
        .native_tools
        .iter()
        .map(|role| native_tool_name(*role))
        .collect::<Vec<_>>();
    format!(
        "{} {} ({}); build script: {}; procedural macro: {}; native tools: {}; caller environment: {}",
        capability.package,
        capability.version,
        capability.checksum,
        capability.build_script,
        capability.proc_macro,
        list(&tools),
        list(&capability.caller_env)
    )
}

fn write_source(
    output: &mut impl Write,
    source: Option<(&str, &str, bool, bool)>,
) -> io::Result<()> {
    let Some((tree, license, build_script, proc_macro)) = source else {
        return writeln!(
            output,
            "    Source lies outside the reviewed feature/platform closure."
        );
    };
    let license = if license.is_empty() {
        "unspecified"
    } else {
        license
    };
    writeln!(
        output,
        "    tree: {tree}; license: {license}; build script: {build_script}; procedural macro: {proc_macro}"
    )
}

/// Host, target, compile kinds, host features, and target features.
type ContextRow<'a> = (&'a str, &'a str, &'a [UnitKind], &'a [String], &'a [String]);

fn context_rows<'a>(
    selected: &'a [ContextPackage],
    name: &str,
    version: &str,
    id: &str,
) -> Vec<ContextRow<'a>> {
    selected
        .iter()
        .filter(|context| context.name == name && context.version == version && context.id == id)
        .map(|context| {
            (
                context.host.as_str(),
                context.target.as_str(),
                context.compile_kinds.as_slice(),
                context.host_features.as_slice(),
                context.target_features.as_slice(),
            )
        })
        .collect()
}

/// Lists previous feature contexts only when they changed.
fn write_contexts(
    output: &mut impl Write,
    previous: Option<Vec<ContextRow<'_>>>,
    next: Vec<ContextRow<'_>>,
) -> io::Result<()> {
    let previous = previous.filter(|previous| *previous != next);
    let rows = previous
        .iter()
        .flatten()
        .map(|row| ("previous ", row))
        .chain(next.iter().map(|row| ("", row)));
    for (label, (host, target, kinds, host_features, target_features)) in rows {
        writeln!(
            output,
            "    {label}{host} -> {target} ({}); host features: {}; target features: {}",
            list(kinds),
            list(host_features),
            list(target_features)
        )?;
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
        list(&names.into_iter().collect::<Vec<_>>())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_state::{LockedRegistry, SourceEvidence};
    use crate::config::NativeToolRole;

    #[test]
    fn review_escapes_control_characters_from_package_metadata() {
        let license = "MIT\r    tree: x; build script: false\u{1b}[K";
        let line = format!("    tree: abc; license: {license}; build script: true\n");
        assert_eq!(
            String::from_utf8(escape_controls(line.as_bytes())).unwrap(),
            "    tree: abc; license: MIT\\r    tree: x; build script: false\\u{1b}[K; build script: true\n"
        );
    }

    #[test]
    fn human_review_writes_plain_stable_text() {
        let checksum = "1".repeat(64);
        let context = |target: &str| Context {
            host: "host".to_owned(),
            target: target.to_owned(),
        };
        let locked = |name: &str, checksum: &str| LockedRegistry {
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            id: checksum.to_owned(),
            dependencies: vec![],
        };
        let mut previous = Review {
            resolver_version: 2,
            contexts: vec![context("target")],
            locked_registry: vec![locked("helper", &checksum)],
            context_registry: vec![ContextPackage {
                host: "host".to_owned(),
                target: "target".to_owned(),
                name: "helper".to_owned(),
                version: "1.0.0".to_owned(),
                id: checksum.clone(),
                compile_kinds: vec![UnitKind::Host],
                host_features: vec![],
                target_features: vec![],
            }],
            registry_sources: vec![SourceEvidence {
                name: "helper".to_owned(),
                version: "1.0.0".to_owned(),
                id: checksum.clone(),
                license: String::new(),
                source_tree_sha256: "2".repeat(64),
                build_script: true,
                proc_macro: true,
            }],
            ..Review::default()
        };
        previous
            .complete(vec![Capability {
                package: "helper".to_owned(),
                version: "1.0.0".to_owned(),
                checksum: checksum.clone(),
                build_script: true,
                proc_macro: false,
                native_tools: vec![NativeToolRole::CCompiler],
                caller_env: vec![],
            }])
            .unwrap();
        let mut next = previous.clone();
        previous
            .locked_registry
            .push(locked("old", &"3".repeat(64)));
        next.contexts.insert(0, context("other"));
        next.context_registry[0]
            .compile_kinds
            .push(UnitKind::Target);
        next.context_registry[0].host_features = vec!["default".to_owned(), "std".to_owned()];
        next.registry_sources[0].license = "MIT".to_owned();
        next.capabilities[0].caller_env = vec!["PUBLIC".to_owned()];
        let report = render(
            Some(&previous),
            Some("abc"),
            &next,
            &Resolution {
                root_edges: vec![],
                packages: vec![],
            },
        )
        .unwrap();
        let grant = format!(
            "helper 1.0.0 ({checksum}); build script: true; procedural macro: false; native tools: c-compiler; caller environment"
        );
        let expected = format!(
            "Workspace dependency admission review:
  Previous commitment: abc
  Review scope: all workspace members; default features; no additional feature requests
  Contexts: host -> other, host -> target
  Previous contexts: host -> target
  Resolver: 2; 1 locked registry/Git packages; 1 grants
  Reviewed source additions: 1; removals: 1; grant additions: 1; removals: 1
  - locked package: old 1.0.0 (crates.io); checksum: {old}; dependencies: none
  - capability: {grant}: none
  + capability: {grant}: PUBLIC

  Package: helper 1.0.0 (crates.io)
    checksum: {checksum}
    member users: none
    locked dependencies: none
    tree: {tree}; license: MIT; build script: true; procedural macro: true
    previous host -> target (host); host features: none; target features: none
    host -> target (host, target); host features: default, std; target features: none
",
            old = "3".repeat(64),
            tree = "2".repeat(64),
        );
        assert_eq!(String::from_utf8(report).unwrap(), expected);
    }
}
