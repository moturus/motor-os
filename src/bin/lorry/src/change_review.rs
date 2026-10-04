use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use crate::admission_state::Review;
use crate::diagnostic::{Error, Result};
use crate::prompt;

#[derive(Clone, Copy)]
pub enum Mode {
    Change,
    Forced,
    AcceptAll,
}

/// Displays the dependency change for approval. With a reconstructible
/// committed baseline this is a semantic diff. When visible input changes
/// prevent reconstruction, the prior commitment and complete candidate are
/// shown instead.
pub fn approve(
    previous: Option<&Review>,
    previous_sha256: &str,
    next: &Review,
    mode: Mode,
    terminal: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    match previous {
        Some(previous) if previous == next && matches!(mode, Mode::Change) => return Ok(()),
        Some(previous) => {
            if previous != next {
                writeln!(output, "Dependency change review:").map_err(|error| {
                    Error::failure(format!("failed to write dependency change review: {error}"))
                })?;
                write_review_difference(output, previous, next)?;
            }
        }
        None => {
            let report = next.render()?;
            writeln!(
                output,
                "The previous admission commitment was {previous_sha256}.\n\
                 The visible dependency inputs no longer reconstruct that review, so no semantic diff is available.\n\
                 Complete candidate review document:"
            )
            .and_then(|()| output.write_all(&report))
            .map_err(|error| {
                Error::failure(format!("failed to write dependency change review: {error}"))
            })?;
        }
    }
    confirm(mode, terminal, input, output)
}

pub(crate) fn approve_json(
    previous: Option<&Review>,
    previous_sha256: Option<&str>,
    next: &Review,
    mode: Mode,
    terminal: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    if previous == Some(next) && matches!(mode, Mode::Change) {
        return Ok(());
    }
    let packages =
        |review: &Review| {
            review.registry_sources.iter().map(|package| serde_json::json!({
            "name": package.name, "version": package.version,
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "checksum": package.checksum, "source_tree_sha256": package.source_tree_sha256,
            "license": package.license, "build_script": package.build_script,
            "proc_macro": package.proc_macro,
        })).chain(review.git_sources.iter().map(|package| serde_json::json!({
            "name": package.name, "version": package.version, "source": package.source,
            "checksum": null, "source_tree_sha256": package.source_tree_sha256,
            "license": package.license, "build_script": package.build_script,
            "proc_macro": package.proc_macro,
        }))).collect::<Vec<_>>()
        };
    let capabilities = |review: &Review| {
        review
            .capabilities
            .iter()
            .map(|capability| {
                serde_json::json!({
                    "name": capability.package, "version": capability.version,
                    "checksum": capability.checksum, "build_script": capability.build_script,
                    "proc_macro": capability.proc_macro,
                    "native_tools": capability.native_tools.iter().map(|role| match role {
                        crate::config::NativeToolRole::CCompiler => "c-compiler",
                        crate::config::NativeToolRole::Archiver => "archiver",
                    }).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>()
    };
    let old_packages = previous.map(packages).unwrap_or_default();
    let next_packages = packages(next);
    let old_capabilities = previous.map(capabilities).unwrap_or_default();
    let next_capabilities = capabilities(next);
    let difference = |left: &[serde_json::Value], right: &[serde_json::Value]| {
        left.iter()
            .filter(|value| !right.contains(value))
            .cloned()
            .collect::<Vec<_>>()
    };
    let message = serde_json::json!({
        "reason": "lorry-vendor-change",
        "previous_commitment": previous_sha256,
        "previous_review_available": previous.is_some() || previous_sha256.is_none(),
        "added": difference(&next_packages, &old_packages),
        "removed": difference(&old_packages, &next_packages),
        "capabilities_added": difference(&next_capabilities, &old_capabilities),
        "capabilities_removed": difference(&old_capabilities, &next_capabilities),
        // Retain the full review for changes beyond this summary, including
        // feature contexts and unresolved comparisons with a prior commitment.
        "review": String::from_utf8(next.render()?).map_err(|error| {
            Error::failure(format!("candidate review is not UTF-8: {error}"))
        })?,
    });
    writeln!(output, "{message}").map_err(|error| {
        Error::failure(format!("failed to write vendor change message: {error}"))
    })?;
    confirm(mode, terminal, input, output)
}

fn confirm(
    mode: Mode,
    terminal: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    if matches!(mode, Mode::AcceptAll) {
        return Ok(());
    }
    if !terminal {
        return Err(Error::failure(
            "dependency change requires confirmation, but no interactive terminal is available",
        )
        .with_help(
            "rerun the command from an interactive terminal and review the displayed graph",
        ));
    }
    write!(
        output,
        "Approve this dependency and capability change? [y/N]: "
    )
    .and_then(|()| output.flush())
    .map_err(|error| {
        Error::failure(format!("failed to write dependency change prompt: {error}"))
    })?;
    let response =
        prompt::read_answer(input, output, prompt::echo_required(terminal)).map_err(|error| {
            Error::failure(format!(
                "failed to read dependency change approval: {error}"
            ))
        })?;
    if matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(Error::failure("dependency change approval was declined"))
    }
}

fn write_review_difference(
    output: &mut impl Write,
    previous: &Review,
    next: &Review,
) -> Result<()> {
    if previous.scope != next.scope {
        writeln!(
            output,
            "  - review scope: {:?}\n  + review scope: {:?}",
            previous.scope, next.scope
        )
        .map_err(|error| Error::failure(format!("failed to write review scope: {error}")))?;
    }
    write_difference(
        output,
        "direct requirement",
        &previous.direct_registry,
        &next.direct_registry,
        |value| (value.alias.clone(), value.kind, value.target.clone()),
    )?;
    write_difference(
        output,
        "direct Git requirement",
        &previous.direct_git,
        &next.direct_git,
        |value| (value.alias.clone(), value.kind, value.target.clone()),
    )?;
    write_difference(
        output,
        "root feature",
        &previous.root_features,
        &next.root_features,
        |value| value.name.clone(),
    )?;
    write_difference(
        output,
        "crates.io patch",
        &previous.crates_io_patches,
        &next.crates_io_patches,
        |value| value.alias.clone(),
    )?;
    write_difference(
        output,
        "locked package",
        &previous.locked_registry,
        &next.locked_registry,
        |value| value.name.clone(),
    )?;
    write_difference(
        output,
        "locked Git package",
        &previous.locked_git,
        &next.locked_git,
        |value| value.name.clone(),
    )?;
    write_difference(
        output,
        "context",
        &previous.contexts,
        &next.contexts,
        |value| (value.host.clone(), value.target.clone()),
    )?;
    write_difference(
        output,
        "context package",
        &previous.context_registry,
        &next.context_registry,
        |value| (value.host.clone(), value.target.clone(), value.name.clone()),
    )?;
    write_difference(
        output,
        "Git context package",
        &previous.context_git,
        &next.context_git,
        |value| (value.host.clone(), value.target.clone(), value.name.clone()),
    )?;
    write_difference(
        output,
        "source evidence",
        &previous.registry_sources,
        &next.registry_sources,
        |value| value.name.clone(),
    )?;
    write_difference(
        output,
        "Git source evidence",
        &previous.git_sources,
        &next.git_sources,
        |value| value.name.clone(),
    )?;
    write_difference(
        output,
        "capability",
        &previous.capabilities,
        &next.capabilities,
        |value| value.package.clone(),
    )
}

fn write_difference<T, K>(
    output: &mut impl Write,
    label: &str,
    previous: &[T],
    next: &[T],
    change_key: impl Fn(&T) -> K,
) -> Result<()>
where
    T: Ord + std::fmt::Debug,
    K: Ord,
{
    let mut removed = Vec::new();
    let mut added = Vec::new();
    let (mut previous_index, mut next_index) = (0, 0);
    while previous_index < previous.len() && next_index < next.len() {
        match previous[previous_index].cmp(&next[next_index]) {
            std::cmp::Ordering::Less => {
                removed.push(&previous[previous_index]);
                previous_index += 1;
            }
            std::cmp::Ordering::Greater => {
                added.push(&next[next_index]);
                next_index += 1;
            }
            std::cmp::Ordering::Equal => {
                previous_index += 1;
                next_index += 1;
            }
        }
    }
    removed.extend(&previous[previous_index..]);
    added.extend(&next[next_index..]);

    let mut matches = BTreeMap::<K, (usize, Vec<usize>)>::new();
    for value in &removed {
        matches.entry(change_key(value)).or_default().0 += 1;
    }
    for (index, value) in added.iter().enumerate() {
        matches.entry(change_key(value)).or_default().1.push(index);
    }
    let mut paired_additions = vec![false; added.len()];
    for value in removed {
        write_difference_line(output, '-', label, value)?;
        let Some((1, additions)) = matches.get(&change_key(value)) else {
            continue;
        };
        if additions.len() == 1 {
            let index = additions[0];
            write_difference_line(output, '+', label, added[index])?;
            paired_additions[index] = true;
        }
    }
    for (index, value) in added.into_iter().enumerate() {
        if !paired_additions[index] {
            write_difference_line(output, '+', label, value)?;
        }
    }
    Ok(())
}

fn write_difference_line(
    output: &mut impl Write,
    sign: char,
    label: &str,
    value: &impl std::fmt::Debug,
) -> Result<()> {
    writeln!(output, "  {sign} {label}: {value:?}").map_err(|error| {
        Error::failure(format!("failed to write dependency change review: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_state::RegistrySource;

    #[test]
    fn json_review_is_one_message_and_nonterminal_confirmation_never_reads() {
        let review = Review {
            resolver_version: 2,
            contexts: vec![crate::admission_state::Context {
                host: "host".to_owned(),
                target: "target".to_owned(),
            }],
            ..Review::default()
        };
        struct NoInput;
        impl std::io::Read for NoInput {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("nonterminal review must not read input");
            }
        }
        impl BufRead for NoInput {
            fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
                panic!("nonterminal review must not read input");
            }
            fn consume(&mut self, _: usize) {
                panic!("nonterminal review must not consume input");
            }
        }
        for (mode, accepted) in [(Mode::Forced, false), (Mode::AcceptAll, true)] {
            let mut output = Vec::new();
            let result = approve_json(None, None, &review, mode, false, &mut NoInput, &mut output);
            assert_eq!(result.is_ok(), accepted);
            let message: serde_json::Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(message["reason"], "lorry-vendor-change");
            assert_eq!(message["previous_review_available"], true);
            assert_eq!(message["added"], serde_json::json!([]));
            assert_eq!(message["capabilities_removed"], serde_json::json!([]));
            assert!(
                message["review"]
                    .as_str()
                    .unwrap()
                    .contains("resolver-version = 2")
            );
            assert_eq!(String::from_utf8(output).unwrap().lines().count(), 1);
        }
    }

    #[test]
    fn pairs_changed_review_items_before_unpaired_additions() {
        let source = |version: &str, checksum: &str| RegistrySource {
            name: "example".to_owned(),
            version: version.to_owned(),
            checksum: checksum.repeat(64),
            license: "MIT".to_owned(),
            source_tree_sha256: checksum.repeat(64),
            build_script: false,
            proc_macro: false,
        };
        let previous = Review {
            registry_sources: vec![source("1.0.0", "1")],
            ..Review::default()
        };
        let next = Review {
            registry_sources: vec![
                source("2.0.0", "2"),
                RegistrySource {
                    name: "new-package".to_owned(),
                    version: "1.0.0".to_owned(),
                    checksum: "3".repeat(64),
                    license: "MIT".to_owned(),
                    source_tree_sha256: "3".repeat(64),
                    build_script: false,
                    proc_macro: false,
                },
            ],
            ..Review::default()
        };
        let mut output = Vec::new();
        let error = approve(
            Some(&previous),
            &"0".repeat(64),
            &next,
            Mode::Change,
            false,
            &mut "".as_bytes(),
            &mut output,
        )
        .unwrap_err();
        assert!(error.render().contains("interactive terminal"));
        let output = String::from_utf8(output).unwrap();
        let removal = output.find("- source evidence").unwrap();
        let changed_addition = output[removal..].find("+ source evidence").unwrap() + removal;
        let unpaired_addition = output.find("new-package").unwrap();
        assert!(removal < changed_addition);
        assert!(changed_addition < unpaired_addition, "{output}");
        assert!(!output[removal..changed_addition].contains("new-package"));
    }

    #[test]
    fn forced_review_prompts_once_and_automation_approves_without_input() {
        let review = Review::default();
        let mut output = Vec::new();
        let error = approve(
            Some(&review),
            &"0".repeat(64),
            &review,
            Mode::Forced,
            true,
            &mut "\n".as_bytes(),
            &mut output,
        )
        .unwrap_err();
        assert!(error.render().contains("approval was declined"));
        assert_eq!(
            String::from_utf8(output).unwrap().matches("[y/N]").count(),
            1
        );

        let mut output = Vec::new();
        approve(
            Some(&review),
            &"0".repeat(64),
            &review,
            Mode::AcceptAll,
            false,
            &mut "".as_bytes(),
            &mut output,
        )
        .unwrap();
        assert!(output.is_empty());
    }
}
