use std::io::{BufRead, Write};

use crate::admission_state::Review;
use crate::diagnostic::{Error, Result};
use crate::prompt;

pub(crate) mod workspace;

#[derive(Clone, Copy)]
pub enum Mode {
    Change,
    Forced,
    AcceptAll,
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
    let packages = |review: &Review| {
        review
            .registry_sources
            .iter()
            .map(|package| {
                serde_json::json!({
                    "name": package.name, "version": package.version,
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "checksum": package.id, "source_tree_sha256": package.source_tree_sha256,
                    "license": package.license, "build_script": package.build_script,
                    "proc_macro": package.proc_macro,
                })
            })
            .chain(review.git_sources.iter().map(|package| {
                serde_json::json!({
                    "name": package.name, "version": package.version, "source": package.id,
                    "checksum": null, "source_tree_sha256": package.source_tree_sha256,
                    "license": package.license, "build_script": package.build_script,
                    "proc_macro": package.proc_macro,
                })
            }))
            .collect::<Vec<_>>()
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
                    "caller_env": capability.caller_env,
                    "native_tools": capability.native_tools.iter().map(|role| match role {
                        crate::config::NativeToolRole::CCompiler => "c-compiler",
                        crate::config::NativeToolRole::CxxCompiler => "cxx-compiler",
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::admission_state::SourceEvidence;

    #[test]
    fn json_reports_changed_execution_and_native_tool_grants() {
        use crate::admission_state::{
            Capability, Context, ContextPackage, LockedRegistry, UnitKind,
        };
        use crate::config::NativeToolRole;
        let checksum = "1".repeat(64);
        let mut previous = Review {
            resolver_version: 2,
            contexts: vec![Context {
                host: "host".to_owned(),
                target: "target".to_owned(),
            }],
            locked_registry: vec![LockedRegistry {
                name: "helper".to_owned(),
                version: "1.0.0".to_owned(),
                id: checksum.clone(),
                dependencies: vec![],
            }],
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
                license: "MIT".to_owned(),
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
                caller_env: Vec::new(),
            }])
            .unwrap();
        let mut next = previous.clone();
        let key = crate::resolver::PackageKey {
            name: "helper".to_owned(),
            version: semver::Version::new(1, 0, 0),
            source: crate::resolver::PackageSourceKey::CratesIo,
        };
        let package = crate::resolver::ResolvedPackage {
            key: key.clone(),
            source: crate::resolver::ResolvedSource::CratesIo {
                checksum: crate::hash::decode_hex(&checksum).unwrap(),
            },
            local_manifest: None,
            feature_sets: BTreeMap::new(),
            compile_kinds: Default::default(),
            host_features: Default::default(),
            target_features: Default::default(),
            edges: vec![],
            lock_edges: vec![],
        };
        let evidence = crate::policy::PackageEvidence {
            license: "MIT".to_owned(),
            build_script: true,
            proc_macro: true,
            newly_acquired: false,
            archive_bytes: Some(1),
            extracted_bytes: 1,
            file_count: 1,
            source_tree_sha256: [2; 32],
        };
        next.complete(
            crate::admission_state::capabilities_from(
                &crate::resolver::Resolution {
                    root_edges: vec![],
                    packages: vec![package],
                },
                &BTreeMap::from([(key.clone(), evidence)]),
                &crate::policy::Admission {
                    packages: BTreeMap::from([(
                        key,
                        crate::policy::PackageAdmission {
                            caller_env: ["EMPTY".into(), "PUBLIC".into()].into(),
                            native_tools: [NativeToolRole::CCompiler, NativeToolRole::Archiver]
                                .into(),
                            configured_native_tools: false,
                        },
                    )]),
                },
            )
            .unwrap(),
        )
        .unwrap();
        let mut output = Vec::new();
        approve_json(
            Some(&previous),
            Some(&previous.commitment().unwrap()),
            &next,
            Mode::AcceptAll,
            false,
            &mut "".as_bytes(),
            &mut output,
        )
        .unwrap();
        let message: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(message["added"], serde_json::json!([]));
        assert_eq!(message["removed"], serde_json::json!([]));
        assert_eq!(message["capabilities_removed"][0]["proc_macro"], false);
        assert_eq!(
            message["capabilities_removed"][0]["native_tools"],
            serde_json::json!(["c-compiler"])
        );
        assert_eq!(message["capabilities_added"][0]["proc_macro"], true);
        assert_eq!(
            message["capabilities_added"][0]["native_tools"],
            serde_json::json!(["archiver", "c-compiler"])
        );
        assert_eq!(message["capabilities_added"][0]["checksum"], checksum);
        assert_eq!(
            message["capabilities_removed"][0]["caller_env"],
            serde_json::json!([])
        );
        assert_eq!(
            message["capabilities_added"][0]["caller_env"],
            serde_json::json!(["EMPTY", "PUBLIC"])
        );
        assert_eq!(
            message["review"],
            String::from_utf8(next.render().unwrap()).unwrap()
        );
        assert_eq!(String::from_utf8(output).unwrap().lines().count(), 1);
        let mut caller_only = previous.clone();
        caller_only.capabilities[0].caller_env = vec!["PUBLIC".into()];
        let mut output = Vec::new();
        approve_json(
            Some(&previous),
            None,
            &caller_only,
            Mode::AcceptAll,
            false,
            &mut std::io::Cursor::new([]),
            &mut output,
        )
        .unwrap();
        let message: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(message["capabilities_added"].as_array().unwrap().len(), 1);
        assert_eq!(message["capabilities_removed"].as_array().unwrap().len(), 1);
        assert_eq!(
            message["capabilities_added"][0]["caller_env"],
            serde_json::json!(["PUBLIC"])
        );
    }

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
}
