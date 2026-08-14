use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use crate::admission_state::Review;
use crate::diagnostic::{Error, Result};

/// Displays the dependency change for approval. With a reconstructible
/// committed baseline this is a semantic diff. When visible input changes
/// prevent reconstruction, the prior commitment and complete candidate are
/// shown instead.
pub fn approve(
    previous: Option<&Review>,
    previous_sha256: &str,
    next: &Review,
    terminal: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    match previous {
        Some(previous) if previous == next => return Ok(()),
        Some(previous) => {
            writeln!(output, "Dependency upgrade review:").map_err(|error| {
                Error::failure(format!("failed to write upgrade review: {error}"))
            })?;
            write_difference(
                output,
                "direct requirement",
                &previous.direct_registry,
                &next.direct_registry,
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
                "source evidence",
                &previous.registry_sources,
                &next.registry_sources,
                |value| value.name.clone(),
            )?;
            write_difference(
                output,
                "capability",
                &previous.capabilities,
                &next.capabilities,
                |value| value.package.clone(),
            )?;
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
            .map_err(|error| Error::failure(format!("failed to write upgrade review: {error}")))?;
        }
    }
    if !terminal {
        return Err(Error::failure(
            "dependency upgrade requires confirmation, but no interactive terminal is available",
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
    .map_err(|error| Error::failure(format!("failed to write upgrade prompt: {error}")))?;
    let mut response = String::new();
    std::io::Read::take(&mut *input, 65)
        .read_line(&mut response)
        .map_err(|error| Error::failure(format!("failed to read upgrade approval: {error}")))?;
    if matches!(response.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(Error::failure("dependency upgrade approval was declined"))
    }
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
    writeln!(output, "  {sign} {label}: {value:?}")
        .map_err(|error| Error::failure(format!("failed to write upgrade review: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_state::RegistrySource;

    #[test]
    fn pairs_changed_review_items_before_unpaired_additions() {
        let source = |version: &str, checksum: &str| RegistrySource {
            name: "example".to_owned(),
            version: version.to_owned(),
            checksum: checksum.repeat(64),
            license: "MIT".to_owned(),
            source_tree_sha256: checksum.repeat(64),
            build_script: false,
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
                },
            ],
            ..Review::default()
        };
        let mut output = Vec::new();
        let error = approve(
            Some(&previous),
            &"0".repeat(64),
            &next,
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
}
