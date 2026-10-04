use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use semver::{Comparator, Op, Version as SemVersion, VersionReq};

use super::Version;
use crate::diagnostic::{Error, Result};
use crate::glob::Pattern;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PackageSelection {
    pub packages: Vec<String>,
    pub workspace: bool,
    pub exclude: Vec<String>,
}

impl PackageSelection {
    pub(super) fn single(package: Option<&str>) -> Self {
        Self {
            packages: package.into_iter().map(str::to_owned).collect(),
            ..Self::default()
        }
    }

    pub(super) fn select_one<'a>(
        &self,
        members: impl Iterator<Item = (&'a str, &'a Version, &'a Path)>,
        defaults: impl Iterator<Item = &'a Path>,
    ) -> Result<(PathBuf, Vec<String>)> {
        let (mut selected, warnings) = self.select(members, defaults)?;
        match selected.len() {
            1 => Ok((selected.pop().unwrap(), warnings)),
            count => Err(Error::failure(format!(
                "package selection selects {count} packages; multi-package execution is not yet supported"
            ))
            .with_help("select one workspace package with `-p NAME`")),
        }
    }

    pub(crate) fn select<'a>(
        &self,
        members: impl Iterator<Item = (&'a str, &'a Version, &'a Path)>,
        defaults: impl Iterator<Item = &'a Path>,
    ) -> Result<(Vec<PathBuf>, Vec<String>)> {
        let members = members.collect::<Vec<_>>();
        let available = || {
            format!(
                "available workspace packages: {}",
                members
                    .iter()
                    .map(|member| member.0)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let requested = |name: &str| -> Result<Vec<PathBuf>> {
            let selected = matching(members.iter().copied(), name)?;
            if selected.is_empty() {
                Err(Error::failure(format!(
                    "package selector `{name}` did not match any workspace package"
                ))
                .with_help(available()))
            } else {
                Ok(selected)
            }
        };
        if !self.workspace && !self.exclude.is_empty() {
            return Err(Error::failure(
                "--exclude can only be used together with --workspace",
            ));
        }
        let mut warnings = Vec::new();
        let mut selected = BTreeSet::new();
        if self.workspace {
            selected.extend(members.iter().map(|member| member.2.to_owned()));
            if self.exclude.is_empty() {
                for name in &self.packages {
                    requested(name)?;
                }
            } else {
                // Cargo's opt-out selection takes precedence over any -p options.
                for name in &self.exclude {
                    let excluded = matching(members.iter().copied(), name)?;
                    if excluded.is_empty() {
                        warnings.push(format!(
                            "excluded package selector `{name}` not found in workspace"
                        ));
                    }
                    for member in excluded {
                        selected.remove(&member);
                    }
                }
            }
        } else if self.packages.is_empty() {
            selected.extend(defaults.map(Path::to_owned));
        } else {
            for name in &self.packages {
                selected.extend(requested(name)?);
            }
        }
        if selected.is_empty() {
            return Err(Error::failure(
                "package selection contains no packages to compile",
            ));
        }
        Ok((selected.into_iter().collect(), warnings))
    }
}

enum VersionSpec {
    Full(SemVersion),
    Partial(Comparator),
}

impl VersionSpec {
    fn parse(value: &str) -> Result<Self> {
        if let Ok(version) = SemVersion::parse(value) {
            return Ok(Self::Full(version));
        }
        if let Ok(mut requirement) = VersionReq::parse(value)
            && requirement.comparators.len() == 1
            && !value.starts_with('^')
        {
            let comparator = requirement.comparators.pop().unwrap();
            if comparator.op == Op::Caret {
                return Ok(Self::Partial(comparator));
            }
        }
        Err(Error::failure(format!(
            "invalid package selector version `{value}`"
        )))
    }

    fn matches(&self, version: &Version) -> bool {
        match self {
            Self::Full(expected) => {
                expected.major == version.major
                    && expected.minor == version.minor
                    && expected.patch == version.patch
                    && expected.pre.as_str() == version.pre
                    && (expected.build.is_empty() || expected.build.as_str() == version.build)
            }
            Self::Partial(expected) => {
                expected.major == version.major
                    && expected.minor.is_none_or(|minor| minor == version.minor)
                    && expected.patch.is_none_or(|patch| patch == version.patch)
                    && expected.pre.as_str() == version.pre
            }
        }
    }
}

fn matching<'a>(
    members: impl Iterator<Item = (&'a str, &'a Version, &'a Path)>,
    requested: &str,
) -> Result<Vec<PathBuf>> {
    let (source, fragment) = if requested.contains("://") {
        let requested = requested.strip_prefix("path+").unwrap_or(requested);
        let (source, fragment) = requested
            .split_once('#')
            .map_or((requested, None), |(source, fragment)| {
                (source, Some(fragment))
            });
        if !source.starts_with("file://") || source.contains('?') {
            return Err(Error::failure(
                "only workspace file package IDs can select workspace members",
            ));
        }
        (
            Some(source),
            fragment.unwrap_or_else(|| source.rsplit('/').next().unwrap()),
        )
    } else {
        (None, requested)
    };
    let (name, version) = match fragment
        .rsplit_once('@')
        .or_else(|| fragment.rsplit_once(':'))
    {
        Some((name, version)) => (name, Some(VersionSpec::parse(version)?)),
        None if source.is_some()
            && fragment
                .chars()
                .next()
                .is_some_and(|value| value.is_ascii_digit()) =>
        {
            (
                source.unwrap().rsplit('/').next().unwrap(),
                Some(VersionSpec::parse(fragment)?),
            )
        }
        None => (fragment, None),
    };
    let pattern = Pattern::parse(name).map_err(Error::failure)?;
    if name.contains(['*', '?', '[', ']']) && (source.is_some() || version.is_some()) {
        return Err(Error::failure(
            "package patterns cannot include versions or source URLs",
        ));
    }
    let mut matches = Vec::new();
    for (candidate, candidate_version, root) in members {
        if !pattern.matches(candidate)
            || version
                .as_ref()
                .is_some_and(|version| !version.matches(candidate_version))
        {
            continue;
        }
        if let Some(source) = source {
            let id = crate::metadata::package::path_package_id(
                root,
                candidate,
                &candidate_version.original,
            )?;
            if id.split_once('#').unwrap().0.strip_prefix("path+").unwrap() != source {
                continue;
            }
        }
        matches.push(root.to_owned());
    }
    Ok(matches)
}
