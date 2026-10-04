use std::path::{Path, PathBuf};

use semver::{Comparator, Op, Version as SemVersion, VersionReq};

use super::Version;
use crate::diagnostic::{Error, Result};
use crate::glob::Pattern;

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

pub(super) fn select_one<'a>(
    members: impl Iterator<Item = (&'a str, &'a Version, &'a Path)>,
    requested: &str,
) -> Result<PathBuf> {
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
    let mut available = Vec::new();
    for (candidate, candidate_version, root) in members {
        available.push(candidate.to_owned());
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
    match matches.as_slice() {
        [member] => Ok(member.clone()),
        [] => Err(Error::failure(format!(
            "package selector `{requested}` did not match any workspace package"
        ))
        .with_help(format!(
            "available workspace packages: {}",
            available.join(", ")
        ))),
        _ => Err(Error::failure(format!(
            "package selector `{requested}` selects {} packages; multi-package execution is not yet supported",
            matches.len()
        ))),
    }
}
