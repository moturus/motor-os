use crate::diagnostic::{Error, Result};
use crate::manifest::{GitDependency, GitSelector};

mod direct;
mod http;
mod materialize;
mod refresh;

pub(crate) use direct::{
    DirectCatalog, configure_direct, load_locked_dependencies, materialize_locked_dependencies,
};
pub(crate) use refresh::{PatchRefresh, resolve_patch_refreshes};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LockedSource {
    pub cargo_source: String,
    pub url: String,
    pub selector: GitSelector,
    pub commit: String,
}

impl LockedSource {
    pub(crate) fn matches(&self, dependency: &GitDependency) -> bool {
        self.url == dependency.url && self.selector == dependency.selector
    }
}

pub(crate) fn parse_locked_source(source: &str) -> Result<LockedSource> {
    let value = source
        .strip_prefix("git+")
        .ok_or_else(|| Error::failure("Git lock source is missing its `git+` prefix"))?;
    let (remote, commit) = value
        .rsplit_once('#')
        .ok_or_else(|| Error::failure("Git lock source is missing its commit fragment"))?;
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::failure(
            "Git lock source commit is not 40 lowercase hexadecimal digits",
        ));
    }
    let (url, query) = remote
        .split_once('?')
        .map_or((remote, None), |(url, query)| (url, Some(query)));
    validate_git_url(url)?;
    let selector = match query {
        None => GitSelector::Head,
        Some(query) => {
            let (kind, value) = query.split_once('=').ok_or_else(|| {
                Error::failure("Git lock source query is not one branch, tag, or rev selector")
            })?;
            if value.is_empty() || value.contains('&') {
                return Err(Error::failure(
                    "Git lock source query has an empty or multiple selector",
                ));
            }
            let value = percent_decode(value)?;
            validate_revision(&value)?;
            match kind {
                "branch" => GitSelector::Branch(value),
                "tag" => GitSelector::Tag(value),
                "rev" => GitSelector::Revision(value),
                _ => {
                    return Err(Error::failure(format!(
                        "Git lock source has unsupported selector `{kind}`"
                    )));
                }
            }
        }
    };
    Ok(LockedSource {
        cargo_source: source.to_owned(),
        url: url.to_owned(),
        selector,
        commit: commit.to_owned(),
    })
}

fn percent_decode(value: &str) -> Result<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let input = value.as_bytes();
    let mut position = 0;
    while position < input.len() {
        if input[position] != b'%' {
            bytes.push(input[position]);
            position += 1;
            continue;
        }
        let digits = input
            .get(position + 1..position + 3)
            .ok_or_else(|| Error::failure("Git lock source has incomplete percent encoding"))?;
        let high = hex_digit(digits[0])?;
        let low = hex_digit(digits[1])?;
        bytes.push((high << 4) | low);
        position += 3;
    }
    String::from_utf8(bytes)
        .map_err(|_| Error::failure("Git lock source selector is not valid UTF-8"))
}

fn hex_digit(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(Error::failure(
            "Git lock source has invalid percent encoding",
        )),
    }
}

fn validate_git_url(url: &str) -> Result<()> {
    if !url.starts_with("https://")
        || !url.is_ascii()
        || url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || url.contains(['#', '?'])
        || url[8..].contains('@')
    {
        return Err(Error::failure(format!(
            "Git URL `{url}` is not a canonical anonymous HTTPS URL"
        )));
    }
    Ok(())
}

fn validate_revision(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 1024
        || value.starts_with('-')
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.contains("..")
        || value.contains(['~', '^', ':', '?', '*', '[', '\\', ' '])
        || value.ends_with(['.', '/'])
        || value.contains("@{")
    {
        return Err(Error::failure(format!(
            "Git revision `{value}` is not safe"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cargo_git_lock_identity() {
        let source = "git+https://example.com/repository.git?branch=feature%2Fmotor#0123456789abcdef0123456789abcdef01234567";
        let locked = parse_locked_source(source).unwrap();
        assert_eq!(locked.cargo_source, source);
        assert_eq!(locked.url, "https://example.com/repository.git");
        assert_eq!(
            locked.selector,
            GitSelector::Branch("feature/motor".to_owned())
        );
        assert_eq!(locked.commit, "0123456789abcdef0123456789abcdef01234567");

        for invalid in [
            "git+http://example.com/repository#0123456789abcdef0123456789abcdef01234567",
            "git+https://user@example.com/repository#0123456789abcdef0123456789abcdef01234567",
            "git+https://example.com/repository?branch=one&tag=two#0123456789abcdef0123456789abcdef01234567",
            "git+https://example.com/repository#0123456789ABCDEF0123456789ABCDEF01234567",
        ] {
            assert!(
                parse_locked_source(invalid).is_err(),
                "accepted `{invalid}`"
            );
        }
    }
}
