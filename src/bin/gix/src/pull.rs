//! `gix pull [--ff-only | --rebase | --no-rebase] [REMOTE [BRANCH]]`: fetch, then merge what
//! was fetched or rebase onto it.

use std::{
    collections::HashSet,
    io::{self, Write},
};

use gix::{
    bstr::{BStr, ByteSlice},
    prelude::ObjectIdExt,
    refs::{Category, FullName, FullNameRef},
    refspec::{Instruction, instruction, parse::Operation},
    remote::Direction,
};

use crate::{
    cancellation::Cancellation,
    fetch, head_ref,
    merge::{self, Preparation},
    mutation::Guard,
    network, rebase,
    replay::{self, Range},
    repository::OpenedRepository,
};

/// What `gix pull` was asked to do.
pub struct Request<'a> {
    /// The remote to fetch, instead of the upstream remote of the current branch.
    pub remote: Option<&'a str>,
    /// The remote's branch or tag to merge, instead of the upstream branch.
    pub branch: Option<&'a str>,
    pub ff_only: bool,
    pub rebase: bool,
    pub no_rebase: bool,
}

/// How to join the current branch with what was pulled, chosen the way Git chooses it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Reconcile {
    /// Nothing was chosen: fast-forward, but refuse branches that have diverged.
    Unspecified,
    FastForwardOnly,
    Merge,
    /// `pull.ff = false`: a merge commit even for a fast-forward, which gix cannot make.
    AlwaysMergeCommit,
    Rebase,
    /// The configuration asks for a rebase that keeps merges or is interactive.
    OtherRebase,
}

/// The remote, and the ref on it, to merge.
struct Source {
    /// A configured remote, or `.` for a branch of this repository.
    remote: String,
    /// The ref as the remote names it: the configured full name, or the BRANCH argument.
    branch: String,
}

/// Fetch the upstream of the current branch and merge it, as `git pull` does.
pub fn run(
    opened: &mut OpenedRepository,
    request: Request<'_>,
    policy: &network::Policy,
    mut out: impl Write,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    // One guard covers the fetch and the merge, so nothing changes the repository in between.
    let guard = Guard::acquire(&opened.repo)?;
    let head = head_ref::capture(&opened.repo)?;
    let current = head
        .reference
        .filter(|name| name.category() == Some(Category::LocalBranch))
        .ok_or_else(|| unsupported("pull requires HEAD attached to a local branch"))?;
    let source = source(&opened.repo, current.as_ref(), &request)?;
    let reconcile = reconcile(&opened.repo, current.shorten(), &request)?;
    // Like Git, look for the fork point before the fetch adds to the reflog it is read from.
    let fork_point = match (reconcile, head.id) {
        (Reconcile::Rebase, Some(head)) => match tracking_ref(&opened.repo, &source)? {
            Some(tracking) => fork_point(&opened.repo, tracking.as_ref(), head, cancellation)?,
            None => None,
        },
        _ => None,
    };

    let (name, id, url) = if source.remote == "." {
        let mut reference = opened.repo.find_reference(source.branch.as_str())?;
        let id = reference.peel_to_id()?.detach();
        (reference.name().as_bstr().to_owned(), id, None)
    } else {
        let spec = gix::refspec::parse(source.branch.as_str().into(), Operation::Fetch)?;
        if !matches!(
            spec.instruction(),
            Instruction::Fetch(instruction::Fetch::Only { .. })
        ) {
            return Err(invalid(format!(
                "'{}' does not name a single branch or tag",
                source.branch
            ))
            .into());
        }
        // Fetching installs a generic committer for reflogs when none is configured. Use a
        // copy of the handle, so that a merge commit still requires a configured identity.
        let mut repo = opened.repo.clone();
        let fetched = fetch::fetch(
            &mut repo,
            &source.remote,
            Some(spec.to_owned()),
            policy,
            cancellation,
        )?;
        let [(name, id)] = <[_; 1]>::try_from(fetched.wanted).map_err(|found| {
            let count = if found.is_empty() {
                "no ref"
            } else {
                "several refs"
            };
            invalid(format!(
                "remote '{}' has {count} named '{}'",
                source.remote, source.branch
            ))
        })?;
        (name, id, Some(shown_url(fetched.url)))
    };
    let commit = opened.repo.find_object(id)?.peel_to_commit()?.id;
    cancellation.check()?;

    let diverged = |problem: &str| {
        Err(unsupported(format!(
            "the current branch and what was pulled have diverged; {problem}"
        ))
        .into())
    };
    // The commits a rebase covers and how far their replay got, once there was a rebase.
    let mut rebased = None;
    let shared: &OpenedRepository = opened;
    let planned = merge::plan(
        shared,
        guard,
        commit,
        |original, base| match reconcile {
            Reconcile::Merge | Reconcile::AlwaysMergeCommit => Ok(None),
            Reconcile::FastForwardOnly => diverged("a fast-forward is not possible"),
            Reconcile::OtherRebase => diverged(
                "the configuration asks for a kind of rebase that gix cannot do; \
                 run 'gix pull --rebase' for a plain rebase or 'gix pull --no-rebase' to merge",
            ),
            Reconcile::Unspecified => diverged(
                "run 'gix pull --rebase' to rebase or 'gix pull --no-rebase' to merge, \
                 or set pull.rebase to true or false to choose for every pull",
            ),
            Reconcile::Rebase => {
                // If the upstream still has the fork point, it changes nothing: commits
                // that the upstream has are never replayed. So Git's test for that case
                // is not needed here.
                let base = fork_point.unwrap_or(base);
                let range = Range {
                    original,
                    onto: commit,
                    base,
                };
                let commits = replay::todo(&shared.repo, &range, cancellation)?;
                let replayed = replay::run(shared, &commits, commit, cancellation)?;
                let tip = replayed.tip;
                rebased = Some((range, replayed));
                Ok(Some(tip))
            }
        },
        cancellation,
    )?;
    let action = if request.rebase {
        "pull --rebase"
    } else {
        "pull"
    };
    let dropping = |dropped: &[gix::ObjectId]| -> crate::Result<String> {
        let mut report = String::new();
        for dropped in dropped {
            let label = replay::label(&opened.repo, *dropped)?;
            report.push_str(&format!(
                "dropping {label} -- patch contents already upstream\n"
            ));
        }
        Ok(report)
    };
    // A commit that does not apply stops the rebase where the user can resolve it.
    let rebased = match rebased {
        Some((range, replayed)) => match replayed.stopped {
            Some(stopped) => {
                write!(out, "{}", dropping(&replayed.dropped)?)?;
                out.flush()?;
                return rebase::stop(
                    opened,
                    planned.into_guard(),
                    &current,
                    &range,
                    (replayed.tip, stopped),
                    action,
                    cancellation,
                );
            }
            None => Some(replayed.dropped),
        },
        None => None,
    };
    let mut reflog = format!("{action}: Fast-forward");
    let report = match (planned.preparation(), planned.original_commit()) {
        // Git says it this way when a rebase finds the branch ahead of what was pulled.
        (Preparation::UpToDate, Some(old)) if reconcile == Reconcile::Rebase && old != commit => {
            Some(format!(
                "Current branch {} is up to date.",
                current.shorten()
            ))
        }
        (Preparation::UpToDate, _) => Some("Already up to date.".to_owned()),
        (Preparation::FastForward { .. }, _) if rebased.is_some() => {
            reflog = format!("{action} (finish): {} onto {commit}", current.as_bstr());
            let mut report = dropping(rebased.as_deref().unwrap_or_default())?;
            report.push_str(&format!(
                "Successfully rebased and updated {}.",
                current.as_bstr()
            ));
            Some(report)
        }
        (Preparation::FastForward { .. }, _) if reconcile == Reconcile::AlwaysMergeCommit => {
            return Err(unsupported(
                "pull.ff = false asks for a merge commit, which gix cannot make for \
                 a fast-forward; run 'gix pull --ff-only'",
            )
            .into());
        }
        (Preparation::FastForward { .. }, Some(old)) => Some(format!(
            "Updating {}..{}\nFast-forward",
            old.attach(&opened.repo).shorten_or_id(),
            commit.attach(&opened.repo).shorten_or_id()
        )),
        // An unborn branch simply starts at the pulled commit. Git reports nothing either.
        (Preparation::FastForward { .. }, None) => None,
        (Preparation::Divergent { .. }, _) => Some("Merge made.".to_owned()),
    };
    let message = merge_message(name.as_bstr(), url.as_deref(), current.as_ref());
    merge::install(
        opened,
        planned,
        &message,
        reflog.as_bytes().as_bstr(),
        cancellation,
    )?;
    if let Some(report) = report {
        writeln!(out, "{report}")?;
        out.flush()?;
    }
    Ok(())
}

/// Find what to pull: the arguments, or else the upstream of branch `current`.
fn source(
    repo: &gix::Repository,
    current: &FullNameRef,
    request: &Request<'_>,
) -> crate::Result<Source> {
    if let (Some(remote), Some(branch)) = (request.remote, request.branch) {
        return Ok(Source {
            remote: remote.to_owned(),
            branch: branch.to_owned(),
        });
    }
    let short = current.shorten();
    let configured = repo
        .branch_remote_name(short, Direction::Fetch)
        .zip(repo.branch_remote_ref_name(current, Direction::Fetch));
    let no_upstream = |advice: String| {
        invalid(format!(
            "branch '{}' has no upstream {advice}",
            short.to_str_lossy()
        ))
    };
    let Some((remote, branch)) = configured else {
        return Err(no_upstream("branch; run 'gix pull REMOTE BRANCH'".into()).into());
    };
    let remote = remote.as_bstr().to_str()?;
    match request.remote {
        // Like Git, merge the configured branch only when pulling from its own remote.
        Some(requested) if requested != remote => Err(no_upstream(format!(
            "on remote '{requested}'; run 'gix pull {requested} BRANCH'"
        ))
        .into()),
        _ => Ok(Source {
            remote: remote.to_owned(),
            branch: branch?.as_bstr().to_str()?.to_owned(),
        }),
    }
}

/// The local ref that follows the branch to pull, as the fetch refspecs of its remote
/// place it. Its reflog knows which commits the upstream once had.
fn tracking_ref(repo: &gix::Repository, source: &Source) -> crate::Result<Option<FullName>> {
    let name = match source.branch.starts_with("refs/") {
        true => source.branch.clone(),
        false => format!("refs/heads/{}", source.branch),
    };
    let Ok(name) = FullName::try_from(name) else {
        return Ok(None);
    };
    if source.remote == "." {
        return Ok(repo.try_find_reference(name.as_ref())?.map(|_| name));
    }
    let Some(remote) = repo.try_find_remote(source.remote.as_str()) else {
        return Ok(None);
    };
    let remote = remote?;
    let specs = remote.refspecs(Direction::Fetch).iter();
    let maps = |spec: &gix::refspec::RefSpecRef<'_>| {
        spec.source().is_some() && spec.destination().is_some()
    };
    let group = gix::refspec::MatchGroup {
        specs: specs.map(|spec| spec.to_ref()).filter(maps).collect(),
    };
    let null = repo.object_hash().null();
    let item = gix::refspec::match_group::Item {
        full_ref_name: name.as_bstr(),
        target: &null,
        object: None,
    };
    let mapping = group
        .match_lhs(Some(item).into_iter())
        .mappings
        .into_iter()
        .next();
    Ok(match mapping.and_then(|mapping| mapping.rhs) {
        Some(tracking) => Some(FullName::try_from(tracking.into_owned())?),
        None => None,
    })
}

/// Where the branch at `head` left `tracking`, even if `tracking` was rewritten since: Git's
/// `merge-base --fork-point`.
///
/// The candidates are the commits that the reflog of `tracking` names. The fork point is
/// the one merge base of `head` and all of them, if it is one of them.
fn fork_point(
    repo: &gix::Repository,
    tracking: &FullNameRef,
    head: gix::ObjectId,
    cancellation: &Cancellation,
) -> crate::Result<Option<gix::ObjectId>> {
    let Some(reference) = repo.try_find_reference(tracking)? else {
        return Ok(None);
    };
    // Every commit the ref was at, newest first, and the one before the oldest line.
    let mut named = Vec::new();
    let mut log = reference.log_iter();
    if let Some(lines) = log.rev()? {
        let mut oldest = None;
        for line in lines.take(replay::MAX_COMMITS) {
            cancellation.check()?;
            let line = line?;
            named.push(line.new_oid);
            oldest = Some(line.previous_oid);
        }
        named.extend(oldest);
    }
    // A reflog may name objects that are gone, and a ref may not point to a commit.
    let is_commit = |id: gix::ObjectId| -> crate::Result<bool> {
        let header = repo.try_find_header(id)?;
        Ok(header.is_some_and(|header| header.kind() == gix::objs::Kind::Commit))
    };
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    for id in named {
        if !id.is_null() && seen.insert(id) && is_commit(id)? {
            candidates.push(id);
        }
    }
    if let (true, Some(id)) = (candidates.is_empty(), reference.try_id())
        && is_commit(id.detach())?
    {
        candidates.push(id.detach());
    }
    let bases = repo.merge_bases_many(head, &candidates)?;
    let [base] = bases[..] else {
        return Ok(None);
    };
    let base = base.detach();
    Ok(candidates.contains(&base).then_some(base))
}

/// Read the options and the `pull.ff`, `branch.<name>.rebase` and `pull.rebase` settings
/// with Git's precedence.
fn reconcile(
    repo: &gix::Repository,
    branch: &BStr,
    request: &Request<'_>,
) -> crate::Result<Reconcile> {
    if request.ff_only {
        return Ok(Reconcile::FastForwardOnly);
    }
    let config = repo.config_snapshot();
    let fast_forward = match config.string("pull.ff") {
        // On the command line, `--rebase` and `--no-rebase` override a configured
        // `pull.ff = only`.
        Some(value) if value.as_bstr() == "only" && !request.rebase && !request.no_rebase => {
            return Ok(Reconcile::FastForwardOnly);
        }
        Some(value) if value.as_bstr() == "only" => Some(true),
        Some(value) => Some(gix::config::Boolean::try_from(value.as_bstr())?.0),
        None => None,
    };
    let rebase = if request.rebase || request.no_rebase {
        Some(request.rebase)
    } else {
        match config
            .plumbing()
            .string_by("branch", Some(branch), "rebase")
            .or_else(|| config.string("pull.rebase"))
        {
            Some(value) => match gix::config::Boolean::try_from(value.as_bstr()) {
                Ok(rebase) => Some(rebase.0),
                // Git also accepts `merges` and `interactive`.
                Err(_) => return Ok(Reconcile::OtherRebase),
            },
            None => None,
        }
    };
    Ok(match (rebase, fast_forward) {
        (Some(true), _) => Reconcile::Rebase,
        (_, Some(false)) => Reconcile::AlwaysMergeCommit,
        (Some(false), _) | (_, Some(true)) => Reconcile::Merge,
        (None, None) => Reconcile::Unspecified,
    })
}

/// The message Git gives the merge commit of a pull, such as
/// `Merge branch 'main' of https://example.test/project into topic`.
fn merge_message(name: &BStr, url: Option<&str>, current: &FullNameRef) -> String {
    let name = name.to_str_lossy();
    let (kind, short) = [
        ("refs/heads/", "branch"),
        ("refs/tags/", "tag"),
        ("refs/remotes/", "remote-tracking branch"),
    ]
    .into_iter()
    .find_map(|(prefix, kind)| Some((kind, name.strip_prefix(prefix)?)))
    .unwrap_or(("commit", name.as_ref()));
    let mut message = format!("Merge {kind} '{short}'");
    if let Some(url) = url {
        message.push_str(" of ");
        message.push_str(url);
    }
    // Git leaves out the destination when it is the main branch.
    let current = current.shorten().to_str_lossy();
    if current != "main" && current != "master" {
        message.push_str(" into ");
        message.push_str(&current);
    }
    message
}

/// The URL as Git writes it into a merge message: no credentials, no trailing `/` or `.git`.
fn shown_url(mut url: gix::Url) -> String {
    url.set_user(None);
    url.set_password(None);
    let text = url.to_bstring();
    let text = text.to_str_lossy();
    let text = text.trim_end_matches('/');
    text.strip_suffix(".git").unwrap_or(text).to_owned()
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_message_follows_git() -> crate::Result {
        let url = Some("https://example.test/project");
        for (name, url, current, expected) in [
            (
                "refs/heads/main",
                url,
                "refs/heads/main",
                "Merge branch 'main' of https://example.test/project",
            ),
            (
                "refs/heads/dev",
                url,
                "refs/heads/topic",
                "Merge branch 'dev' of https://example.test/project into topic",
            ),
            (
                "refs/tags/v1",
                url,
                "refs/heads/master",
                "Merge tag 'v1' of https://example.test/project",
            ),
            (
                "refs/pull/7/head",
                url,
                "refs/heads/main",
                "Merge commit 'refs/pull/7/head' of https://example.test/project",
            ),
            (
                "refs/heads/main",
                None,
                "refs/heads/topic",
                "Merge branch 'main' into topic",
            ),
        ] {
            let current: &FullNameRef = current.try_into()?;
            assert_eq!(merge_message(name.into(), url, current), expected);
        }
        Ok(())
    }

    #[test]
    fn shown_url_hides_the_user_and_the_suffix() -> crate::Result {
        for (url, expected) in [
            (
                "https://example.test/group/project.git",
                "https://example.test/group/project",
            ),
            (
                "https://example.test/group/project/",
                "https://example.test/group/project",
            ),
            (
                "ssh://git@example.test/group/project.git/",
                "ssh://example.test/group/project",
            ),
            (
                "git@example.test:group/project.git",
                "example.test:group/project",
            ),
        ] {
            assert_eq!(
                shown_url(gix::url::parse(url.as_bytes().as_bstr())?),
                expected
            );
        }
        Ok(())
    }
}
