use std::{
    io::{self, Write},
    path::Path,
};

use gix::bstr::ByteSlice;

use crate::cancellation::Cancellation;

const MAX_RECORD_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Incomplete,
    Ready,
    Publishing,
    /// A rebase waits with a clean worktree: `rebase --continue` goes on.
    Paused,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Incomplete => "incomplete",
            State::Ready => "ready",
            State::Publishing => "publishing",
            State::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Switch,
    FastForward,
    Merge,
    Rebase(Rebase),
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Switch => "switch",
            Kind::FastForward => "fast-forward",
            Kind::Merge => "merge",
            Kind::Rebase(_) => "rebase",
        }
    }
}

/// What a rebase record holds besides the fields of every record.
///
/// For a rebase, `Record::original` is HEAD before the step in progress, and
/// `Record::target_commit` is the commit HEAD is detached at after it. Between steps both
/// name the same commit. `Record::result_tree` is the tree that the step installs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rebase {
    /// The tip of the branch before the rebase. The branch stays there until the rebase ends.
    pub original: gix::ObjectId,
    /// The upstream commit that the branch is rebased onto.
    pub onto: gix::ObjectId,
    /// Where the branch left the upstream.
    pub base: gix::ObjectId,
    /// The commit to replay next. While `Ready` it is the commit whose conflicts are
    /// installed. `None` when every commit was replayed.
    pub next: Option<gix::ObjectId>,
    /// What an `Incomplete` record was doing.
    pub step: Option<Step>,
}

/// The steps of a rebase that write files, and so need recovery when interrupted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// Move to `Record::target_commit`. Recovery ends there, `Paused`, with a clean worktree.
    Pause,
    /// Return to the branch at `Rebase::original`.
    Abort,
}

impl Step {
    fn as_str(self) -> &'static str {
        match self {
            Step::Pause => "pause",
            Step::Abort => "abort",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Original {
    pub reference: Option<gix::refs::FullName>,
    pub id: Option<gix::ObjectId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub state: State,
    pub kind: Kind,
    pub original: Original,
    pub target_ref: gix::refs::FullName,
    pub target_commit: gix::ObjectId,
    pub result_tree: gix::ObjectId,
    pub intended_commit: Option<gix::ObjectId>,
}

impl Record {
    pub fn description(&self) -> String {
        format!("{} {}", self.kind.as_str(), self.state.as_str())
    }

    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        // Fixed fields, newlines and the eight SHA-1 IDs of a rebase fit in 768 bytes.
        let refs_len = self
            .original
            .reference
            .as_ref()
            .map_or(0, |name| name.as_bstr().len())
            .checked_add(self.target_ref.as_bstr().len())
            .and_then(|len| len.checked_add(768))
            .ok_or_else(|| invalid("record length overflow"))?;
        if refs_len > MAX_RECORD_BYTES {
            return Err(invalid("record exceeds 64 KiB"));
        }
        let mut out = Vec::new();
        out.try_reserve_exact(refs_len)
            .map_err(|source| io::Error::new(io::ErrorKind::OutOfMemory, source))?;
        // Only rebase records have version 2, so older programs refuse them and nothing else.
        let version: &[u8] = match self.kind {
            Kind::Rebase(_) => b"2",
            _ => b"1",
        };
        field(&mut out, b"version=", version);
        field(&mut out, b"state=", self.state.as_str().as_bytes());
        field(&mut out, b"kind=", self.kind.as_str().as_bytes());
        field(
            &mut out,
            b"original-ref=",
            self.original
                .reference
                .as_ref()
                .map_or(b"-".as_slice(), |name| name.as_bstr().as_bytes()),
        );
        id_field(&mut out, b"original-id=", self.original.id)?;
        field(
            &mut out,
            b"target-ref=",
            self.target_ref.as_bstr().as_bytes(),
        );
        id_field(&mut out, b"target-commit=", Some(self.target_commit))?;
        id_field(&mut out, b"result-tree=", Some(self.result_tree))?;
        id_field(&mut out, b"intended-commit=", self.intended_commit)?;
        if let Kind::Rebase(rebase) = self.kind {
            id_field(&mut out, b"rebase-original=", Some(rebase.original))?;
            id_field(&mut out, b"rebase-onto=", Some(rebase.onto))?;
            id_field(&mut out, b"rebase-base=", Some(rebase.base))?;
            id_field(&mut out, b"rebase-next=", rebase.next)?;
            let step = rebase.step.map_or("-", Step::as_str);
            field(&mut out, b"rebase-step=", step.as_bytes());
        }
        if out.len() > MAX_RECORD_BYTES {
            return Err(invalid("record exceeds 64 KiB"));
        }
        Ok(out)
    }

    fn validate(&self) -> io::Result<()> {
        if self.original.reference.is_none() && self.original.id.is_none() {
            return Err(invalid(
                "original HEAD has neither a reference nor an object",
            ));
        }
        gix::validate::reference::branch_name(self.target_ref.as_bstr())
            .map_err(|error| invalid(format!("invalid target branch: {error}")))?;
        if !matches!(
            self.target_ref.category(),
            Some(gix::refs::Category::LocalBranch)
        ) {
            return Err(invalid("target is not a local branch"));
        }
        let rebase = match self.kind {
            Kind::Rebase(rebase) => Some(rebase),
            _ => None,
        };
        for id in [
            self.original.id,
            Some(self.target_commit),
            Some(self.result_tree),
            self.intended_commit,
            rebase.map(|rebase| rebase.original),
            rebase.map(|rebase| rebase.onto),
            rebase.map(|rebase| rebase.base),
            rebase.and_then(|rebase| rebase.next),
        ]
        .into_iter()
        .flatten()
        {
            if id.kind() != gix::hash::Kind::Sha1 {
                return Err(invalid("object ID is not SHA-1"));
            }
        }
        if let Some(rebase) = rebase {
            return self.validate_rebase(rebase);
        }
        if self.state == State::Paused {
            return Err(invalid("only a rebase may be paused"));
        }
        let is_merge = self.kind == Kind::Merge;
        if matches!(self.kind, Kind::FastForward | Kind::Merge)
            && self.original.reference.as_ref() != Some(&self.target_ref)
        {
            return Err(invalid(
                "fast-forward and merge must advance the original attached branch",
            ));
        }
        if is_merge && self.original.id.is_none() {
            return Err(invalid("merge requires a born original HEAD"));
        }
        if matches!(self.state, State::Ready | State::Publishing) && !is_merge {
            return Err(invalid("only merge operations may be ready or publishing"));
        }
        if (self.state == State::Publishing) != self.intended_commit.is_some() {
            return Err(invalid(
                "an intended commit is present exactly while publishing",
            ));
        }
        Ok(())
    }

    fn validate_rebase(&self, rebase: Rebase) -> io::Result<()> {
        if (self.state == State::Publishing) != self.intended_commit.is_some() {
            return Err(invalid(
                "an intended commit is present exactly while publishing",
            ));
        }
        if (self.state == State::Incomplete) != rebase.step.is_some() {
            return Err(invalid("a rebase has a step exactly while incomplete"));
        }
        let detached = Original {
            reference: None,
            id: Some(self.target_commit),
        };
        match self.state {
            // Before its first step a rebase is on its branch, at the original commit.
            State::Incomplete => {
                let on_branch = self.original.reference.as_ref() == Some(&self.target_ref)
                    && self.original.id == Some(rebase.original);
                if !on_branch && (self.original.reference.is_some() || self.original.id.is_none()) {
                    return Err(invalid(
                        "a rebase step starts on the rebased branch or on a detached HEAD",
                    ));
                }
            }
            State::Ready | State::Publishing | State::Paused => {
                if self.original != detached {
                    return Err(invalid("a stopped rebase has HEAD detached at its commit"));
                }
            }
        }
        if matches!(self.state, State::Ready | State::Publishing) && rebase.next.is_none() {
            return Err(invalid("a rebase stopped at a conflict names its commit"));
        }
        Ok(())
    }
}

/// Parse and structurally validate an operation record.
///
/// Recovery must still validate recorded objects and live references before writes.
pub fn read(path: &Path) -> io::Result<Option<Record>> {
    let mut options = gix::features::fs::open_options_no_follow();
    let file = match options.read(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let data =
        gix::features::fs::read_to_end_bounded(&file, MAX_RECORD_BYTES).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("invalid gix operation record: {error}"),
            )
        })?;
    parse(&data).map(Some)
}

/// Require every object named by an operation record to retain its recorded type and hash.
pub(crate) fn require_objects(
    repo: &gix::Repository,
    record: &Record,
    cancellation: &Cancellation,
) -> crate::Result {
    if let Some(id) = record.original.id {
        checked_object(repo, id, cancellation)?
            .try_into_commit()?
            .decode()?;
    }
    let target = checked_object(repo, record.target_commit, cancellation)?.try_into_commit()?;
    let target_tree = target.decode()?.tree();
    checked_object(repo, record.result_tree, cancellation)?
        .try_into_tree()?
        .decode()?;
    let rebase = match record.kind {
        Kind::Rebase(rebase) => Some(rebase),
        _ => None,
    };
    // A merge, or a rebase stopped at a conflict, installs a tree that no commit has yet.
    let between_commits = record.kind == Kind::Merge || rebase.is_some();
    if !between_commits && target_tree != record.result_tree {
        return Err(object_invalid("recorded result tree does not match the target commit").into());
    }
    for id in [
        rebase.map(|rebase| rebase.original),
        rebase.map(|rebase| rebase.onto),
        rebase.map(|rebase| rebase.base),
        rebase.and_then(|rebase| rebase.next),
    ]
    .into_iter()
    .flatten()
    {
        checked_object(repo, id, cancellation)?
            .try_into_commit()?
            .decode()?;
    }
    if let Some(id) = record.intended_commit {
        let intended = checked_object(repo, id, cancellation)?.try_into_commit()?;
        let decoded = intended.decode()?;
        let born = record.original.id.expect("publishing has a born original");
        // A merge commit joins both sides. A replayed commit follows the detached HEAD.
        let parents: &[gix::ObjectId] = match rebase {
            Some(_) => &[record.target_commit],
            None => &[born, record.target_commit],
        };
        if !decoded.parents().eq(parents.iter().copied()) {
            return Err(object_invalid("recorded intended commit has different parents").into());
        }
    }
    cancellation.check()
}

fn checked_object<'repo>(
    repo: &'repo gix::Repository,
    id: gix::ObjectId,
    cancellation: &Cancellation,
) -> crate::Result<gix::Object<'repo>> {
    cancellation.check()?;
    let object = repo.find_object(id)?;
    if gix::objs::compute_hash(repo.object_hash(), object.kind, &object.data)? != id {
        return Err(object_invalid(format!(
            "recorded object {id} has a mismatched content hash"
        ))
        .into());
    }
    cancellation.check()?;
    Ok(object)
}

fn object_invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub(crate) fn validate_transition(current: &Record, next: &Record) -> io::Result<()> {
    current.validate()?;
    next.validate()?;
    if let (Kind::Rebase(before), Kind::Rebase(after)) = (current.kind, next.kind) {
        // Each step of a rebase moves HEAD, so only the rebase itself stays the same.
        if current.target_ref != next.target_ref
            || (before.original, before.onto, before.base)
                != (after.original, after.onto, after.base)
        {
            return Err(invalid("rebase identity changed during a state update"));
        }
        let allowed = matches!(
            (current.state, next.state),
            (
                State::Incomplete,
                State::Ready | State::Paused | State::Incomplete
            ) | (
                State::Ready,
                State::Incomplete | State::Publishing | State::Paused
            ) | (State::Publishing, State::Ready | State::Paused)
                | (State::Paused, State::Incomplete | State::Paused)
        );
        if !allowed {
            return Err(invalid("unsupported rebase state transition"));
        }
        return Ok(());
    }
    if current.kind != next.kind
        || current.original != next.original
        || current.target_ref != next.target_ref
        || current.target_commit != next.target_commit
        || current.result_tree != next.result_tree
    {
        return Err(invalid("operation identity changed during a state update"));
    }
    let allowed = matches!(
        (current.state, next.state),
        (State::Incomplete, State::Ready)
            | (State::Ready, State::Publishing)
            | (State::Publishing, State::Ready)
            | (State::Ready, State::Incomplete)
    );
    if !allowed {
        return Err(invalid("unsupported operation state transition"));
    }
    Ok(())
}

fn parse(data: &[u8]) -> io::Result<Record> {
    let Some(lines) = data.strip_suffix(b"\n") else {
        return Err(invalid("missing final newline"));
    };
    let mut lines = lines.split(|byte| *byte == b'\n');
    let version = next(&mut lines, b"version=")?;
    if version != b"1" && version != b"2" {
        return Err(invalid("unsupported version"));
    }
    let state = match next(&mut lines, b"state=")? {
        b"incomplete" => State::Incomplete,
        b"ready" => State::Ready,
        b"publishing" => State::Publishing,
        b"paused" => State::Paused,
        _ => return Err(invalid("unknown state")),
    };
    let kind = next(&mut lines, b"kind=")?;
    // The version follows from the kind, so each record has exactly one encoding.
    if (version == b"2") != (kind == b"rebase") {
        return Err(invalid("version does not match the kind"));
    }
    let original_ref = optional_ref(next(&mut lines, b"original-ref=")?)?;
    let original_id = optional_id(next(&mut lines, b"original-id=")?)?;
    let target_ref = required_ref(next(&mut lines, b"target-ref=")?)?;
    let target_commit = required_id(next(&mut lines, b"target-commit=")?)?;
    let result_tree = required_id(next(&mut lines, b"result-tree=")?)?;
    let intended_commit = optional_id(next(&mut lines, b"intended-commit=")?)?;
    let kind = match kind {
        b"switch" => Kind::Switch,
        b"fast-forward" => Kind::FastForward,
        b"merge" => Kind::Merge,
        b"rebase" => Kind::Rebase(Rebase {
            original: required_id(next(&mut lines, b"rebase-original=")?)?,
            onto: required_id(next(&mut lines, b"rebase-onto=")?)?,
            base: required_id(next(&mut lines, b"rebase-base=")?)?,
            next: optional_id(next(&mut lines, b"rebase-next=")?)?,
            step: match next(&mut lines, b"rebase-step=")? {
                b"-" => None,
                b"pause" => Some(Step::Pause),
                b"abort" => Some(Step::Abort),
                _ => return Err(invalid("unknown rebase step")),
            },
        }),
        _ => return Err(invalid("unknown kind")),
    };
    if lines.next().is_some() {
        return Err(invalid("unexpected trailing fields"));
    }
    let record = Record {
        state,
        kind,
        original: Original {
            reference: original_ref,
            id: original_id,
        },
        target_ref,
        target_commit,
        result_tree,
        intended_commit,
    };
    record.validate()?;
    Ok(record)
}

fn next<'a>(lines: &mut impl Iterator<Item = &'a [u8]>, prefix: &[u8]) -> io::Result<&'a [u8]> {
    lines
        .next()
        .and_then(|line| line.strip_prefix(prefix))
        .ok_or_else(|| invalid("missing or out-of-order field"))
}

fn optional_ref(value: &[u8]) -> io::Result<Option<gix::refs::FullName>> {
    if value == b"-" {
        Ok(None)
    } else {
        required_ref(value).map(Some)
    }
}

fn required_ref(value: &[u8]) -> io::Result<gix::refs::FullName> {
    gix::refs::FullName::try_from(value.as_bstr())
        .map_err(|error| invalid(format!("invalid reference: {error}")))
}

fn optional_id(value: &[u8]) -> io::Result<Option<gix::ObjectId>> {
    if value == b"-" {
        Ok(None)
    } else {
        required_id(value).map(Some)
    }
}

fn required_id(value: &[u8]) -> io::Result<gix::ObjectId> {
    if value.len() != 40 {
        return Err(invalid("object ID is not 40 hexadecimal bytes"));
    }
    gix::ObjectId::from_hex(value).map_err(|error| invalid(format!("invalid object ID: {error}")))
}

fn field(out: &mut Vec<u8>, prefix: &[u8], value: &[u8]) {
    out.extend_from_slice(prefix);
    out.extend_from_slice(value);
    out.push(b'\n');
}

fn id_field(out: &mut Vec<u8>, prefix: &[u8], id: Option<gix::ObjectId>) -> io::Result<()> {
    out.extend_from_slice(prefix);
    match id {
        Some(id) => write!(out, "{id}")?,
        None => out.push(b'-'),
    }
    out.push(b'\n');
    Ok(())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid gix operation record: {}", message.into()),
    )
}
