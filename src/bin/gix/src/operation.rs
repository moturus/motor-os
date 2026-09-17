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
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Incomplete => "incomplete",
            State::Ready => "ready",
            State::Publishing => "publishing",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Switch,
    FastForward,
    Merge,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Switch => "switch",
            Kind::FastForward => "fast-forward",
            Kind::Merge => "merge",
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
        // Fixed fields, newlines and four SHA-1 IDs fit in 512 bytes.
        let refs_len = self
            .original
            .reference
            .as_ref()
            .map_or(0, |name| name.as_bstr().len())
            .checked_add(self.target_ref.as_bstr().len())
            .and_then(|len| len.checked_add(512))
            .ok_or_else(|| invalid("record length overflow"))?;
        if refs_len > MAX_RECORD_BYTES {
            return Err(invalid("record exceeds 64 KiB"));
        }
        let mut out = Vec::new();
        out.try_reserve_exact(refs_len)
            .map_err(|source| io::Error::new(io::ErrorKind::OutOfMemory, source))?;
        field(&mut out, b"version=", b"1");
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
        for id in [
            self.original.id,
            Some(self.target_commit),
            Some(self.result_tree),
            self.intended_commit,
        ]
        .into_iter()
        .flatten()
        {
            if id.kind() != gix::hash::Kind::Sha1 {
                return Err(invalid("object ID is not SHA-1"));
            }
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
    if record.kind != Kind::Merge && target_tree != record.result_tree {
        return Err(object_invalid("recorded result tree does not match the target commit").into());
    }
    if let Some(id) = record.intended_commit {
        let intended = checked_object(repo, id, cancellation)?.try_into_commit()?;
        let decoded = intended.decode()?;
        let parents = [
            record
                .original
                .id
                .expect("publishing merge has a born original"),
            record.target_commit,
        ];
        if !decoded.parents().eq(parents) {
            return Err(
                object_invalid("recorded intended commit has different merge parents").into(),
            );
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
    if version != b"1" {
        return Err(invalid("unsupported version"));
    }
    let state = match next(&mut lines, b"state=")? {
        b"incomplete" => State::Incomplete,
        b"ready" => State::Ready,
        b"publishing" => State::Publishing,
        _ => return Err(invalid("unknown state")),
    };
    let kind = match next(&mut lines, b"kind=")? {
        b"switch" => Kind::Switch,
        b"fast-forward" => Kind::FastForward,
        b"merge" => Kind::Merge,
        _ => return Err(invalid("unknown kind")),
    };
    let original_ref = optional_ref(next(&mut lines, b"original-ref=")?)?;
    let original_id = optional_id(next(&mut lines, b"original-id=")?)?;
    let target_ref = required_ref(next(&mut lines, b"target-ref=")?)?;
    let target_commit = required_id(next(&mut lines, b"target-commit=")?)?;
    let result_tree = required_id(next(&mut lines, b"result-tree=")?)?;
    let intended_commit = optional_id(next(&mut lines, b"intended-commit=")?)?;
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
