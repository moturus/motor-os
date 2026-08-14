//! Sessions: the transcript, on disk, as it happens.
//!
//! JSONL under `<workspace>/.gears/sessions/`, one record per line, appended
//! as the conversation grows. The format has one rule that matters more than
//! the rest: **a record whose type this binary does not know is skipped, not
//! rejected**. Plan step 9 restarts gears into a freshly built binary and
//! resumes the session it was writing a moment earlier, so a session written
//! by a newer gears must load in an older one and vice versa. A leading `meta`
//! record says who wrote it.
//!
//! One writer at a time, enforced by a pid lockfile with stale detection —
//! `flock` does not exist on Motor OS, and `O_CREAT|O_EXCL` does.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::agent::turn::Journal;
use crate::provider::{ChatMessage, Usage, UsageMeter};

/// Where sessions live, relative to the workspace root.
pub const SESSIONS_DIR: &str = ".gears/sessions";
const STATE_SESSIONS_DIR: &str = "sessions";

pub fn dir_in(workspace: &Path) -> PathBuf {
    workspace.join(SESSIONS_DIR)
}

/// What a session file said when it was read back.
#[derive(Debug, Default, PartialEq)]
pub struct Transcript {
    /// The model the session was started with; `None` if the meta record was
    /// missing, which an old or hand-edited file can be.
    pub model: Option<String>,
    pub messages: Vec<ChatMessage>,
    pub usage: UsageMeter,
    /// What the endpoint counted for the *last* request this session made,
    /// as against the sum of them all. It is the one number that says how
    /// full the window was when the session stopped (`agent/context.rs`).
    pub last_prompt_tokens: u64,
    /// Records of a type this binary does not know — written by a newer gears.
    /// Counted rather than dropped in silence.
    pub unknown: usize,
    /// Lines that were not readable at all. An append-only file whose writer
    /// was killed mid-line ends in one of these.
    pub damaged: usize,
}

/// An open session: the file, the lock on it, and the id that names it.
#[derive(Debug)]
pub struct Session {
    id: String,
    path: PathBuf,
    lock: PathBuf,
    file: File,
}

impl Session {
    /// Start a new session.
    pub fn create(workspace: &Path, model: &str) -> Result<Session, String> {
        let state = crate::state::StateDir::new(workspace)?;
        let dir = state.directory(Path::new(STATE_SESSIONS_DIR))?;
        let mut session = Session::open(&state, &free_id(&dir)?)?;
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        session
            .record(
                "meta",
                json!({
                    "version": 1,
                    "gears": env!("CARGO_PKG_VERSION"),
                    "model": model,
                    "workspace": workspace.display().to_string(),
                    "started": started,
                }),
            )
            .map_err(|e| format!("{}: {e}", session.path.display()))?;
        Ok(session)
    }

    /// Reopen a session and read back what it holds. The lock is taken before
    /// the file is read, so what comes back cannot already be stale.
    pub fn resume(workspace: &Path, id: &str) -> Result<(Session, Transcript), String> {
        validate_id(id)?;
        let state = crate::state::StateDir::new(workspace)?;
        let relative = Path::new(STATE_SESSIONS_DIR).join(format!("{id}.jsonl"));
        let Some(path) = state.existing_file(&relative)? else {
            return Err(format!(
                "{}: no such session",
                dir_in(workspace).join(format!("{id}.jsonl")).display()
            ));
        };
        let session = Session::open(&state, id)?;
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok((session, read(&text)))
    }

    /// Every session in this workspace, oldest first.
    pub fn list(workspace: &Path) -> Result<Vec<String>, String> {
        let state = crate::state::StateDir::new(workspace)?;
        let Some(dir) = state.existing_directory(Path::new(STATE_SESSIONS_DIR))? else {
            return Ok(Vec::new());
        };
        let entries =
            std::fs::read_dir(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        let mut ids: Vec<String> = entries
            .filter_map(|entry| {
                let name = entry.ok()?.file_name().into_string().ok()?;
                let id = name.strip_suffix(".jsonl")?;
                valid_id(id).then(|| id.to_string())
            })
            .collect();
        ids.sort();
        Ok(ids)
    }

    fn open(state: &crate::state::StateDir, id: &str) -> Result<Session, String> {
        validate_id(id)?;
        let path = state.file(&Path::new(STATE_SESSIONS_DIR).join(format!("{id}.jsonl")))?;
        let lock = state.file(&Path::new(STATE_SESSIONS_DIR).join(format!("{id}.lock")))?;
        acquire(&lock)?;
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => Ok(Session {
                id: id.to_string(),
                path,
                lock,
                file,
            }),
            Err(e) => {
                let _ = std::fs::remove_file(&lock);
                Err(format!("{}: {e}", path.display()))
            }
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// One line, flushed: a session that survives a crash is the whole point.
    fn record(&mut self, kind: &str, value: Value) -> std::io::Result<()> {
        let mut object = match value {
            Value::Object(map) => map,
            other => {
                return Err(std::io::Error::other(format!(
                    "a {kind} record is not an object: {other}"
                )));
            }
        };
        object.insert("record".to_string(), json!(kind));
        writeln!(self.file, "{}", Value::Object(object))?;
        self.file.flush()
    }
}

/// Session ids are filenames, never paths. This is also the grammar emitted
/// by `free_id`: seconds, process id, and an optional collision suffix.
pub(super) fn validate_id(id: &str) -> Result<(), String> {
    match valid_id(id) {
        true => Ok(()),
        false => Err(
            "bad session id (expected SECONDS-PID or SECONDS-PID-SUFFIX, using digits only)"
                .to_string(),
        ),
    }
}

fn valid_id(id: &str) -> bool {
    let mut parts = id.split('-');
    let part = |part: Option<&str>| {
        part.is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    };
    part(parts.next())
        && part(parts.next())
        && parts
            .next()
            .is_none_or(|suffix| part(Some(suffix)) && parts.next().is_none())
}

impl Journal for Session {
    fn message(&mut self, message: &ChatMessage) -> std::io::Result<()> {
        self.record("message", message_value(message)?)
    }

    fn usage(&mut self, usage: &Usage) -> std::io::Result<()> {
        let value = serde_json::to_value(usage).map_err(std::io::Error::other)?;
        self.record("usage", value)
    }

    fn compaction(
        &mut self,
        head: usize,
        replaced: usize,
        replacement: &[ChatMessage],
    ) -> std::io::Result<()> {
        let replacement = replacement
            .iter()
            .map(message_value)
            .collect::<std::io::Result<Vec<_>>>()?;
        self.record(
            "compaction_v2",
            json!({"head": head, "replaced": replaced, "replacement": replacement}),
        )
    }
}

fn message_value(message: &ChatMessage) -> std::io::Result<Value> {
    let mut value = serde_json::to_value(message).map_err(std::io::Error::other)?;
    if message.retains_artifact() {
        value["artifact_reference"] = json!(true);
    }
    Ok(value)
}

fn message_from_value(value: Value) -> Option<ChatMessage> {
    let artifact_reference = match value.get("artifact_reference") {
        None => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return None,
    };
    let mut message = serde_json::from_value::<ChatMessage>(value).ok()?;
    if artifact_reference {
        if message.role != crate::provider::Role::Tool || message.tool_call_id.is_none() {
            return None;
        }
        message = message.retaining_artifact();
    }
    Some(message)
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock);
    }
}

/// Read a session file. Nothing here fails: a transcript that cannot be fully
/// understood is still worth resuming, and what was not understood is counted
/// so that the user is told.
fn read(text: &str) -> Transcript {
    let mut transcript = Transcript::default();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            transcript.damaged += 1;
            continue;
        };
        match value["record"].as_str() {
            Some("meta") => {
                transcript.model = value["model"].as_str().map(str::to_string);
            }
            Some("message") => match message_from_value(value) {
                Some(message) => transcript.messages.push(message),
                None => transcript.damaged += 1,
            },
            Some("usage") => match serde_json::from_value::<Usage>(value) {
                Ok(usage) => {
                    if usage.prompt_tokens > 0 {
                        transcript.last_prompt_tokens = usage.prompt_tokens;
                    }
                    transcript.usage.add(&usage);
                }
                Err(_) => transcript.damaged += 1,
            },
            // A checkpoint is applied as it is read, so what comes back is the
            // conversation as it stood, not as it was written.
            Some("compaction") => match compact(&mut transcript.messages, &value) {
                true => {}
                false => transcript.damaged += 1,
            },
            Some("compaction_v2") => match compact_v2(&mut transcript.messages, &value) {
                true => {}
                false => transcript.damaged += 1,
            },
            // The forward-compatibility rule: a record type from a newer gears
            // is stepped over, not fought with.
            Some(_) => transcript.unknown += 1,
            None => transcript.damaged += 1,
        }
    }
    transcript
}

/// Apply a checkpoint to the transcript read so far. A record that does not
/// describe a stretch of *this* transcript is damage rather than an
/// instruction, and is counted as such instead of being obeyed.
fn compact(messages: &mut Vec<ChatMessage>, value: &Value) -> bool {
    let Some(summary) = value["summary"].as_str() else {
        return false;
    };
    let head = value["head"].as_u64().unwrap_or(u64::MAX) as usize;
    let replaced = value["replaced"].as_u64().unwrap_or_default() as usize;
    let Some(end) = head
        .checked_add(replaced)
        .filter(|end| *end <= messages.len())
    else {
        return false;
    };
    if replaced == 0 {
        return false;
    }
    messages
        .splice(head..end, [crate::agent::context::checkpoint(summary)])
        .for_each(drop);
    true
}

fn compact_v2(messages: &mut Vec<ChatMessage>, value: &Value) -> bool {
    let Some(values) = value["replacement"].as_array() else {
        return false;
    };
    let Some(replacement) = values
        .iter()
        .cloned()
        .map(message_from_value)
        .collect::<Option<Vec<_>>>()
        .filter(|messages| !messages.is_empty())
    else {
        return false;
    };
    let head = value["head"].as_u64().unwrap_or(u64::MAX) as usize;
    let replaced = value["replaced"].as_u64().unwrap_or_default() as usize;
    let Some(end) = head
        .checked_add(replaced)
        .filter(|end| replaced > 0 && *end <= messages.len())
    else {
        return false;
    };
    messages.splice(head..end, replacement).for_each(drop);
    true
}

/// `<seconds>-<pid>`, with a suffix if that is somehow taken: unique without a
/// random number generator, and it sorts by age, which is what makes
/// `Session::list` worth having.
fn free_id(dir: &Path) -> Result<String, String> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let base = format!("{secs}-{}", std::process::id());
    // Two sessions started in the same second by the same process is the only
    // way the base collides; another gears has another pid.
    for attempt in 0..100 {
        let id = match attempt {
            0 => base.clone(),
            n => format!("{base}-{n}"),
        };
        if !dir.join(format!("{id}.jsonl")).exists() {
            return Ok(id);
        }
    }
    Err(format!("no free session id in {}", dir.display()))
}

/// Take the lock, or say who has it. A lockfile whose owner is gone is stale —
/// gears is built with `panic = "abort"`, so an aborted run leaves one behind
/// and the next run has to be able to clear it.
fn acquire(lock: &Path) -> Result<(), String> {
    match create_lock(lock) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            return Err(format!("{}: {e}", lock.display()));
        }
        Err(_) => {}
    }
    let owner = std::fs::read_to_string(lock)
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok());
    if let Some(pid) = owner
        && crate::platform::process_alive(pid)
    {
        return Err(format!(
            "this session is open in another gears (process {pid}); \
             if that is wrong, delete {}",
            lock.display()
        ));
    }
    crate::trace::log(
        crate::trace::Level::Warn,
        &format!("clearing a stale lock: {}", lock.display()),
    );
    let _ = std::fs::remove_file(lock);
    create_lock(lock).map_err(|e| format!("{}: {e}", lock.display()))
}

fn create_lock(lock: &Path) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(lock)?;
    write!(file, "{}", std::process::id())?;
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::turn::Conversation;
    use crate::provider::{Role, ToolCall};
    use std::sync::atomic::{AtomicU32, Ordering};

    fn workspace(name: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "gears-session-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn exchange(session: &mut Session) {
        session.message(&ChatMessage::user("write a file")).unwrap();
        session
            .message(&ChatMessage {
                role: Role::Assistant,
                content: None,
                tool_calls: vec![ToolCall::new("call_1", "write_file", r#"{"path":"a"}"#)],
                tool_call_id: None,
                artifact_reference: false,
            })
            .unwrap();
        session
            .message(&ChatMessage::tool_result("call_1", "wrote 1 byte"))
            .unwrap();
        session
            .usage(&Usage {
                prompt_tokens: 10,
                completion_tokens: 4,
                cost: Some(0.001),
                ..Usage::default()
            })
            .unwrap();
        session.message(&ChatMessage::assistant("done")).unwrap();
    }

    #[test]
    fn a_session_round_trips_through_the_file() {
        let dir = workspace("round-trip");
        let id = {
            let mut session = Session::create(&dir, "test/model").unwrap();
            exchange(&mut session);
            session.id().to_string()
        };

        let (_session, transcript) = Session::resume(&dir, &id).unwrap();
        assert_eq!(transcript.model.as_deref(), Some("test/model"));
        assert_eq!(transcript.messages.len(), 4);
        assert_eq!(
            transcript.messages[0].content.as_deref(),
            Some("write a file")
        );
        assert_eq!(transcript.messages[1].tool_calls[0].name(), "write_file");
        assert_eq!(
            transcript.messages[2].tool_call_id.as_deref(),
            Some("call_1")
        );
        assert_eq!(transcript.usage.total_tokens(), 14);
        assert_eq!(transcript.usage.cost_usd(), Some(0.001));
        assert_eq!((transcript.unknown, transcript.damaged), (0, 0));
        assert_eq!(Session::list(&dir).unwrap(), [id]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The rule that makes plan step 9 possible: a session written by a newer
    /// gears still loads here, minus the parts this binary has no name for.
    #[test]
    fn records_from_a_newer_gears_are_stepped_over() {
        let dir = workspace("forward");
        let id = {
            let session = Session::create(&dir, "test/model").unwrap();
            session.id().to_string()
        };
        let path = dir_in(&dir).join(format!("{id}.jsonl"));
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(
            file,
            r#"{{"record":"message","role":"user","content":"hi"}}"#
        )
        .unwrap();
        writeln!(file, r#"{{"record":"tone","mood":"brisk"}}"#).unwrap();
        writeln!(file, r#"{{"record":"telepathy","strength":11}}"#).unwrap();
        writeln!(
            file,
            r#"{{"record":"message","role":"assistant","content":"hello"}}"#
        )
        .unwrap();
        // What a killed writer leaves behind: half a line, at the end.
        write!(file, r#"{{"record":"message","role":"user","cont"#).unwrap();
        drop(file);

        let (_session, transcript) = Session::resume(&dir, &id).unwrap();
        assert_eq!(transcript.messages.len(), 2);
        assert_eq!(transcript.messages[1].content.as_deref(), Some("hello"));
        assert_eq!(transcript.unknown, 2);
        assert_eq!(transcript.damaged, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The first checkpoint format remains readable after v2 starts retaining
    /// exact replacement messages.
    #[test]
    fn a_legacy_compaction_is_applied_when_the_session_is_read() {
        let dir = workspace("compaction");
        let id = {
            let mut session = Session::create(&dir, "m").unwrap();
            for turn in 0..4 {
                session
                    .message(&ChatMessage::user(format!("ask {turn}")))
                    .unwrap();
                session
                    .message(&ChatMessage::assistant(format!("answer {turn}")))
                    .unwrap();
            }
            // The first six, replaced; the last two left alone.
            session
                .record(
                    "compaction",
                    json!({"head": 0, "replaced": 6, "summary": "we discussed four things"}),
                )
                .unwrap();
            session.message(&ChatMessage::user("and now this")).unwrap();
            session.id().to_string()
        };

        let (_session, transcript) = Session::resume(&dir, &id).unwrap();
        assert_eq!(transcript.messages.len(), 4);
        let summary = transcript.messages[0].content.clone().unwrap();
        assert!(summary.ends_with("we discussed four things"), "{summary}");
        assert_eq!(transcript.messages[0].role, Role::Assistant);
        assert_eq!(transcript.messages[1].content.as_deref(), Some("ask 3"));
        assert_eq!(
            transcript.messages[3].content.as_deref(),
            Some("and now this")
        );
        assert_eq!((transcript.unknown, transcript.damaged), (0, 0));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_artifact_call_and_result_survive_live_compaction_and_resume() {
        let dir = workspace("artifact-compaction");
        let session = Session::create(&dir, "m").unwrap();
        let id = session.id().to_string();
        let mut conversation = Conversation::new("m").with_journal(Box::new(session));
        conversation.push(ChatMessage::user("inspect it")).unwrap();
        conversation
            .push(ChatMessage {
                role: Role::Assistant,
                content: None,
                tool_calls: vec![ToolCall::new("call-7", "run", r#"{"command":"check"}"#)],
                tool_call_id: None,
                artifact_reference: false,
            })
            .unwrap();
        conversation
            .push(
                ChatMessage::tool_result("call-7", "complete output is artifact 7")
                    .retaining_artifact(),
            )
            .unwrap();
        conversation.push(ChatMessage::user("continue")).unwrap();
        conversation.compact(0..3, "I inspected it.").unwrap();
        drop(conversation);

        let (resumed_session, transcript) = Session::resume(&dir, &id).unwrap();
        assert_eq!((transcript.unknown, transcript.damaged), (0, 0));
        assert_eq!(transcript.messages.len(), 4, "{:?}", transcript.messages);
        assert_eq!(transcript.messages[1].tool_calls[0].id, "call-7");
        assert_eq!(
            transcript.messages[2].tool_call_id.as_deref(),
            Some("call-7")
        );
        assert!(transcript.messages[2].retains_artifact());
        assert_eq!(transcript.messages[3].content.as_deref(), Some("continue"));
        drop(resumed_session);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A checkpoint that does not describe a stretch of this transcript is
    /// damage: a half-written record, or one meant for another file.
    #[test]
    fn a_compaction_that_fits_nothing_is_not_obeyed() {
        let dir = workspace("bad-compaction");
        let id = {
            let mut session = Session::create(&dir, "m").unwrap();
            session.message(&ChatMessage::user("only this")).unwrap();
            session
                .compaction(
                    0,
                    9,
                    &[crate::agent::context::checkpoint("of nine messages")],
                )
                .unwrap();
            session.id().to_string()
        };

        let (_session, transcript) = Session::resume(&dir, &id).unwrap();
        assert_eq!(transcript.messages.len(), 1);
        assert_eq!(transcript.damaged, 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_resumed_session_keeps_appending_to_the_same_file() {
        let dir = workspace("append");
        let id = {
            let mut session = Session::create(&dir, "m").unwrap();
            session.message(&ChatMessage::user("first")).unwrap();
            session.id().to_string()
        };
        {
            let (mut session, transcript) = Session::resume(&dir, &id).unwrap();
            assert_eq!(transcript.messages.len(), 1);
            session.message(&ChatMessage::user("second")).unwrap();
        }
        let (_session, transcript) = Session::resume(&dir, &id).unwrap();
        assert_eq!(transcript.messages.len(), 2);
        assert_eq!(transcript.messages[1].content.as_deref(), Some("second"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_writer_at_a_time() {
        let dir = workspace("lock");
        let held = Session::create(&dir, "m").unwrap();
        let id = held.id().to_string();

        let error = Session::resume(&dir, &id).unwrap_err();
        assert!(error.contains("another gears"), "{error}");
        assert!(error.contains(&std::process::id().to_string()), "{error}");

        // The lock goes when the session does.
        drop(held);
        let (again, _) = Session::resume(&dir, &id).unwrap();
        drop(again);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_lock_left_by_a_dead_process_is_cleared() {
        let dir = workspace("stale");
        let id = {
            let session = Session::create(&dir, "m").unwrap();
            session.id().to_string()
        };
        // pid 0 is never a live process on any platform gears runs on, and a
        // lockfile with junk in it is treated the same way.
        let lock = dir_in(&dir).join(format!("{id}.lock"));
        for owner in ["0", "not a pid"] {
            std::fs::write(&lock, owner).unwrap();
            let (session, _) = Session::resume(&dir, &id).unwrap();
            assert_eq!(
                std::fs::read_to_string(&lock).unwrap(),
                std::process::id().to_string()
            );
            drop(session);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resuming_something_that_is_not_there_says_so() {
        let dir = workspace("missing");
        let error = Session::resume(&dir, "1-2").unwrap_err();
        assert!(error.contains("1-2.jsonl"), "{error}");
        assert!(Session::list(&dir).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_session_id_can_never_be_a_path() {
        let dir = workspace("unsafe-id");
        let state = dir.join(".gears");
        std::fs::create_dir_all(state.join("sessions")).unwrap();
        let outside = state.join("outside.jsonl");
        std::fs::write(&outside, "leave this alone\n").unwrap();

        for id in ["../outside", "1/2", ".", "", "1-2-3-4", "one-2"] {
            let error = Session::resume(&dir, id).unwrap_err();
            assert!(error.contains("bad session id"), "{id:?}: {error}");
        }
        assert_eq!(
            std::fs::read_to_string(outside).unwrap(),
            "leave this alone\n"
        );
        assert!(!state.join("outside.lock").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sessions_refuse_a_redirected_state_root() {
        use std::os::unix::fs::symlink;

        let dir = workspace("state-link");
        let outside = workspace("state-link-outside");
        symlink(&outside, dir.join(crate::state::STATE_DIR)).unwrap();
        let error = Session::create(&dir, "m").unwrap_err();
        assert!(error.contains("symlink"), "{error}");
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
        std::fs::remove_dir_all(dir).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
}
