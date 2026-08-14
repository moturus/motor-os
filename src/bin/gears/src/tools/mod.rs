//! Tools: what the model is allowed to do.
//!
//! Tools are pure functions of their arguments. The permission gate lives in
//! the agent layer (plan step 4), not here, so a tool can be tested without a
//! UI and the gate can be reasoned about without file I/O in the way.
//!
//! Two rules shape everything below. A bad call is the *model's* problem, not
//! the process's: malformed arguments come back as an error-flagged tool
//! result it can read and correct. And every result is byte-capped — a single
//! `cargo build` stderr is enough to flood a context window.

pub mod artifact;
pub mod fetch;
pub mod file;
pub mod fs;
pub mod instructions;
pub mod run;
pub mod search;
pub mod selfhost;
pub mod spawn;
pub mod toolchain;
pub mod unsupported;
pub mod vcs;

use serde_json::{Value, json};

use crate::agent::bus::{AgentId, Cancel, Event, Gone, ToolStream};

pub use fs::Workspace;

/// Default cap on what one call returns to the model.
pub const DEFAULT_CAP: usize = 16 * 1024;

/// Maximum UTF-8 bytes in one live output event. This is batching, not the
/// retained-output limit; the process capture applies that separately.
pub const LIVE_CHUNK_BYTES: usize = 8 * 1024;

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

/// The live agent-side state available to one tool call.
///
/// It is owned and cloneable because foreground process output is drained by
/// worker threads. A tool may narrow the deadline, but never extend one set by
/// its caller.
#[derive(Clone)]
pub struct Execution {
    agent: AgentId,
    events: std::sync::mpsc::SyncSender<Event>,
    cancel: Cancel,
    deadline: Option<std::time::Instant>,
}

impl Execution {
    pub(crate) fn new(
        agent: AgentId,
        events: std::sync::mpsc::SyncSender<Event>,
        cancel: Cancel,
    ) -> Execution {
        Execution {
            agent,
            events,
            cancel,
            deadline: None,
        }
    }

    pub fn agent(&self) -> AgentId {
        self.agent
    }

    pub fn cancelled(&self) -> bool {
        if crate::platform::interrupt_pending() {
            self.cancel.raise();
        }
        self.cancel.pending()
    }

    pub(crate) fn cancellation(&self) -> &Cancel {
        &self.cancel
    }

    pub fn deadline(&self) -> Option<std::time::Instant> {
        self.deadline
    }

    pub fn with_deadline(&self, deadline: std::time::Instant) -> Execution {
        let mut context = self.clone();
        context.deadline = Some(self.deadline.map_or(deadline, |old| old.min(deadline)));
        context
    }

    /// Send a tool-side notice through the same ordered event stream as every
    /// other visible part of this agent's work.
    pub fn notice(&self, text: impl Into<String>) -> Result<(), Gone> {
        self.events
            .send(Event::Notice {
                agent: self.agent,
                text: text.into(),
            })
            .map_err(|_| Gone)
    }

    /// Emit every byte of `text`, split at UTF-8 boundaries so no individual
    /// live event can monopolize the render queue.
    pub fn output(&self, stream: ToolStream, text: &str) -> Result<(), Gone> {
        let mut rest = text;
        while !rest.is_empty() {
            let at = floor_boundary(rest, rest.len().min(LIVE_CHUNK_BYTES));
            let (chunk, tail) = rest.split_at(at);
            self.events
                .send(Event::ToolOutput {
                    agent: self.agent,
                    stream,
                    text: chunk.to_string(),
                })
                .map_err(|_| Gone)?;
            rest = tail;
        }
        Ok(())
    }

    pub fn progress(&self, elapsed: std::time::Duration) -> Result<(), Gone> {
        self.events
            .send(Event::ToolProgress {
                agent: self.agent,
                elapsed,
            })
            .map_err(|_| Gone)
    }
}

/// What one call produced. A failure still travels to the model as content,
/// because it is information rather than an exception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    pub content: String,
    pub outcome: ToolOutcome,
    artifact_reference: bool,
}

/// Why a tool call ended. A command's non-zero status is still `Completed`:
/// it ran and its diagnostics are evidence, not a tool-protocol failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolOutcome {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    SpawnFailed,
    ProtocolFailed,
}

impl ToolOutcome {
    pub fn is_error(self) -> bool {
        self != ToolOutcome::Completed
    }
}

impl ToolResult {
    pub fn ok(content: impl Into<String>) -> ToolResult {
        ToolResult {
            content: content.into(),
            outcome: ToolOutcome::Completed,
            artifact_reference: false,
        }
    }

    pub fn error(content: impl Into<String>) -> ToolResult {
        ToolResult::failed(content, ToolOutcome::Failed)
    }

    pub(crate) fn failed(content: impl Into<String>, outcome: ToolOutcome) -> ToolResult {
        ToolResult {
            content: content.into(),
            outcome,
            artifact_reference: false,
        }
    }

    pub fn is_error(&self) -> bool {
        self.outcome.is_error()
    }

    pub(crate) fn retains_artifact(&self) -> bool {
        self.artifact_reference
    }
}

pub trait Tool: Send + Sync {
    fn name(&self) -> &'static str;

    /// Description and argument schema, as the model is shown them.
    fn spec(&self) -> crate::provider::ToolSpec;

    /// Whether a call can change the workspace. A static property of the tool
    /// rather than of the call, because that is the question step 7's
    /// read-only sub-agents ask when they filter this registry.
    fn mutates(&self) -> bool;

    /// Whether *this* call has to be put to the user. Mutating is the usual
    /// reason, but not the only one: `fetch` changes nothing and still asks
    /// before it leaves the egress allowlist.
    fn gated(&self, _args: &Value) -> bool {
        self.mutates()
    }

    /// Told that the user has allowed a call [`Tool::gated`] asked about, just
    /// before it runs. `fetch` is why this exists: consent is what widens the
    /// egress policy, and a tool has no other way to hear about it.
    fn approved(&self, _args: &Value) {}

    /// What an "always allow this" answer is remembered under. The name is
    /// right for a tool whose calls are all alike; `run` is not one of those,
    /// and narrows it to the command, as `fetch` does to the host.
    fn permission_key(&self, _args: &Value) -> String {
        self.name().to_string()
    }

    /// `args` is always a decoded JSON object. An `Err` is a message for the
    /// model, not a process failure.
    fn call(&self, args: &Value) -> Result<String, String>;

    /// Run with the agent's cancellation, event, identity, and deadline
    /// handles. Existing tools use the compatibility body until they need
    /// live execution state.
    fn execute(&self, args: &Value, _execution: &Execution) -> Result<String, String> {
        self.call(args)
    }

    /// Invoke a decoded call and classify how it ended. Process-backed tools
    /// override this to retain outcomes more precise than success or failure.
    fn invoke(&self, args: &Value, execution: &Execution) -> ToolResult {
        match self.execute(args, execution) {
            Ok(text) => ToolResult::ok(text),
            Err(msg) => ToolResult::error(format!("{}: {msg}", self.name())),
        }
    }

    fn cap(&self) -> usize {
        DEFAULT_CAP
    }
}

/// The tools one agent may call, in the order the model is shown them.
///
/// Shared rather than owned, because a sub-agent gets its own registry over
/// the *same* tools: one workspace, one undo log, one egress policy, however
/// many agents are looking at them.
#[derive(Default)]
pub struct Registry {
    tools: Vec<std::sync::Arc<dyn Tool>>,
    artifacts: Option<std::sync::Arc<crate::agent::artifact::LazyStore>>,
}

impl Registry {
    pub fn new() -> Registry {
        Registry::default()
    }

    pub fn register(&mut self, tool: Box<dyn Tool>) {
        self.register_shared(tool.into());
    }

    pub fn register_shared(&mut self, tool: std::sync::Arc<dyn Tool>) {
        debug_assert!(
            self.get(tool.name()).is_none(),
            "two tools named '{}'",
            tool.name()
        );
        self.tools.push(tool);
    }

    /// Retain complete results that are too large for a tool's model-facing
    /// result cap. The store stays lazy until such a result is produced.
    pub fn with_artifacts(
        mut self,
        artifacts: std::sync::Arc<crate::agent::artifact::LazyStore>,
    ) -> Registry {
        self.artifacts = Some(artifacts);
        self
    }

    pub fn get(&self, name: &str) -> Option<&dyn Tool> {
        self.tools
            .iter()
            .find(|tool| tool.name() == name)
            .map(AsRef::as_ref)
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.tools.iter().map(|tool| tool.name()).collect()
    }

    pub fn specs(&self) -> Vec<crate::provider::ToolSpec> {
        self.tools.iter().map(|tool| tool.spec()).collect()
    }

    /// Run one call. `arguments` is the raw JSON string the model emitted,
    /// which is allowed to be nonsense.
    pub fn dispatch(&self, name: &str, arguments: &str, execution: &Execution) -> ToolResult {
        self.dispatch_inner(name, arguments, None, execution)
    }

    /// Run one provider tool call, preserving its unique reference if a large
    /// result has to move into the session artifact store.
    pub fn dispatch_call(
        &self,
        name: &str,
        arguments: &str,
        reference: &str,
        execution: &Execution,
    ) -> ToolResult {
        self.dispatch_inner(name, arguments, Some(reference), execution)
    }

    fn dispatch_inner(
        &self,
        name: &str,
        arguments: &str,
        reference: Option<&str>,
        execution: &Execution,
    ) -> ToolResult {
        // Clipped: a write_file call carries a whole file in its arguments.
        crate::trace::log(
            crate::trace::Level::Debug,
            &format!("tool {name} {}", clip(arguments, 512)),
        );
        let mut result = self.run(name, arguments, reference, execution);
        result.content = crate::trace::scrub(&result.content);
        crate::trace::log(
            crate::trace::Level::Debug,
            &format!(
                "tool {name} -> {} bytes{}",
                result.content.len(),
                if result.is_error() { " (error)" } else { "" }
            ),
        );
        result
    }

    fn run(
        &self,
        name: &str,
        arguments: &str,
        reference: Option<&str>,
        execution: &Execution,
    ) -> ToolResult {
        let Some(tool) = self.get(name) else {
            return ToolResult::failed(
                format!(
                    "no such tool '{name}'; available: {}",
                    self.names().join(", ")
                ),
                ToolOutcome::ProtocolFailed,
            );
        };
        let args = match parse_args(arguments) {
            Ok(args) => args,
            Err(msg) => {
                return ToolResult::failed(format!("{name}: {msg}"), ToolOutcome::ProtocolFailed);
            }
        };
        let mut result = tool.invoke(&args, execution);
        result.content = crate::trace::scrub(&result.content);
        if result.content.len() <= tool.cap() {
            return result;
        }
        let complete_size = result.content.len();
        if let (Some(artifacts), Some(reference)) = (&self.artifacts, reference) {
            let origin = crate::agent::artifact::Origin {
                producer: name.to_string(),
                reference: format!("agent {} tool call {reference}", execution.agent()),
            };
            match artifacts.put_text(crate::agent::artifact::TOOL_OUTPUT, origin, &result.content) {
                Ok(metadata) => {
                    result.content = crate::agent::artifact::complete_reference(name, &metadata);
                    result.artifact_reference = true;
                    return result;
                }
                Err(error) => {
                    result.content = clamp(
                        &format!(
                            "{name} produced {complete_size} bytes, but complete output could not \
                             be retained: {}\n{}",
                            crate::trace::scrub(&error),
                            result.content
                        ),
                        tool.cap(),
                    );
                    return result;
                }
            }
        }
        if result.outcome == ToolOutcome::Completed {
            result.content = clamp(&result.content, tool.cap());
        }
        result
    }
}

/// One line naming a pending call, for the permission prompt and for the
/// transcript. Generic on purpose: what a call is *about* is the file, the
/// command, the pattern, the URL, the commit message or the task it names —
/// with its arguments, since "allow run cargo?" is not a question anybody can
/// answer — and a tool that names none of those is described well enough by
/// its own name.
pub fn describe(name: &str, args: Option<&Value>) -> String {
    let Some(args) = args else {
        return format!("{name} (unreadable arguments)");
    };
    let mut words = Vec::new();
    for field in [
        "command",
        "path",
        "pattern",
        "url",
        "message",
        "task",
        "candidate",
    ] {
        match &args[field] {
            Value::String(text) => words.push(text.clone()),
            // A number where the answer to "allow what?" is one: which
            // candidate binary is about to replace the running gears.
            Value::Number(number) => words.push(number.to_string()),
            _ => continue,
        }
        break;
    }
    for field in ["args", "paths"] {
        if let Value::Array(rest) = &args[field] {
            words.extend(rest.iter().filter_map(Value::as_str).map(str::to_string));
        }
    }
    match words.is_empty() {
        true => name.to_string(),
        false => format!("{name} {}", clip(&words.join(" "), 100)),
    }
}

/// Models omit the arguments of a no-argument call, and occasionally emit
/// something that is not an object at all.
pub fn parse_args(arguments: &str) -> Result<Value, String> {
    if arguments.trim().is_empty() {
        return Ok(json!({}));
    }
    match serde_json::from_str(arguments) {
        Ok(Value::Object(map)) => Ok(Value::Object(map)),
        Ok(other) => Err(format!(
            "arguments must be a JSON object, got {}",
            kind_of(&other)
        )),
        Err(e) => Err(format!("arguments are not valid JSON: {e}")),
    }
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// A JSON-schema object, hand-built: the schemas are small and static, and a
/// derive would hide what the model actually sees.
pub fn schema(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

pub fn string_arg(args: &Value, name: &str) -> Result<String, String> {
    match opt_string(args, name)? {
        Some(text) => Ok(text),
        None => Err(format!("missing required argument '{name}'")),
    }
}

pub fn opt_string(args: &Value, name: &str) -> Result<Option<String>, String> {
    match &args[name] {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(text.clone())),
        other => Err(format!(
            "argument '{name}' must be a string, got {}",
            kind_of(other)
        )),
    }
}

/// A list of strings, absent meaning empty: an argument vector, or the extra
/// flags a build takes.
pub fn string_list(args: &Value, name: &str) -> Result<Vec<String>, String> {
    let bad = |what: String| format!("argument '{name}' must be a list of strings, got {what}");
    match &args[name] {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => Ok(text.clone()),
                other => Err(bad(format!("{} in it", kind_of(other)))),
            })
            .collect(),
        other => Err(bad(kind_of(other).to_string())),
    }
}

pub fn bool_arg(args: &Value, name: &str, default: bool) -> Result<bool, String> {
    match &args[name] {
        Value::Null => Ok(default),
        Value::Bool(value) => Ok(*value),
        other => Err(format!(
            "argument '{name}' must be a boolean, got {}",
            kind_of(other)
        )),
    }
}

pub fn usize_arg(args: &Value, name: &str, default: usize) -> Result<usize, String> {
    match &args[name] {
        Value::Null => Ok(default),
        Value::Number(number) => number
            .as_u64()
            .map(|value| value as usize)
            .ok_or_else(|| format!("argument '{name}' must be a positive whole number")),
        other => Err(format!(
            "argument '{name}' must be a number, got {}",
            kind_of(other)
        )),
    }
}

/// Cut `text` to roughly `cap` bytes, keeping the head *and* the tail: the
/// start of a build log says what was attempted and the end says how it went,
/// so eliding the middle loses the least. The marker itself is extra — the
/// cap governs the text kept, not the total.
pub fn clamp(text: &str, cap: usize) -> String {
    if text.len() <= cap {
        return text.to_string();
    }
    let head = floor_boundary(text, cap / 2);
    let tail = ceil_boundary(text, text.len() - (cap - cap / 2));
    format!(
        "{}\n… [{} bytes elided] …\n{}",
        &text[..head],
        tail - head,
        &text[tail..]
    )
}

/// One line, cut at the end rather than in the middle: for a trace entry or a
/// search hit, where the shape of the text matters more than its tail.
pub fn clip(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        None => text.to_string(),
        Some((at, _)) => format!("{}…", &text[..at]),
    }
}

fn floor_boundary(text: &str, mut at: usize) -> usize {
    while at > 0 && !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

fn ceil_boundary(text: &str, mut at: usize) -> usize {
    while at < text.len() && !text.is_char_boundary(at) {
        at += 1;
    }
    at
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execution() -> Execution {
        let (tx, _rx) = crate::agent::event_channel();
        crate::agent::Bus::new(crate::agent::ROOT, tx).execution()
    }

    struct Echo;

    impl Tool for Echo {
        fn name(&self) -> &'static str {
            "echo"
        }

        fn spec(&self) -> crate::provider::ToolSpec {
            crate::provider::ToolSpec::new(
                "echo",
                "Echo text back.",
                schema(json!({"text": {"type": "string"}}), &["text"]),
            )
        }

        fn mutates(&self) -> bool {
            false
        }

        fn call(&self, args: &Value) -> Result<String, String> {
            string_arg(args, "text")
        }

        fn cap(&self) -> usize {
            32
        }
    }

    fn registry() -> Registry {
        let mut registry = Registry::new();
        registry.register(Box::new(Echo));
        registry
    }

    #[test]
    fn an_execution_context_carries_agent_events_cancellation_and_deadline() {
        let (tx, rx) = crate::agent::event_channel();
        let bus = crate::agent::Bus::new(7, tx);
        let execution = bus.execution();
        assert_eq!(execution.agent(), 7);
        assert!(!execution.cancelled());
        assert_eq!(execution.deadline(), None);

        let later = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let earlier = later - std::time::Duration::from_secs(1);
        let bounded = execution.with_deadline(later).with_deadline(earlier);
        assert_eq!(bounded.deadline(), Some(earlier));

        bounded.notice("working").unwrap();
        assert!(matches!(
            rx.recv().unwrap(),
            Event::Notice { agent: 7, text } if text == "working"
        ));
        bus.canceller().raise();
        assert!(bounded.cancelled());
    }

    #[test]
    fn live_output_events_are_typed_ordered_and_individually_bounded() {
        let (tx, rx) = crate::agent::event_channel();
        let execution = crate::agent::Bus::new(3, tx).execution();
        let text = format!("{}🦀tail", "x".repeat(LIVE_CHUNK_BYTES));
        execution.output(ToolStream::Stderr, &text).unwrap();
        execution
            .progress(std::time::Duration::from_millis(2500))
            .unwrap();

        let mut rebuilt = String::new();
        let events: Vec<Event> = rx.try_iter().collect();
        for event in &events[..events.len() - 1] {
            match event {
                Event::ToolOutput {
                    agent: 3,
                    stream: ToolStream::Stderr,
                    text,
                } => {
                    assert!(text.len() <= LIVE_CHUNK_BYTES);
                    rebuilt.push_str(text);
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(rebuilt, text);
        assert!(matches!(
            events.last().unwrap(),
            Event::ToolProgress { agent: 3, elapsed }
                if *elapsed == std::time::Duration::from_millis(2500)
        ));
    }

    #[test]
    fn specs_are_what_the_model_is_shown() {
        let specs = registry().specs();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].function.name, "echo");
        assert_eq!(
            specs[0].function.parameters["required"],
            json!(["text"]),
            "{:?}",
            specs[0].function.parameters
        );
    }

    #[test]
    fn a_call_returns_its_output() {
        let result = registry().dispatch("echo", r#"{"text":"hi"}"#, &execution());
        assert_eq!(result, ToolResult::ok("hi"));
    }

    /// None of these is a process error: each one goes back to the model as a
    /// result it can act on.
    #[test]
    fn bad_calls_come_back_as_error_results() {
        let registry = registry();
        for (arguments, expected) in [
            ("{", "not valid JSON"),
            ("[1,2]", "must be a JSON object"),
            ("{}", "missing required argument 'text'"),
            (r#"{"text":7}"#, "must be a string"),
            ("", "missing required argument 'text'"), // No arguments at all.
        ] {
            let result = registry.dispatch("echo", arguments, &execution());
            assert!(result.is_error(), "{arguments}");
            assert!(
                result.content.contains(expected),
                "{arguments}: {}",
                result.content
            );
        }

        let result = registry.dispatch("delete_everything", "{}", &execution());
        assert!(result.is_error());
        assert_eq!(result.outcome, ToolOutcome::ProtocolFailed);
        assert!(result.content.contains("no such tool"), "{result:?}");
        assert!(result.content.contains("echo"), "{result:?}");

        let malformed = registry.dispatch("echo", "{", &execution());
        assert_eq!(malformed.outcome, ToolOutcome::ProtocolFailed);
        let rejected = registry.dispatch("echo", "{}", &execution());
        assert_eq!(rejected.outcome, ToolOutcome::Failed);
    }

    #[test]
    fn optional_arguments_have_defaults() {
        let args = json!({"n": 3, "flag": false});
        assert_eq!(usize_arg(&args, "n", 1).unwrap(), 3);
        assert_eq!(usize_arg(&args, "missing", 1).unwrap(), 1);
        assert!(!bool_arg(&args, "flag", true).unwrap());
        assert!(bool_arg(&args, "missing", true).unwrap());
        assert!(usize_arg(&json!({"n": -1}), "n", 1).is_err());
        assert!(bool_arg(&json!({"flag": "yes"}), "flag", false).is_err());
    }

    #[test]
    fn a_call_describes_itself_by_what_it_is_about() {
        assert_eq!(
            describe(
                "write_file",
                Some(&json!({"path": "src/x.rs", "content": "…"}))
            ),
            "write_file src/x.rs"
        );
        assert_eq!(
            describe("grep", Some(&json!({"pattern": "TODO"}))),
            "grep TODO"
        );
        assert_eq!(
            describe("fetch", Some(&json!({"url": "https://docs.rs/serde"}))),
            "fetch https://docs.rs/serde"
        );
        // A command is nothing without its arguments.
        assert_eq!(
            describe(
                "run",
                Some(&json!({"command": "cargo", "args": ["build", "--release"]}))
            ),
            "run cargo build --release"
        );
        // "allow git_commit?" is not a question either: what is being asked
        // about is the message, and for a restore the files it will discard.
        assert_eq!(
            describe("git_commit", Some(&json!({"message": "add notes"}))),
            "git_commit add notes"
        );
        assert_eq!(
            describe("git_restore", Some(&json!({"paths": ["a.rs", "b.rs"]}))),
            "git_restore a.rs b.rs"
        );
        assert_eq!(describe("list_dir", Some(&json!({}))), "list_dir");
        // A call whose arguments would not even parse still has a name.
        assert!(describe("write_file", None).contains("write_file"));
    }

    #[test]
    fn results_are_capped_head_and_tail() {
        let long = "x".repeat(1000);
        let result =
            registry().dispatch("echo", &json!({ "text": long }).to_string(), &execution());
        assert!(!result.is_error());
        assert!(result.content.starts_with(&"x".repeat(16)));
        assert!(result.content.ends_with(&"x".repeat(16)));
        assert!(result.content.contains("[968 bytes elided]"), "{result:?}");
    }

    #[test]
    fn oversized_calls_are_redacted_archived_and_linked_to_the_call() {
        let root = std::env::temp_dir().join(format!(
            "gears-tool-result-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let artifacts = std::sync::Arc::new(
            crate::agent::artifact::LazyStore::new(root.clone(), "19-1".to_string(), 4096, 8192)
                .unwrap(),
        );
        let secret = "sk-gears-tool-result-unique-secret";
        crate::trace::redact(secret);
        let raw = format!("before {secret} after {}", "x".repeat(100));
        let expected = crate::trace::scrub(&raw);
        let result = registry().with_artifacts(artifacts.clone()).dispatch_call(
            "echo",
            &json!({"text": raw}).to_string(),
            "call-7",
            &execution(),
        );

        assert_eq!(result.outcome, ToolOutcome::Completed);
        assert!(result.content.contains("complete output is artifact 1"));
        assert!(result.retains_artifact());
        assert!(!result.content.contains(secret));
        let store = artifacts.get().unwrap();
        assert_eq!(store.read(1).unwrap(), expected.as_bytes());
        let metadata = store.metadata(1).unwrap();
        assert_eq!(metadata.artifact_type, "tool_output");
        assert_eq!(metadata.origin.producer, "echo");
        assert_eq!(metadata.origin.reference, "agent 0 tool call call-7");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn clamping_never_splits_a_character() {
        // Cutting at cap/2 = 5 lands mid-crab from both ends.
        let text = "🦀🦀🦀🦀";
        let clamped = clamp(text, 10);
        assert_eq!(clamped, "🦀\n… [8 bytes elided] …\n🦀");
        assert_eq!(clamp(text, 16), text);
    }
}
