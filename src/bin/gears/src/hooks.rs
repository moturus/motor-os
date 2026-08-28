//! Versioned command-hook protocol and ordered composition.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::HookConfig;
use crate::process::{Cancellation, Request as ProcessRequest, run};
use crate::provider::{Message, ToolCall, ToolSpec};
use crate::session::{HookState, Session};

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Serialize)]
struct Event<'a> {
    protocol_version: u32,
    event: &'a str,
    hook: &'a str,
    workspace: &'a Path,
    session: SessionView<'a>,
    payload: Value,
}

#[derive(Serialize)]
struct SessionView<'a> {
    id: &'a str,
    path: Option<&'a Path>,
    state: Option<Value>,
}

#[derive(Deserialize, Default)]
struct Response {
    protocol_version: Option<u32>,
    #[serde(default)]
    prompt_fragments: Vec<String>,
    #[serde(default)]
    tools: Vec<ToolSpec>,
    input: Option<String>,
    messages: Option<Vec<Message>>,
    decision: Option<Decision>,
    tool_result: Option<ToolResult>,
    compaction: Option<CompactionAdvice>,
    state: Option<Value>,
    context: Option<Message>,
    notice: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    Ask,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    pub content: String,
    #[serde(default)]
    pub is_error: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct CompactionAdvice {
    #[serde(default)]
    pub cancel: bool,
    pub focus: Option<String>,
    pub output_reserve_tokens: Option<u64>,
    pub recent_tail_tokens: Option<u64>,
    pub summary: Option<String>,
    pub retained_tail: Option<Vec<Message>>,
}

pub struct Initialize {
    pub prompt_fragments: Vec<String>,
    pub tools: Vec<ToolSpec>,
}

struct Hook {
    config: HookConfig,
}

pub struct Manager {
    workspace: PathBuf,
    hooks: Vec<Hook>,
    tool_owner: HashMap<String, usize>,
    prompt_fragments: Vec<String>,
    tools: Vec<ToolSpec>,
}

impl Manager {
    pub fn initialize(
        configs: Vec<HookConfig>,
        workspace: PathBuf,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<Self, String> {
        let hooks = configs
            .into_iter()
            .map(|config| Hook { config })
            .collect::<Vec<_>>();
        let mut manager = Self {
            workspace,
            hooks,
            tool_owner: HashMap::new(),
            prompt_fragments: Vec::new(),
            tools: Vec::new(),
        };
        let mut names = HashSet::from(["sh".to_string()]);
        for index in 0..manager.hooks.len() {
            let response = manager.invoke(
                index,
                "initialize",
                Value::Object(Default::default()),
                session,
                cancellation,
                notice,
            )?;
            for fragment in response.prompt_fragments {
                if !fragment.trim().is_empty() {
                    manager.prompt_fragments.push(fragment);
                }
            }
            for tool in response.tools {
                validate_tool(&tool)?;
                if !names.insert(tool.name.clone()) {
                    return Err(format!("duplicate tool name {:?}", tool.name));
                }
                manager.tool_owner.insert(tool.name.clone(), index);
                manager.tools.push(tool);
            }
        }
        Ok(manager)
    }

    pub fn initialized(&self) -> Initialize {
        Initialize {
            prompt_fragments: self.prompt_fragments.clone(),
            tools: self.tools.clone(),
        }
    }

    pub fn manifest(&self) -> Value {
        serde_json::json!({
            "hooks": self.hooks.iter().map(|hook| &hook.config.name).collect::<Vec<_>>(),
            "tools": self.tools,
        })
    }

    pub fn transform_input(
        &self,
        mut input: String,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<String, String> {
        for index in 0..self.hooks.len() {
            let response = self.invoke(
                index,
                "input",
                serde_json::json!({"input": input}),
                session,
                cancellation,
                notice,
            )?;
            if let Some(transformed) = response.input {
                input = transformed;
            }
        }
        Ok(input)
    }

    pub fn transform_context(
        &self,
        mut messages: Vec<Message>,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<Vec<Message>, String> {
        for index in 0..self.hooks.len() {
            let response = self.invoke(
                index,
                "context",
                serde_json::json!({"messages": messages}),
                session,
                cancellation,
                notice,
            )?;
            if let Some(transformed) = response.messages {
                messages = transformed;
            }
            if let Some(context) = response.context {
                messages.push(context);
            }
        }
        Ok(messages)
    }

    pub fn permission(
        &self,
        call: &ToolCall,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Decision {
        let mut result = Decision::Ask;
        for index in 0..self.hooks.len() {
            let response = self.invoke(
                index,
                "permission",
                serde_json::json!({"tool_call": call}),
                session,
                cancellation,
                notice,
            );
            let decision = match response {
                Ok(response) => response.decision.unwrap_or(Decision::Ask),
                Err(error) => {
                    notice(format!(
                        "permission hook {} failed; denying call: {error}",
                        self.hooks[index].config.name
                    ));
                    Decision::Deny
                }
            };
            result = match (result, decision) {
                (_, Decision::Deny) => Decision::Deny,
                (Decision::Deny, _) => Decision::Deny,
                (_, Decision::Allow) => Decision::Allow,
                (current, Decision::Ask) => current,
            };
        }
        result
    }

    pub fn owns_tool(&self, name: &str) -> bool {
        self.tool_owner.contains_key(name)
    }

    pub fn execute_tool(
        &self,
        call: &ToolCall,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<ToolResult, String> {
        let index = self
            .tool_owner
            .get(&call.name)
            .copied()
            .ok_or_else(|| format!("no hook owns tool {:?}", call.name))?;
        let response = self.invoke(
            index,
            "tool_execute",
            serde_json::json!({"tool_call": call}),
            session,
            cancellation,
            notice,
        )?;
        response
            .tool_result
            .ok_or_else(|| format!("hook returned no result for tool {:?}", call.name))
    }

    pub fn transform_tool_result(
        &self,
        call: &ToolCall,
        mut result: ToolResult,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<ToolResult, String> {
        for index in 0..self.hooks.len() {
            let response = self.invoke(
                index,
                "tool_result",
                serde_json::json!({"tool_call": call, "tool_result": result}),
                session,
                cancellation,
                notice,
            )?;
            if let Some(transformed) = response.tool_result {
                result = transformed;
            }
        }
        Ok(result)
    }

    pub fn before_compact(
        &self,
        payload: Value,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<CompactionAdvice, String> {
        let mut combined = CompactionAdvice::default();
        for index in 0..self.hooks.len() {
            let response = self.invoke(
                index,
                "before_compact",
                payload.clone(),
                session,
                cancellation,
                notice,
            )?;
            if let Some(advice) = response.compaction {
                if advice.cancel {
                    combined.cancel = true;
                }
                if advice.focus.is_some() {
                    combined.focus = advice.focus;
                }
                if advice.output_reserve_tokens.is_some() {
                    combined.output_reserve_tokens = advice.output_reserve_tokens;
                }
                if advice.recent_tail_tokens.is_some() {
                    combined.recent_tail_tokens = advice.recent_tail_tokens;
                }
                if advice.summary.is_some() {
                    combined.summary = advice.summary;
                    combined.retained_tail = advice.retained_tail;
                }
            }
        }
        Ok(combined)
    }

    pub fn notify(
        &self,
        event: &str,
        payload: Value,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) {
        for index in 0..self.hooks.len() {
            if let Err(error) =
                self.invoke(index, event, payload.clone(), session, cancellation, notice)
            {
                notice(format!(
                    "hook {} failed during {event}: {error}",
                    self.hooks[index].config.name
                ));
            }
        }
    }

    fn invoke(
        &self,
        index: usize,
        event_name: &str,
        payload: Value,
        session: &mut Session,
        cancellation: &Cancellation,
        notice: &mut dyn FnMut(String),
    ) -> Result<Response, String> {
        let hook = &self.hooks[index];
        let event = Event {
            protocol_version: PROTOCOL_VERSION,
            event: event_name,
            hook: &hook.config.name,
            workspace: &self.workspace,
            session: SessionView {
                id: session.id(),
                path: session.path(),
                state: session.hook_state(&hook.config.name),
            },
            payload,
        };
        let stdin = serde_json::to_vec(&event)
            .map_err(|error| format!("cannot serialize hook event: {error}"))?;
        let output = run(
            &ProcessRequest {
                program: hook.config.command[0].clone(),
                args: hook.config.command[1..].to_vec(),
                cwd: self.workspace.clone(),
                stdin: Some(stdin),
                timeout: hook.config.timeout,
                max_output_bytes: hook.config.max_output_bytes,
                env: Vec::new(),
                remove_env: vec![crate::provider::KEY_ENV.to_string()],
            },
            cancellation,
            &mut |_, _| {},
        )?;
        if !output.stderr.trim().is_empty() {
            notice(format!(
                "hook {}: {}",
                hook.config.name,
                output.stderr.trim()
            ));
        }
        if output.cancelled {
            return Err("cancelled".to_string());
        }
        if output.timed_out {
            return Err(format!(
                "timed out after {}s",
                hook.config.timeout.as_secs()
            ));
        }
        if output.code != Some(0) {
            return Err(format!("exited unsuccessfully: {}", output.status));
        }
        if output.stdout_dropped > 0 {
            return Err(format!(
                "stdout exceeded {} bytes",
                hook.config.max_output_bytes
            ));
        }
        let raw: Value = serde_json::from_str(output.stdout.trim())
            .map_err(|error| format!("invalid JSON result: {error}"))?;
        validate_result_fields(event_name, &raw)?;
        let response: Response = serde_json::from_value(raw)
            .map_err(|error| format!("invalid result shape: {error}"))?;
        if response.protocol_version.unwrap_or(PROTOCOL_VERSION) != PROTOCOL_VERSION {
            return Err("hook returned an incompatible protocol_version".to_string());
        }
        if let Some(message) = response.notice.as_deref() {
            notice(format!("hook {}: {message}", hook.config.name));
        }
        if response.state.is_some() || response.context.is_some() {
            session.append_hook_state(&HookState {
                hook: hook.config.name.clone(),
                state: response
                    .state
                    .clone()
                    .or_else(|| session.hook_state(&hook.config.name))
                    .unwrap_or(Value::Null),
                context: response.context.clone(),
            })?;
        }
        Ok(response)
    }
}

fn validate_tool(tool: &ToolSpec) -> Result<(), String> {
    if tool.name.is_empty()
        || !tool
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(format!("invalid hook tool name {:?}", tool.name));
    }
    if !tool.parameters.is_object() {
        return Err(format!(
            "tool {:?} parameters must be a JSON object",
            tool.name
        ));
    }
    Ok(())
}

fn validate_result_fields(event: &str, value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("hook result must be a JSON object")?;
    let mut allowed = HashSet::from(["protocol_version", "state", "context", "notice"]);
    match event {
        "initialize" => allowed.extend(["prompt_fragments", "tools"]),
        "input" => {
            allowed.insert("input");
        }
        "context" => {
            allowed.insert("messages");
        }
        "permission" => {
            allowed.insert("decision");
        }
        "tool_execute" | "tool_result" => {
            allowed.insert("tool_result");
        }
        "before_compact" => {
            allowed.insert("compaction");
        }
        _ => {}
    }
    for field in object.keys() {
        if !allowed.contains(field.as_str()) {
            return Err(format!("field {field:?} is not valid for event {event:?}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn fixture(name: &str) -> (PathBuf, Session) {
        let root = std::env::temp_dir().join(format!("gears-hooks-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let store = crate::session::Store::with_root(&workspace, root.join("state")).unwrap();
        let session = store.create(true, None).unwrap();
        (workspace, session)
    }

    #[cfg(unix)]
    fn hook(name: &str, script: &str, timeout: std::time::Duration) -> HookConfig {
        HookConfig {
            name: name.to_string(),
            command: vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            timeout,
            max_output_bytes: 4096,
        }
    }

    #[test]
    fn event_fields_are_event_specific() {
        assert!(
            validate_result_fields(
                "permission",
                &serde_json::json!({"decision": "allow", "state": {"n": 1}})
            )
            .is_ok()
        );
        assert!(
            validate_result_fields(
                "permission",
                &serde_json::json!({"input": "not allowed here"})
            )
            .is_err()
        );
    }

    #[test]
    fn tool_names_and_schemas_are_checked() {
        assert!(
            validate_tool(&ToolSpec::new(
                "valid_tool",
                "test",
                serde_json::json!({"type": "object"})
            ))
            .is_ok()
        );
        assert!(
            validate_tool(&ToolSpec::new(
                "bad tool",
                "test",
                serde_json::json!({"type": "object"})
            ))
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn transforms_are_ordered_and_state_is_durable() {
        let (workspace, mut session) = fixture("ordered");
        let first = hook(
            "first",
            r#"event=$(cat)
case "$event" in
  *'"event":"initialize"'*) printf '%s' '{"state":{"ready":true}}' ;;
  *'"event":"input"'*) printf '%s' '{"input":"first"}' ;;
  *) printf '%s' '{}' ;;
esac"#,
            std::time::Duration::from_secs(2),
        );
        let second = hook(
            "second",
            r#"event=$(cat)
case "$event" in
  *'"event":"initialize"'*) printf '%s' '{}' ;;
  *'"event":"input"'*'"input":"first"'*) printf '%s' '{"input":"second"}' ;;
  *'"event":"input"'*) exit 7 ;;
  *) printf '%s' '{}' ;;
esac"#,
            std::time::Duration::from_secs(2),
        );
        let cancellation = Cancellation::new();
        let mut notices = Vec::new();
        let manager = Manager::initialize(
            vec![first, second],
            workspace,
            &mut session,
            &cancellation,
            &mut |notice| notices.push(notice),
        )
        .unwrap();
        assert_eq!(
            manager
                .transform_input(
                    "original".to_string(),
                    &mut session,
                    &cancellation,
                    &mut |notice| notices.push(notice),
                )
                .unwrap(),
            "second"
        );
        assert_eq!(session.hook_state("first").unwrap()["ready"], true);
    }

    #[cfg(unix)]
    #[test]
    fn duplicate_registered_tools_are_rejected() {
        let (workspace, mut session) = fixture("duplicate-tool");
        let script = r#"cat >/dev/null
printf '%s' '{"tools":[{"name":"same","description":"test","parameters":{"type":"object"}}]}'"#;
        let result = Manager::initialize(
            vec![
                hook("one", script, std::time::Duration::from_secs(2)),
                hook("two", script, std::time::Duration::from_secs(2)),
            ],
            workspace,
            &mut session,
            &Cancellation::new(),
            &mut |_| {},
        );
        assert!(matches!(result, Err(error) if error.contains("duplicate tool name")));
    }

    #[cfg(unix)]
    #[test]
    fn permission_denial_wins_over_allow() {
        let (workspace, mut session) = fixture("permission-order");
        let permission_hook = |name, decision| {
            hook(
                name,
                &format!(
                    r#"event=$(cat)
case "$event" in
  *'"event":"permission"'*) printf '%s' '{{"decision":"{decision}"}}' ;;
  *) printf '%s' '{{}}' ;;
esac"#
                ),
                std::time::Duration::from_secs(2),
            )
        };
        let cancellation = Cancellation::new();
        let manager = Manager::initialize(
            vec![
                permission_hook("allow", "allow"),
                permission_hook("deny", "deny"),
            ],
            workspace,
            &mut session,
            &cancellation,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(
            manager.permission(
                &ToolCall::new("c1", "sh", r#"{"command":"true"}"#),
                &mut session,
                &cancellation,
                &mut |_| {},
            ),
            Decision::Deny
        );
    }

    #[cfg(unix)]
    #[test]
    fn malformed_timeout_and_cancellation_deny_permission() {
        for (name, permission, cancellation) in [
            ("malformed", "printf '%s' not-json", Cancellation::new()),
            ("timeout", "sleep 1; printf '%s' '{}'", Cancellation::new()),
            ("cancel", "sleep 1; printf '%s' '{}'", {
                let cancellation = Cancellation::new();
                cancellation.cancel();
                cancellation
            }),
        ] {
            let (workspace, mut session) = fixture(name);
            let script = format!(
                r#"event=$(cat)
case "$event" in
  *'"event":"permission"'*) {permission} ;;
  *) printf '%s' '{{}}' ;;
esac"#
            );
            let timeout = if name == "timeout" {
                std::time::Duration::from_millis(20)
            } else {
                std::time::Duration::from_secs(2)
            };
            let manager = Manager::initialize(
                vec![hook(name, &script, timeout)],
                workspace,
                &mut session,
                &Cancellation::new(),
                &mut |_| {},
            )
            .unwrap();
            let mut notices = Vec::new();
            assert_eq!(
                manager.permission(
                    &ToolCall::new("c1", "sh", r#"{"command":"true"}"#),
                    &mut session,
                    &cancellation,
                    &mut |notice| notices.push(notice),
                ),
                Decision::Deny,
                "{name}"
            );
            assert!(notices.iter().any(|notice| notice.contains("denying")));
        }
    }
}
