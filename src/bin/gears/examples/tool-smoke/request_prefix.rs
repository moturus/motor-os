//! Prefix snapshots are separate from history and retain their marked-entry identity.

use std::sync::{Arc, Mutex};

use gears::config::{Config, ContextConfig};
use gears::provider::{Completion, EventSink, Message, Provider, ProviderError, Request, ToolSpec};
use gears::runtime::{Approval, Permission, Runtime};
use gears::session::{RequestPrefix, Store};
use gears::tools::Registry;

#[derive(Default)]
struct Capture {
    requests: Mutex<Vec<Request>>,
    large_answer: bool,
}

impl Provider for Capture {
    fn complete(
        &self,
        request: &Request,
        _: &mut dyn EventSink,
    ) -> Result<Completion, ProviderError> {
        let mut requests = self.requests.lock().unwrap();
        requests.push(request.clone());
        Ok(Completion {
            content: if self.large_answer && requests.len() == 1 {
                "Original answer with details. ".repeat(1100)
            } else {
                "Nothing to save.".into()
            },
            ..Completion::default()
        })
    }
}

pub fn smoke() -> Result<(), String> {
    let base = std::env::temp_dir().join(format!("gears-request-prefix-{}", std::process::id()));
    std::fs::create_dir(&base).map_err(|error| error.to_string())?;
    let store = Store::with_root(&base, base.join("sessions"))?;
    let parent = store.create(false, None)?;
    assert_eq!(parent.request_prefix()?, None); // Old sessions have no snapshot.
    let path = parent.path().unwrap().to_path_buf();
    let provider = Arc::new(Capture {
        large_answer: true,
        ..Capture::default()
    });
    let config = Config {
        context: ContextConfig {
            window_tokens: 4096,
            output_reserve_tokens: 512,
            recent_tail_tokens: 128,
        },
        ..Config::default()
    };
    let mut runtime = Runtime::new_with_registry_at(
        provider.clone(),
        store.clone(),
        parent,
        &config,
        "executor".into(),
        Registry::default(),
        base.join("tools"),
    )?;
    let mut deny = |_: &Permission| Approval::Deny;
    runtime.turn("Original task".into(), &mut deny, &mut |_| Ok(()))?;
    let entry = runtime.session().active_leaf().unwrap().to_string();
    let prefix = runtime.session().request_prefix()?.unwrap();
    runtime.turn("Continue after compaction".into(), &mut deny, &mut |_| {
        Ok(())
    })?;
    {
        let requests = provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].system, prefix.system);
        assert_eq!(requests[0].tools, prefix.tools);
        assert_eq!(requests[1].system[0], gears::prompt::COMPACTION.trim());
        assert_eq!(requests[2].system, prefix.system);
        assert_eq!(requests[2].tools, prefix.tools);
        assert!(
            !requests[2]
                .messages
                .iter()
                .any(|m| m.text_content().contains("Original answer"))
        );
    }
    assert_eq!(runtime.session().request_prefix()?, Some(prefix.clone()));
    assert_eq!(
        runtime
            .session()
            .entries()
            .iter()
            .filter(|e| e.kind == "request_prefix")
            .count(),
        1
    );
    let selected = store.read(path.to_str().unwrap())?.at(&entry)?;
    assert_eq!(selected.request_prefix()?, Some(prefix.clone()));
    assert!(
        selected
            .context_messages()?
            .iter()
            .any(|m| m.text_content().contains("Original answer"))
    );
    assert!(
        Runtime::new_with_registry_preserving_prefix(
            provider.clone(),
            store.clone(),
            store.create(false, None)?,
            &config,
            "executor".into(),
            Registry::default(),
            prefix.clone(),
        )
        .is_err()
    );
    let child = store.clone_active_with_options(&selected, true)?;
    let reader = Arc::new(Capture::default());
    let mut review_prefix = prefix.clone();
    review_prefix
        .system
        .push("Frozen source instructions".into());
    review_prefix.tools.push(ToolSpec::new(
        "old_tool",
        "Frozen schema",
        serde_json::json!({"type":"object"}),
    ));
    let mut review = Runtime::new_with_registry_preserving_prefix(
        reader.clone(),
        store.clone(),
        child,
        &config,
        "reviewer".into(),
        Registry::default(),
        review_prefix.clone(),
    )?;
    let before = std::fs::read(&path).map_err(|error| error.to_string())?;
    review.turn(
        "Review this task; nothing to save is the default.".into(),
        &mut deny,
        &mut |_| Ok(()),
    )?;
    {
        let requests = reader.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].system[0], gears::prompt::COMPACTION.trim());
        assert_eq!(requests[1].system, review_prefix.system);
        assert_eq!(requests[1].tools, review_prefix.tools);
        assert!(
            requests[1]
                .messages
                .iter()
                .any(|m| m.text_content().contains("Conversation summary"))
        );
        assert!(
            requests[1]
                .messages
                .iter()
                .any(|m| m.text_content().contains("Review this task"))
        );
    }
    assert_eq!(
        std::fs::read(&path).map_err(|error| error.to_string())?,
        before
    );
    let oversized = RequestPrefix {
        system: vec!["Large prefix ".repeat(2000)],
        tools: Vec::new(),
    };
    assert!(
        Runtime::new_with_registry_preserving_prefix(
            reader.clone(),
            store.clone(),
            store.create(true, None)?,
            &config,
            "reviewer".into(),
            Registry::default(),
            oversized,
        )
        .err()
        .unwrap()
        .contains("prefix exceeds")
    );
    assert_eq!(reader.requests.lock().unwrap().len(), 2);
    assert_eq!(review.session().request_prefix()?, Some(review_prefix));
    review.new_session(true, None)?;
    review.turn("New unrelated task".into(), &mut deny, &mut |_| Ok(()))?;
    assert!(
        !reader
            .requests
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .system
            .iter()
            .any(|s| s.contains("Frozen source"))
    );
    assert!(
        reader
            .requests
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .tools
            .is_empty()
    );
    drop(review);
    let mut legacy = store.create(true, None)?;
    legacy.append_message(&Message::user("No recorded prefix"))?;
    assert_eq!(legacy.request_prefix()?, None);
    drop(runtime);
    let mut parent = store.open(path.to_str().unwrap())?;
    let changed = RequestPrefix {
        system: vec!["Changed instructions".into()],
        tools: vec![ToolSpec::new("read", "Changed tool", serde_json::json!({}))],
    };
    parent.record_request_prefix(&changed)?;
    assert_eq!(parent.request_prefix()?, Some(changed));
    assert_eq!(
        store
            .read(path.to_str().unwrap())?
            .at(&entry)?
            .request_prefix()?,
        Some(prefix)
    );
    parent.append(
        "request_prefix",
        &serde_json::json!({"system": 42, "tools": []}),
    )?;
    assert!(parent.request_prefix().is_err());
    drop(parent);
    std::fs::remove_dir_all(base).map_err(|error| error.to_string())?;
    println!("gears saved request prefix ALL PASS");
    Ok(())
}
