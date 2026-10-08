#![cfg(unix)]

// The process-wide interrupt flag must be tested in its own test binary.
use std::time::Duration;

use gears::config::HookConfig;
use gears::hooks::Manager;
use gears::process::Cancellation;
use gears::session::Store;

#[test]
fn an_interrupted_question_still_delivers_its_cancelled_answer() {
    let root =
        std::env::temp_dir().join(format!("gears-question-interrupt-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let log = root.join("answer.json");
    let store = Store::with_root(&root, root.join("sessions")).unwrap();
    let mut session = store.create(true, None).unwrap();
    let cancellation = Cancellation::new();
    let config = HookConfig {
        name: "question".into(),
        events: Some(vec!["initialize".into(), "answer".into()]),
        command: vec!["/bin/sh".into(), "-c".into(),
            "event=$(cat); case \"$event\" in *'\"event\":\"initialize\"'*) printf '{\"question\":{\"id\":\"q1\",\"text\":\"Publish?\",\"choices\":[{\"value\":\"yes\",\"label\":\"Publish\"},{\"value\":\"no\",\"label\":\"Discard\"}]}}' ;; *) printf '%s' \"$event\" > \"$1\"; printf '{}' ;; esac".into(),
            "question".into(), log.display().to_string()],
        timeout: Duration::from_secs(2), max_output_bytes: 4096,
    };
    let manager = Manager::initialize(
        vec![config],
        root.clone(),
        &[],
        serde_json::json!({}),
        &mut session,
        &cancellation,
        &mut |_| {},
    )
    .unwrap();
    let pending = manager.take_question().unwrap();
    gears::platform::note_interrupt();
    assert!(cancellation.cancelled());
    manager
        .answer(
            &pending,
            None,
            true,
            &mut session,
            &cancellation,
            &mut |_| {},
        )
        .unwrap();
    let event: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(log).unwrap()).unwrap();
    assert_eq!(event["event"], "answer");
    assert_eq!(event["payload"]["answer"], serde_json::Value::Null);
    assert_eq!(event["payload"]["cancelled"], true);
    assert!(
        cancellation.cancelled(),
        "answer cleared the user's cancellation"
    );
    assert!(gears::platform::take_interrupt());
    std::fs::remove_dir_all(root).unwrap();
}
