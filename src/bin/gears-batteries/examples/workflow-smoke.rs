//! Portable end-to-end batteries fixture. No external provider is contacted.

#[path = "workflow-smoke/support.rs"]
mod support;

use std::sync::Arc;

use gears::provider::{Completion, EventSink, Provider, ProviderError, Request};
use gears::runtime::{Approval, Approver, Permission, Runtime};
use gears::session::Store;

struct Initialize;
impl Provider for Initialize {
    fn complete(
        &self,
        request: &Request,
        _: &mut dyn EventSink,
    ) -> Result<Completion, ProviderError> {
        assert!(request.tools.iter().any(|tool| tool.name == "todo"));
        assert!(
            request
                .system
                .iter()
                .any(|text| text.contains("Fixture instructions:"))
        );
        Ok(Completion {
            content: "initialized".into(),
            ..Completion::default()
        })
    }
}

struct NoTools;
impl Approver for NoTools {
    fn approve(&mut self, _: &Permission) -> Approval {
        panic!("initialization must not request a tool");
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let binary =
        std::path::PathBuf::from(args.next().ok_or("usage: workflow-smoke BATTERIES RUSTC")?);
    let compiler = args.next().ok_or("missing check compiler")?;
    let fixture = support::Fixture::new(&binary, &compiler)?;
    let store = Store::with_root(&fixture.workspace, fixture.state.clone())?;
    let session = store.create(false, None)?;
    let group = session.path().unwrap().parent().unwrap().to_path_buf();
    let sessions = vec![session.id().to_string()];
    let mut runtime = Runtime::new(
        Arc::new(Initialize),
        store,
        session,
        &fixture.config,
        "fixture/model".into(),
    )?;
    runtime.turn(fixture.label.clone(), &mut NoTools, &mut |_| Ok(()))?;
    let state = runtime
        .session()
        .hook_state(&fixture.hook)
        .ok_or("missing batteries state")?;
    let snapshots = vec![
        state["prompt_snapshot"]
            .as_str()
            .ok_or("missing prompt snapshot")?
            .to_string(),
    ];
    assert_eq!(state["turn_number"], 1);
    assert!(!fixture.workspace.join("checked.rmeta").exists());
    drop(runtime);
    fixture.cleanup(&group, &sessions, &snapshots)?;
    println!("gears batteries initialization ALL PASS");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("batteries workflow fixture failed: {error}");
        std::process::exit(1);
    }
}
