//! Hermetic shipped-manifest checks, also installed as a developer-image test.

use std::path::Path;

use gears::config::Config;
use gears::mock::{MockServer, Script};
use gears::process::{Cancellation, Output};
use gears::tools::{ExecutionContext, Registry};
use serde_json::{Value, json};

#[path = "tool-smoke/directory_lock.rs"]
mod directory_lock;
#[path = "tool-smoke/file_access.rs"]
mod file_access;
#[path = "tool-smoke/fork_entry.rs"]
mod fork_entry;
#[path = "tool-smoke/owned_work.rs"]
mod owned_work;

#[cfg(not(test))]
fn main() -> Result<(), String> {
    let directory = std::env::args_os()
        .nth(1)
        .map(std::path::PathBuf::from)
        .ok_or("usage: tool-smoke GEARS_DIRECTORY [GEARS_EXECUTABLE]")?;
    let config = Config::load_user(Some(&directory.join("gears.toml")))?;
    smoke(&directory, &config)?;
    #[cfg(unix)]
    let gears = std::env::current_exe()
        .map_err(|error| error.to_string())?
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("gears");
    #[cfg(not(unix))]
    let gears = std::path::PathBuf::from("/devtools/bin/gears");
    let gears = std::env::args_os()
        .nth(2)
        .map(std::path::PathBuf::from)
        .unwrap_or(gears);
    owned_work::smoke(&gears, &directory.join("tools/sh"))?;
    directory_lock::smoke(&gears)?;
    fork_entry::smoke(&gears)?;
    file_access::smoke()?;
    println!("gears shipped tools ALL PASS");
    Ok(())
}

fn smoke(directory: &Path, config: &Config) -> Result<(), String> {
    let mut tools = Registry::load(&config.tools, directory)?;
    assert_eq!(tools.tools().len(), 14);
    assert_eq!(tools.enabled_tools().count(), 0);
    for name in [
        "sh", "ls", "head", "tail", "wc", "cat", "diff", "find", "sed", "curl",
    ] {
        tools.set_enabled(name, true)?;
    }
    #[cfg(not(unix))]
    tools.set_enabled("rg", true)?;
    let workspace = std::env::temp_dir().join(format!("gears-tools-smoke-{}", std::process::id()));
    std::fs::create_dir(&workspace).map_err(|error| error.to_string())?;
    let result = check_tools(&tools, &workspace);
    if result.is_ok() {
        std::fs::remove_dir_all(&workspace).map_err(|error| error.to_string())?;
    } else {
        eprintln!("tool smoke fixtures retained in {}", workspace.display());
    }
    result
}

fn execute(
    tools: &Registry,
    workspace: &Path,
    name: &str,
    arguments: Value,
    code: i32,
) -> Result<Output, String> {
    let tool = tools
        .enabled(name)
        .ok_or_else(|| format!("{name} unavailable"))?;
    let state = workspace.join("shell-state");
    let output = tool
        .execute(
            &arguments.to_string(),
            &ExecutionContext {
                workspace,
                session_id: "tool-smoke",
                session_path: None,
                shell_state: tool.process.shell_state.then_some(state.as_path()),
            },
            &Cancellation::new(),
            &mut |_, _| {},
        )
        .map_err(|error| format!("{name}: {error}"))?;
    if output.code != Some(code) || output.timed_out || output.cancelled {
        return Err(format!("{name}: unexpected outcome: {output:?}"));
    }
    if !tool.process.normal_exit_statuses.contains(&code) {
        return Err(format!("{name}: {code} is not a declared normal outcome"));
    }
    Ok(output)
}

fn check_tools(tools: &Registry, workspace: &Path) -> Result<(), String> {
    std::fs::create_dir(workspace.join("shell-state")).map_err(|error| error.to_string())?;
    let directory = "literal * [x]";
    let file = "literal * [x]/a * [x].txt";
    let other = "literal * [x]/b ? [y].txt";
    std::fs::create_dir(workspace.join(directory)).map_err(|error| error.to_string())?;
    std::fs::write(workspace.join(file), "first\nlast\n").map_err(|error| error.to_string())?;
    std::fs::write(workspace.join(other), "first\nchanged\n").map_err(|error| error.to_string())?;
    let listed = execute(tools, workspace, "ls", json!({"path": directory}), 0)?;
    assert!(listed.stdout.contains("a * [x].txt"), "{listed:?}");
    let head = execute(
        tools,
        workspace,
        "head",
        json!({"path": file, "lines": 1}),
        0,
    )?;
    assert_eq!(head.stdout, "first\n");
    let tail = execute(
        tools,
        workspace,
        "tail",
        json!({"path": file, "lines": 1}),
        0,
    )?;
    assert_eq!(tail.stdout, "last\n");
    let wc = execute(
        tools,
        workspace,
        "wc",
        json!({"path": file, "mode": "lines"}),
        0,
    )?;
    assert_eq!(wc.stdout.split_whitespace().next(), Some("2"));
    let cat = execute(tools, workspace, "cat", json!({"path": file}), 0)?;
    assert_eq!(cat.stdout, "first\nlast\n");
    let diff = execute(
        tools,
        workspace,
        "diff",
        json!({"left": file, "right": other}),
        1,
    )?;
    assert!(
        diff.stdout.contains("last") && diff.stdout.contains("changed"),
        "{diff:?}"
    );
    let found = execute(
        tools,
        workspace,
        "find",
        json!({"path": directory, "type": "file"}),
        0,
    )?;
    assert!(
        found.stdout.contains(file) && found.stdout.contains(other),
        "{found:?}"
    );
    let sed = execute(
        tools,
        workspace,
        "sed",
        json!({"path": file, "script": "s/first/replaced/"}),
        0,
    )?;
    assert_eq!(sed.stdout, "replaced\nlast\n");
    assert_eq!(
        std::fs::read_to_string(workspace.join(file)).unwrap(),
        "first\nlast\n"
    );
    #[cfg(not(unix))]
    {
        let rg = execute(
            tools,
            workspace,
            "rg",
            json!({"path": file, "pattern": "first", "fixed_strings": true}),
            0,
        )?;
        assert_eq!(rg.stdout, "first\n");
        execute(
            tools,
            workspace,
            "rg",
            json!({"path": file, "pattern": "absent"}),
            1,
        )?;
    }
    execute(
        tools,
        workspace,
        "sh",
        json!({"command": "[ -z \"${OPENROUTER_API_KEY+x}\" ] && export TOOL_SMOKE_STATE=retained && cd 'literal * [x]'"}),
        0,
    )?;
    let restored = execute(
        tools,
        workspace,
        "sh",
        json!({"command": "printf '%s\\n' \"$TOOL_SMOKE_STATE\"; pwd"}),
        0,
    )?;
    assert_eq!(
        restored.stdout,
        format!("retained\n{}\n", workspace.join(directory).display())
    );
    check_curl(tools, workspace)
}

fn check_curl(tools: &Registry, workspace: &Path) -> Result<(), String> {
    let server = MockServer::start(vec![
        Script::new().write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"),
        Script::new().write(b"HTTP/1.1 302 Found\r\nLocation: /destination\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
    ]).map_err(|error| error.to_string())?;
    let ok = execute(
        tools,
        workspace,
        "curl",
        json!({"url": server.url("/ok")}),
        0,
    )?;
    assert!(
        ok.stdout.contains("HTTP/1.1 200 OK") && ok.stdout.contains("hello"),
        "{ok:?}"
    );
    let redirect = execute(
        tools,
        workspace,
        "curl",
        json!({"url": server.url("/redirect")}),
        0,
    )?;
    assert!(
        redirect.stdout.contains("HTTP/1.1 302 Found")
            && redirect.stdout.contains("Location: /destination"),
        "{redirect:?}"
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].target, "/ok");
    assert_eq!(requests[1].target, "/redirect");
    Ok(())
}

#[test]
fn shipped_tools_follow_their_manifests() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    let config = Config::load_user(Some(&directory.join("config/gears.toml"))).unwrap();
    smoke(directory, &config).unwrap();
}

#[test]
fn nested_work_stops_on_cancellation_and_nested_timeouts() {
    owned_work::smoke(
        Path::new(env!("CARGO_BIN_EXE_gears")),
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tools/sh"),
    )
    .unwrap();
}

#[test]
fn another_gears_cannot_replace_a_live_directory_lock() {
    directory_lock::smoke(Path::new(env!("CARGO_BIN_EXE_gears"))).unwrap();
}

#[test]
fn atomic_workspace_replacement_keeps_executable_access() {
    file_access::smoke().unwrap();
}

#[test]
fn startup_forks_select_old_entries_without_locking_or_changing_the_parent() {
    fork_entry::smoke(Path::new(env!("CARGO_BIN_EXE_gears"))).unwrap();
}
