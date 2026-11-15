#![allow(dead_code)]

#[path = "analyzer/child.rs"]
mod child;
#[path = "analyzer/editor.rs"]
mod editor;
#[path = "analyzer/lorry.rs"]
mod lorry;
#[path = "control/modes.rs"]
mod modes;
#[cfg(target_os = "motor")]
#[path = "analyzer/native.rs"]
mod native;
#[path = "analyzer/process_tests.rs"]
mod process_tests;
#[path = "analyzer/resources.rs"]
mod resources;
#[path = "analyzer/sampler.rs"]
mod sampler;
#[path = "analyzer/session_tests.rs"]
mod session_tests;
mod support;
#[path = "analyzer/workspaces.rs"]
mod workspaces;

use motor_analyzer_tests::{case, process, semantic, session, transport};
use std::{fs, io, path::Path};

fn main() -> io::Result<()> {
    if let Some((lorry, log)) = child::wrapper_paths() {
        if log.parent().unwrap().join("editor-wrapper").exists() {
            return editor::wrapper();
        }
        child::cargo_wrapper(&lorry, &log);
    }
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.first().is_some_and(|arg| arg == "--fake-child") {
        child::fake_child(arguments.get(1).map(String::as_str));
        return Ok(());
    }
    #[cfg(target_os = "motor")]
    if arguments
        .first()
        .is_some_and(|arg| arg == "--resource-sampler")
    {
        return sampler::run();
    }
    let p = support::Project::new();
    // This harness is serial. Pin the compiler and isolate user configuration
    // before creating protocol reader threads or launching the server.
    unsafe {
        #[cfg(not(target_os = "motor"))]
        {
            if std::env::var_os("RUSTUP_HOME").is_none() {
                std::env::set_var(
                    "RUSTUP_HOME",
                    Path::new(&std::env::var_os("HOME").unwrap()).join(".rustup"),
                );
            }
            std::env::set_var("HOME", p.root.join("home"));
        }
        std::env::set_var("RUSTC", p.rustc());
    }
    process_tests::run();
    session_tests::run();
    lorry::run(Path::new(env!("CARGO_BIN_EXE_lorry")))?;
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    editor::run_all(repo, &p.root)?;
    #[cfg(target_os = "motor")]
    native::run(&p.root.join("native-evidence"))?;
    println!("PASS: analyzer protocol, target semantics and editor integration");
    Ok(())
}

fn copy_executable(source: &Path, destination: &Path) -> io::Result<()> {
    fs::copy(source, destination)?;
    support::executable_permissions(destination)
}
