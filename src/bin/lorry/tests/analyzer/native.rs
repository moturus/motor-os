use crate::case::SemanticCase;
use crate::process::ServerProcess;
use crate::semantic::{file_uri, uri_path};
use serde_json::json;
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};
#[path = "native/assertions.rs"]
mod assertions;
#[path = "native/diagnostics.rs"]
mod diagnostics;
use assertions::{require_completion, require_generated_definition};
const SERVER: &str = "/user/lib/rust/bin/rust-analyzer";
const SOURCE: &str = "#![feature(motor_ext)]\n#[path = \"café.rs\"]\nmod café;\npub fn runtime() -> u64 { std::os::motor::rt_version() }\npub fn generated() -> u32 { generated_dependency::GENERATED }\npub fn environment() -> &'static str { generated_dependency::ENVIRONMENT }\npub fn unicode() -> u32 { café::VALUE }\npub fn editable() -> u32 { 7 }\n";

pub fn run(evidence: &Path) -> io::Result<()> {
    fs::create_dir(evidence)?;
    let total_started = Instant::now();
    let deadline = total_started + std::time::Duration::from_secs(90);
    let base = PathBuf::from(format!("/none/tmp/ra-{:x}", std::process::id()));
    fs::create_dir(&base)?;
    crate::support::share(&base, true);
    let root = base.join("first");
    let second = base.join("second");
    for workspace in [&root, &second] {
        crate::workspaces::create("lorry", workspace)?;
    }
    fs::write(root.join("src/lib.rs"), SOURCE)?;
    fs::write(root.join("src/café.rs"), "pub const VALUE: u32 = 7;\n")?;
    crate::modes::share(&base)?;
    // A hex PID and one-byte name leave ` check` visible in the process
    // catalog's 29-byte prefix, including at u32::MAX.
    let lorry = base.join("l");
    crate::copy_executable(Path::new(env!("CARGO_BIN_EXE_lorry")), &lorry)?;
    for workspace in [&root, &second] {
        let output = Command::new(&lorry)
            .args(["vendor", "--locked", "--offline", "--accept-all"])
            .current_dir(workspace)
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!("native admission: {output:?}")));
        }
    }
    let mut sampler =
        ServerProcess::spawn(Command::new(std::env::current_exe()?).arg("--resource-sampler"))?;
    if sampler.read_until(deadline)? != json!({"ready":true}) {
        return Err(io::Error::other(
            "resource sampler did not report readiness",
        ));
    }
    let options = json!({
        "linkedProjects": [root.join("Cargo.toml"), second.join("Cargo.toml")],
        "cargo": {"target": "x86_64-unknown-motor", "targetDir": true, "sysroot": "discover",
            "buildScripts": {"enable": true, "useRustcWrapper": false}},
        "check": {"targets": ["x86_64-unknown-motor"]}, "procMacro": {"enable": false},
        "files": {"watcher": "client"}
    });
    let mut command = Command::new(SERVER);
    command
        .env("CARGO", &lorry)
        .env("RUSTC", "/user/lib/rust/bin/rustc")
        .env(
            "RA_LOG",
            "project_model=debug,rust_analyzer::flycheck=debug",
        );
    let start = Instant::now();
    let mut case = SemanticCase::start_command(
        command,
        &root,
        &[("native", &root), ("second", &second)],
        options,
        deadline,
    )?;
    let initialized = start.elapsed();
    let mut timings = json!({"initialize_ms": initialized.as_secs_f64() * 1000.0});
    let result = (|| {
        case.wait_for_quiescence()?;
        case.wait_for_flychecks(2)?;
        timings["quiescence_ms"] = json!(start.elapsed().as_secs_f64() * 1000.0);
        println!(
            "native initialize={initialized:?} quiescence={:?}",
            start.elapsed()
        );
        let source = root.join("src/lib.rs");
        let uri = case.open_text(&source, SOURCE)?;
        let definition =
            case.text_request("textDocument/definition", &source, SOURCE, "rt_version")?;
        let location = definition
            .as_array()
            .and_then(|locations| locations.first())
            .unwrap_or(&definition);
        let target = location["uri"]
            .as_str()
            .or_else(|| location["targetUri"].as_str())
            .ok_or_else(|| io::Error::other(format!("missing std definition: {definition}")))?;
        if !uri_path(target)?
            .starts_with("/user/lib/rust/lib/rustlib/src/rust/library/std/src/os/motor")
        {
            return Err(io::Error::other(format!(
                "wrong Motor std definition: {definition}"
            )));
        }
        let hover = case.text_request("textDocument/hover", &source, SOURCE, "GENERATED }")?;
        if !hover.to_string().contains("42") {
            return Err(io::Error::other(format!(
                "missing generated hover: {hover}"
            )));
        }
        let generated =
            case.text_request("textDocument/definition", &source, SOURCE, "GENERATED }")?;
        require_generated_definition(&generated, &root)?;
        // The env!-derived string hover: strings render through MIR
        // evaluation, the hover case most sensitive to allocator cost.
        let environment_started = Instant::now();
        let hover = case.text_request("textDocument/hover", &source, SOURCE, "ENVIRONMENT }")?;
        timings["environment_hover_ms"] =
            json!(environment_started.elapsed().as_secs_f64() * 1000.0);
        if !hover.to_string().contains("from-build-script") {
            return Err(io::Error::other(format!(
                "missing environment string hover: {hover}"
            )));
        }
        println!(
            "native environment-hover={:?}",
            environment_started.elapsed()
        );
        let completion_started = Instant::now();
        let completion =
            case.text_request("textDocument/completion", &source, SOURCE, "GENERATED }")?;
        let completion_elapsed = completion_started.elapsed();
        timings["first_completion_ms"] = json!(completion_elapsed.as_secs_f64() * 1000.0);
        require_completion(&completion, "GENERATED")?;
        require_completion(&completion, "ENVIRONMENT")?;
        println!("native first-completion={completion_elapsed:?}");
        let second_source = second.join("src/lib.rs");
        let second_text = fs::read_to_string(second.join("src/lib.rs"))?;
        case.open_text(&second_source, &second_text)?;
        let generated = case.text_request(
            "textDocument/definition",
            &second_source,
            &second_text,
            "GENERATED\n",
        )?;
        require_generated_definition(&generated, &second)?;
        let unicode = case.text_request("textDocument/definition", &source, SOURCE, "VALUE }")?;
        if !unicode
            .to_string()
            .contains(&file_uri(&root.join("src/café.rs")))
        {
            return Err(io::Error::other(format!(
                "wrong Unicode definition: {unicode}"
            )));
        }
        let broken = SOURCE.replace(
            "editable() -> u32 { 7 }",
            "editable() -> u32 { \"native flycheck marker\" }",
        );
        fs::write(&source, &broken)?;
        let check_started = Instant::now();
        case.save_text(&source, 2, &broken)?;
        case.wait_for_flychecks(1)?;
        case.wait_for_rustc_error(&uri, true)?;
        let check_elapsed = check_started.elapsed();
        timings["error_on_save_ms"] = json!(check_elapsed.as_secs_f64() * 1000.0);
        println!("native error-on-save={check_elapsed:?}");
        fs::write(&source, SOURCE)?;
        let fix_started = Instant::now();
        case.save_text(&source, 3, SOURCE)?;
        case.wait_for_flychecks(1)?;
        case.wait_for_rustc_error(&uri, false)?;
        timings["fix_on_save_ms"] = json!(fix_started.elapsed().as_secs_f64() * 1000.0);
        let shutdown_started = Instant::now();
        case.shutdown()?;
        timings["shutdown_ms"] = json!(shutdown_started.elapsed().as_secs_f64() * 1000.0);
        Ok(())
    })();
    fs::write(evidence.join("server.stderr"), case.stderr_tail())?;
    // Preserve completed measurements even if a later semantic assertion failed.
    fs::write(
        evidence.join("timings.json"),
        serde_json::to_vec_pretty(&timings)?,
    )?;
    result?;
    sampler.close_stdin();
    let resources = sampler.read_until(deadline)?;
    let status = sampler.wait_until(deadline)?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "resource sampler failed: {status}; {}",
            sampler.stderr_tail()
        )));
    }
    fs::write(
        evidence.join("resources.json"),
        serde_json::to_vec(&resources)?,
    )?;
    let summary =
        crate::resources::summarize_for_lorry(&resources, SERVER, lorry.to_str().unwrap())?;
    fs::write(
        evidence.join("resource-summary.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    crate::resources::check_limits(&summary)?;
    crate::resources::check_processes(
        &summary,
        SERVER,
        lorry.to_str().unwrap(),
        &[root.to_str().unwrap(), second.to_str().unwrap()],
    )?;
    diagnostics::validate(&case.stderr_tail(), &[&root, &second], &lorry)?;
    timings["total_ms"] = json!(total_started.elapsed().as_secs_f64() * 1000.0);
    fs::write(
        evidence.join("timings.json"),
        serde_json::to_vec_pretty(&timings)?,
    )?;
    println!(
        "native resource summary: {}",
        evidence.join("resource-summary.json").display()
    );
    println!(
        "native rust-analyzer initial semantic case PASS; evidence={}",
        evidence.display()
    );
    fs::remove_dir_all(base)?;
    Ok(())
}
