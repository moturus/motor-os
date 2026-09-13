use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::case::SemanticCase;
use crate::process::ServerProcess;
use crate::semantic::{file_uri, uri_path};

mod assertions;
mod diagnostics;
mod remote;

use assertions::{require_completion, require_generated_definition};
use remote::{Remote, checked, quoted};

const SERVER: &str = "/devtools/rust/bin/rust-analyzer";
const SOURCE: &str = "#![feature(motor_ext)]\n#[path = \"café.rs\"]\nmod café;\npub fn runtime() -> u64 { std::os::motor::rt_version() }\npub fn generated() -> u32 { generated_dependency::GENERATED }\npub fn environment() -> &'static str { generated_dependency::ENVIRONMENT }\npub fn unicode() -> u32 { café::VALUE }\npub fn editable() -> u32 { 7 }\n";

pub fn run(evidence: &Path, sampler_binary: &Path) -> io::Result<()> {
    fs::create_dir(evidence)?;
    let evidence = evidence.canonicalize()?;
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .canonicalize()?;
    let total_started = Instant::now();
    // Match the existing Lorry LSP case's total bound, including staging.
    let remote = Remote {
        repository,
        deadline: total_started + Duration::from_secs(90),
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = PathBuf::from(format!("/devtools/tmp/ra-{}-{nonce:x}", std::process::id()));
    let second = root.with_file_name(format!("ra-{}-{nonce:x}-second", std::process::id()));
    let manifest = remote.run("/system/bin/cat /devtools/toolchain/manifest")?;
    fs::write(evidence.join("manifest"), &manifest.stdout)?;
    let version = remote.run(&format!("{SERVER} --version"))?;
    fs::write(evidence.join("version"), &version.stdout)?;
    let expected = String::from_utf8_lossy(&manifest.stdout)
        .lines()
        .filter_map(|line| line.strip_prefix("native_rust_analyzer_expected_version_base64="))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if expected.len() != 1 {
        return Err(io::Error::other("manifest lacks unique analyzer version"));
    }
    // Decode on the host using the same base64 format as assembly publication.
    let encoded = evidence.join("version.base64");
    fs::write(&encoded, &expected[0])?;
    let decoded = checked(Command::new("base64").arg("-d").arg(encoded).output()?)?;
    if String::from_utf8_lossy(&version.stdout).trim() != String::from_utf8_lossy(&decoded.stdout) {
        return Err(io::Error::other(
            "native analyzer version differs from assembly",
        ));
    }
    let fixture = remote
        .repository
        .join("src/tests/rust-analyzer-smoke/fixtures/lorry");
    fs::write(evidence.join("lib.rs"), SOURCE)?;
    fs::write(evidence.join("café.rs"), "pub const VALUE: u32 = 7;\n")?;
    let batch = evidence.join("stage.sftp");
    fs::write(
        &batch,
        format!(
            "put -r {} {}\nput {} {}/src/lib.rs\nput {} {}/src/café.rs\n",
            quoted(&fixture)?,
            quoted(&root)?,
            quoted(&evidence.join("lib.rs"))?,
            quoted(&root)?,
            quoted(&evidence.join("café.rs"))?,
            quoted(&root)?
        ),
    )?;
    remote.upload(&batch)?;
    let guest_sampler = root.join("resource-sampler");
    fs::write(
        &batch,
        format!(
            "put {} {}\n",
            quoted(&sampler_binary.canonicalize()?)?,
            quoted(&guest_sampler)?
        ),
    )?;
    remote.upload(&batch)?;
    fs::write(
        &batch,
        format!("put -r {} {}\n", quoted(&fixture)?, quoted(&second)?),
    )?;
    remote.upload(&batch)?;
    let mut sampler = ServerProcess::spawn(&mut remote.ssh(&guest_sampler.to_string_lossy())?)?;
    if sampler.read_until(remote.deadline)? != json!({"ready": true}) {
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
    let command = remote.ssh(&format!("CARGO=/devtools/bin/lorry PATH=/devtools/bin:/system/bin TMPDIR=/devtools/tmp RA_LOG=project_model=debug,rust_analyzer::flycheck=debug {SERVER}"))?;
    let start = Instant::now();
    let mut case = SemanticCase::start_command(
        command,
        &root,
        &[("native", &root), ("second", &second)],
        options,
        remote.deadline,
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
            .starts_with("/devtools/rust/lib/rustlib/src/rust/library/std/src/os/motor")
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
        let second_text = fs::read_to_string(fixture.join("src/lib.rs"))?;
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
        remote.write_text(&evidence, &source, &broken)?;
        let check_started = Instant::now();
        case.save_text(&source, 2, &broken)?;
        case.wait_for_flychecks(1)?;
        case.wait_for_rustc_error(&uri, true)?;
        let check_elapsed = check_started.elapsed();
        timings["error_on_save_ms"] = json!(check_elapsed.as_secs_f64() * 1000.0);
        println!("native error-on-save={check_elapsed:?}");
        remote.write_text(&evidence, &source, SOURCE)?;
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
    let resources = sampler.read_until(remote.deadline)?;
    let status = sampler.wait_until(remote.deadline)?;
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
    let summary = crate::resources::summarize(&resources, SERVER)?;
    fs::write(
        evidence.join("resource-summary.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    crate::resources::check_limits(&summary)?;
    crate::resources::check_processes(
        &summary,
        SERVER,
        &[root.to_str().unwrap(), second.to_str().unwrap()],
    )?;
    diagnostics::validate(&case.stderr_tail(), &[&root, &second])?;
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
    Ok(())
}
