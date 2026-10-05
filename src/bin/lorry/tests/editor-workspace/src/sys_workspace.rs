use super::*;

fn args(record: &Value) -> Vec<&str> {
    record["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|arg| arg.as_str().unwrap())
        .collect()
}

// This manual acceptance case consumes a separately fetched, admitted copy.
// The regular editor contract stays hermetic and needs no system checkout.
pub(super) fn run(
    lorry: &Path,
    toolchain: &Toolchain,
    work: &Path,
    shipped: &Value,
    root: &Path,
    home: &Path,
) -> io::Result<()> {
    let root = root.canonicalize()?;
    let home = home.canonicalize()?;
    let admission = root.join(".lorry/dependencies-v2.toml");
    let saved_admission = work.join("sys-admission.toml");
    let lock = fs::read(root.join("Cargo.lock"))?;
    fs::rename(&admission, &saved_admission)?;
    let fetched_result = std::panic::catch_unwind(|| {
        phase(lorry, toolchain, work, shipped, &root, &home, "fetched")
    });
    fs::rename(&saved_admission, &admission)?;
    match fetched_result {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
    for view in ["admitted", "generated"] {
        phase(lorry, toolchain, work, shipped, &root, &home, view)?;
    }
    assert_eq!(fs::read(root.join("Cargo.lock"))?, lock);
    println!(
        "PASS: fetched sys workspace navigation, denied execution, generated code, and admitted sysbox save diagnostics"
    );
    Ok(())
}

fn phase(
    lorry: &Path,
    toolchain: &Toolchain,
    work: &Path,
    shipped: &Value,
    root: &Path,
    home: &Path,
    view: &str,
) -> io::Result<()> {
    let admitted = view != "fetched";
    let generated = view == "generated";
    let wrappers = work.join(view);
    let calls = wrappers.join("invocations");
    fs::create_dir_all(&calls)?;
    let cargo = wrappers.join("cargo");
    fs::copy(env::current_exe()?, &cargo)?;
    fs::write(
        wrappers.join("lorry-path"),
        lorry.to_string_lossy().as_bytes(),
    )?;
    let mut options = shipped.clone();
    options["cargo"]["buildScripts"]["overrideCommand"][0] = json!(cargo);
    options["check"]["workspace"] = json!(false);
    if generated {
        // Netstack uses handwritten constants under cfg(test). Its application
        // view proves generated navigation; default settings cover save checks.
        options["cfg"]["setTest"] = json!(false);
    }
    if !admitted || generated {
        options["checkOnSave"] = json!(false);
    }
    let mut paths = vec![wrappers.clone(), toolchain.sysroot.join("bin")];
    paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
    let mut server = Command::new(&toolchain.rust_analyzer);
    server
        .current_dir(root)
        .env("CARGO", &cargo)
        .env("RUSTC", toolchain.sysroot.join("bin/rustc"))
        .env_remove("RUSTUP_TOOLCHAIN")
        .env("HOME", home)
        .env("CARGO_HOME", home.join(".cargo"))
        .env("CARGO_NET_OFFLINE", "true")
        .env("MOTURUS_STDIO_NO_TERMINAL", "true")
        .env("PATH", env::join_paths(paths).unwrap())
        .env("RA_LOG", "project_model=info,flycheck=info");
    if admitted {
        let mut case = SemanticCase::start_command(
            server,
            root,
            &[("sys", root)],
            options,
            Instant::now() + Duration::from_secs(180),
        )?;
        case.wait_for_quiescence()?;
        if generated {
            let generated_user = root.join("sys-io/netstack/src/iface/neighbor.rs");
            case.open(&generated_user)?;
            let definition =
                uri_path(&case.definition(&generated_user, "IFACE_NEIGHBOR_CACHE_COUNT;")?)?;
            assert!(
                definition.starts_with(root.join("target/rust-analyzer/lorry")),
                "{definition:?}"
            );
            assert_eq!(definition.file_name().unwrap(), "config.rs");
            assert!(
                fs::read_to_string(&definition)?.contains("pub const IFACE_NEIGHBOR_CACHE_COUNT")
            );
        } else {
            let source = root.join("tools/sysbox/src/main.rs");
            let original = fs::read_to_string(&source)?;
            case.open(&source)?;
            let saved =
                format!("{original}\ncompile_error!(\"sysbox editor acceptance marker\");\n");
            fs::write(&source, &saved)?;
            let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                case.save_text(&source, 2, &saved)?;
                case.wait_for_flychecks(1)?;
                case.wait_for_rustc_message(&file_uri(&source), "sysbox editor acceptance marker")
            }));
            fs::write(&source, original)?;
            match checked {
                Ok(result) => result?,
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
        case.shutdown()?;
    } else {
        fetched_navigation(server, root, options, &calls)?;
    }
    let records = fs::read_dir(&calls)?
        .map(|entry| {
            serde_json::from_slice::<Value>(&fs::read(entry?.path())?).map_err(io::Error::other)
        })
        .collect::<io::Result<Vec<_>>>()?;
    let pass = records
        .iter()
        .find(|record| args(record).contains(&"--compile-time-deps"))
        .expect("missing sys compile-time pass");
    assert_eq!(Path::new(pass["cwd"].as_str().unwrap()), root);
    let output = fs::read_to_string(pass["stdout"].as_str().unwrap())?;
    let events = output
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    if admitted {
        assert!(
            events
                .iter()
                .any(|event| event["reason"] == "build-script-executed")
        );
        assert_eq!(
            events.last().unwrap(),
            &json!({"reason":"build-finished", "success":true})
        );
        if !generated {
            let sysbox_id = format!("path+{}#0.1.0", file_uri(&root.join("tools/sysbox")));
            assert!(
                records
                    .iter()
                    .any(|record| args(record).windows(2).any(|pair| {
                        matches!(pair[0], "-p" | "--package")
                            && (pair[1] == "sysbox" || pair[1] == sysbox_id)
                    }))
            );
        }
    } else {
        assert_eq!(
            events,
            [json!({"reason":"build-finished", "success":false})]
        );
        assert!(
            fs::read_to_string(pass["stderr"].as_str().unwrap())?
                .contains("requires workspace admission")
        );
    }
    Ok(())
}

fn fetched_navigation(
    mut server: Command,
    root: &Path,
    options: Value,
    calls: &Path,
) -> io::Result<()> {
    use rust_analyzer_smoke::semantic::position;
    use rust_analyzer_smoke::session::LspSession;

    let deadline = Instant::now() + Duration::from_secs(180);
    let mut session = LspSession::spawn(&mut server)?;
    let response = session.request(
        "initialize",
        json!({
            "processId":null, "rootUri":file_uri(root),
            "workspaceFolders":[{"name":"sys", "uri":file_uri(root)}],
            "capabilities":{"window":{"workDoneProgress":true},
                "workspace":{"workspaceFolders":true},
                "experimental":{"serverStatusNotification":true}},
            "initializationOptions":options
        }),
        deadline,
    )?;
    assert!(response.get("error").is_none(), "{response}");
    session.notify("initialized", Some(json!({})))?;
    // Admission denial is an expected editor warning. Require it explicitly
    // instead of using the successful-workspace helper's health assertion.
    loop {
        if let Some(status) = session
            .notifications()
            .rev()
            .find(|notification| notification.method == "experimental/serverStatus")
            && status.params["quiescent"] == true
        {
            assert_eq!(status.params["health"], "warning");
            assert!(
                status.params["message"]
                    .as_str()
                    .unwrap()
                    .contains("Failed to run build scripts")
            );
            break;
        }
        session.pump(deadline)?;
    }
    for (relative, needle, suffix) in [
        (
            "tools/sysbox/src/commands/free.rs",
            "Collector;",
            "lib/moto-stats/src/userspace.rs",
        ),
        (
            "tools/sysbox/src/commands/less.rs",
            "KeyEventKind,",
            "src/event.rs",
        ),
    ] {
        let source = root.join(relative);
        let text = fs::read_to_string(&source)?;
        session.notify("textDocument/didOpen", Some(json!({
            "textDocument":{"uri":file_uri(&source), "languageId":"rust", "version":1, "text":text}
        })))?;
        let response = session.request(
            "textDocument/definition",
            json!({
                "textDocument":{"uri":file_uri(&source)}, "position":position(&text, needle)?
            }),
            deadline,
        )?;
        let definition = &response["result"][0];
        let uri = definition["targetUri"]
            .as_str()
            .or_else(|| definition["uri"].as_str())
            .expect("missing source definition");
        let path = uri_path(uri)?;
        assert!(path.ends_with(suffix), "{path:?}");
        if relative.ends_with("free.rs") {
            assert!(path.starts_with(root));
        } else {
            let metadata = fs::read_dir(calls)?
                .map(|entry| {
                    serde_json::from_slice::<Value>(&fs::read(entry?.path())?)
                        .map_err(io::Error::other)
                })
                .collect::<io::Result<Vec<_>>>()?;
            let call = metadata
                .iter()
                .find(|record| {
                    args(record).first() == Some(&"metadata")
                        && !args(record).contains(&"--no-deps")
                })
                .expect("missing resolved metadata");
            let metadata: Value =
                serde_json::from_slice(&fs::read(call["stdout"].as_str().unwrap())?)?;
            let package = metadata["packages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|package| package["name"] == "crossterm")
                .unwrap();
            assert!(
                package["source"]
                    .as_str()
                    .unwrap()
                    .starts_with("git+https://github.com/moturus/crossterm.git")
            );
            let manifest = Path::new(package["manifest_path"].as_str().unwrap());
            assert!(path.starts_with(manifest.parent().unwrap()), "{path:?}");
        }
    }
    session.shutdown(deadline)
}
