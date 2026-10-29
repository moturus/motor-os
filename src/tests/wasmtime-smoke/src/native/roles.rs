//! sys-init supplies System authority only on the test service images.
use std::path::Path;
use std::time::{Duration, Instant};

use moto_sdk::sys::{ProcessStaticPage, caps::ProcessRole, stats::ProcessInfoV1};

use super::{COMPILER, RUNTIME, Result, Suite, expect, fs, http, runtime_pid};

pub(super) const DIRECTORY: &str = "/none/wasm-services";

pub(super) fn open_log() -> Result<fs::File> {
    Ok(fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(Path::new(DIRECTORY).join("roles.log"))?)
}

pub(super) fn run() -> Result<()> {
    let caps = ProcessStaticPage::get().capabilities;
    let role = ProcessRole::from_caps(caps);
    if role != ProcessRole::System {
        return Err(format!("role launcher requires System, got {role:?} (caps={caps:#x})").into());
    }
    let started = Instant::now();
    while !Path::new(DIRECTORY).join("roles-start").try_exists()? {
        if started.elapsed() >= Duration::from_secs(120) {
            return Err("service checks did not start the role matrix within 120s".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut suite = Suite::new_in(
        "wasm-roles",
        "/devtools/wasmtime/sources.txt",
        Path::new(DIRECTORY),
        open_log()?,
    )?;
    fs::write(suite.root.join("hello.js"), "console.log('roles');\n")?;
    // Extra spawn/log authority must also be accepted, including without a
    // role bit. Filesystem writes and networking still need their own bits.
    for (name, caps, role) in [
        ("none", 0, ProcessRole::None),
        ("none-extra", 0xc, ProcessRole::None),
        ("interactive", 0x4c, ProcessRole::Interactive),
        ("system", 0xd, ProcessRole::System),
    ] {
        suite.command(
            &format!("{name}-engine-tests"),
            &format!("MOTOR_OS_CAPS={:#x} {DIRECTORY}/engine-tests", caps | 0x200),
            0,
        )?;
        for (label, command) in [
            (
                "emit-plugin",
                format!("javy emit-plugin -o {name}-plugin.wasm"),
            ),
            (
                "init-plugin",
                format!(
                    "javy init-plugin {DIRECTORY}/plugin-p1.wasm --deterministic -o {name}-initialized.wasm"
                ),
            ),
            ("build", format!("javy build hello.js -o {name}.wasm")),
            (
                "build-dynamic",
                format!(
                    "javy build hello.js -C dynamic -C plugin={name}-plugin.wasm -o {name}-dynamic.wasm"
                ),
            ),
            (
                "compile",
                format!("wasmtime compile {name}.wasm -o {name}.cwasm"),
            ),
        ] {
            suite.command(
                &format!("{name}-{label}"),
                &format!("MOTOR_OS_CAPS={:#x} /devtools/bin/{command}", caps | 0x200),
                0,
            )?;
        }
        for (label, command) in [
            ("wasmi", format!("wasmi {name}.wasm")),
            (
                "wasmi-dynamic",
                format!("wasmi {name}-dynamic.wasm --plugin {name}-plugin.wasm"),
            ),
            ("native-raw", format!("wasmtime run {name}.wasm")),
            (
                "native-load",
                format!("wasmtime run --allow-precompiled {name}.cwasm"),
            ),
            (
                "runtime-load",
                format!("wasmtime-rt run --allow-precompiled {name}.cwasm"),
            ),
            (
                "pulley",
                format!("wasmtime run --target pulley64 {name}.wasm"),
            ),
        ] {
            let (out, err) = suite.command(
                &format!("{name}-{label}"),
                &format!("MOTOR_OS_CAPS={caps:#x} /devtools/bin/{command}"),
                0,
            )?;
            expect(label, &out, "roles\n")?;
            expect(label, &err, "")?;
        }
        for (label, tool, extension) in [("full", COMPILER, "wasm"), ("runtime", RUNTIME, "cwasm")]
        {
            let mut job = suite.start(
                &format!("{name}-serve-{label}"),
                &format!(
                    "MOTOR_OS_CAPS={:#x} {tool} serve --allow-precompiled -S cli \
                     --addr 127.0.0.1:0 --shutdown-addr 127.0.0.1:0 \
                     {DIRECTORY}/p2_cli_serve_hello_world.{extension}",
                    caps | 0x100
                ),
                false,
            )?;
            let log = job.wait_stderr("Serving HTTP on http://")?;
            let addr = http::address(&log, "Serving HTTP on http://")?;
            let shutdown = http::address(&log, "Listening for shutdown on tcp://")?;
            let pid = runtime_pid(&job)?;
            let mut info = [ProcessInfoV1::default(); 1];
            let count = ProcessInfoV1::list(pid, &mut info).map_err(|e| format!("{e:?}"))?;
            if count != 1 || info[0].pid != pid || info[0].process_role != role as u8 {
                return Err(format!("{name}-{label}: server did not run as {role:?}").into());
            }
            http::request(addr, &[], b"Hello, WASI!", false)?;
            drop(http::connect(shutdown)?);
            suite.wait(&mut job, 0)?;
        }
    }
    suite.finish()
}
