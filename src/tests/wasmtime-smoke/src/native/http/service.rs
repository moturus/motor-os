//! Test-only images start these services through sys-init with svc:256 masks.
use moto_sdk::sys::{caps::ProcessRole, stats::ProcessInfoV1};

use super::*;

pub(super) fn run() -> Result<()> {
    let processes = processes()?;
    let init = processes
        .iter()
        .find(|p| p.active != 0 && p.debug_name().contains("sys-init"))
        .ok_or("missing sys-init process")?;
    let services: Vec<_> = processes
        .iter()
        .filter(|p| p.active != 0 && p.debug_name().contains("wasmtime-rt"))
        .collect();
    if services.len() != 2 {
        return Err(format!(
            "expected two sys-init Wasmtime services, found {}",
            services.len()
        )
        .into());
    }
    for service in &services {
        if service.parent_pid != init.pid || service.process_role != ProcessRole::None as u8 {
            return Err(format!(
                "service {}: parent={} role={}",
                service.pid, service.parent_pid, service.process_role
            )
            .into());
        }
    }
    for (protocol, port) in [("p2", 18180), ("p3", 18182)] {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        for _ in 0..4 {
            request(addr, &[], b"Hello, WASI!", true)?;
        }
        drop(connect(SocketAddr::from(([127, 0, 0, 1], port + 1)))?);
        println!(
            "PASS sys-init-{protocol}: role=None parent=sys-init configured_mask=256 requests=4"
        );
    }
    let started = Instant::now();
    for service in services {
        while process_active(service.pid)? {
            if started.elapsed() >= IO_TIMEOUT {
                return Err(format!("service {} survived shutdown", service.pid).into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    // Run the independent role matrix after these services have exited so
    // the small-VM compilation checks have the same baseline as the main suite.
    std::fs::write("/none/wasm-services/roles-start", "start")?;
    let started = Instant::now();
    loop {
        match std::fs::read_to_string("/none/wasm-services/roles-result") {
            Ok(report) => {
                print_role_log(&report)?;
                if report == "PASS" {
                    break;
                }
                return Err(format!("wasm roles: {report}").into());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if started.elapsed() >= Duration::from_secs(120) {
            print_role_log("role matrix did not finish within 120s")?;
            return Err("wasm role workflows did not finish within 120s".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    println!("PASS wasm workflows: None, Interactive, System and extra capabilities");

    // This SSH-side driver is Interactive; the System-only test launcher must
    // return a diagnostic here without starting work or aborting the process.
    let error = super::super::roles::run()
        .err()
        .ok_or("role launcher accepted Interactive")?;
    if !error
        .to_string()
        .contains("role launcher requires System, got Interactive")
    {
        return Err(format!("unexpected role launcher diagnostic: {error}").into());
    }
    println!("PASS role-launcher-diagnostic: {error}");
    Ok(())
}

fn print_role_log(report: &str) -> Result<()> {
    let log = std::fs::read_to_string("/none/wasm-services/roles.log")
        .map_err(|error| format!("wasm roles: {report}; reading log: {error}"))?;
    print!("{log}");
    Ok(())
}

fn processes() -> Result<Vec<ProcessInfoV1>> {
    let mut processes = Vec::new();
    let mut next = 0;
    loop {
        let mut batch = [ProcessInfoV1::default(); 32];
        let count =
            ProcessInfoV1::list(next, &mut batch).map_err(|e| format!("process list: {e:?}"))?;
        if count == 0 {
            return Ok(processes);
        }
        next = batch[count - 1].pid + 1;
        processes.extend_from_slice(&batch[..count]);
    }
}
