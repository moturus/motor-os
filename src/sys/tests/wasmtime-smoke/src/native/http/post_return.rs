//! An exhausted p3 instance must finish its post-return work before teardown.
use super::*;

pub(super) fn run(suite: &mut Suite) -> Result<()> {
    let mut job = suite.start(
        "p3-serve-post-return",
        &format!(
            "MOTOR_OS_CAPS=0x100 {RUNTIME} serve --allow-precompiled \
             -W component-model-async -S p3,cli --no-logging-prefix \
             --addr 127.0.0.1:0 --shutdown-addr 127.0.0.1:0 \
             --max-instance-reuse-count 1 --max-concurrent-requests 2 \
             --max-concurrent-connections 8 \
             {FIXTURES}/p3_cli_serve_post_return.cwasm"
        ),
        false,
    )?;
    let log = job.wait_stderr("Serving HTTP on http://")?;
    let addr = address(&log, "Serving HTTP on http://")?;
    let shutdown = address(&log, "Listening for shutdown on tcp://")?;
    let pid = runtime_pid(&job)?;
    for _ in 0..4 {
        thread::scope(|scope| -> Result<()> {
            let clients: Vec<_> = (0..2)
                .map(|_| scope.spawn(|| request(addr, &[], &[], false).map_err(|e| e.to_string())))
                .collect();
            for client in clients {
                client.join().map_err(|_| "post-return client panicked")??;
            }
            Ok(())
        })?;
    }
    // Each handler returns its empty response, then yields ten times before
    // printing. Shutdown must join that work even with instance reuse disabled.
    drop(connect(shutdown)?);
    let (out, _) = suite.wait(&mut job, 0)?;
    super::super::expect("p3-serve-post-return", &out, &"please see me\n".repeat(8))?;
    if process_active(pid)? {
        return Err("p3 post-return runtime survived shutdown".into());
    }
    Ok(())
}
