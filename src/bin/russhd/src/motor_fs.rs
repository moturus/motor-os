//! russhd's connections to sys-io's filesystem service, which it opens itself
//! for what std has no call for: Motor OS's permissions and a flush.

use moto_sdk::io::fs::FsClient;
use std::rc::Rc;

pub(crate) fn io_error(error: moto_sdk::rt::Error) -> std::io::Error {
    std::io::Error::from_raw_os_error(i32::from(moto_sdk::rt::ErrorCode::from(error)))
}

/// Run the connection backoff and the thread-local Motor IPC on a blocking
/// worker so the SSH event loop can continue serving other sessions.
pub async fn with_client<T: Send + 'static>(
    operation: impl AsyncFnOnce(Rc<FsClient>) -> moto_sdk::rt::Result<T> + Send + 'static,
) -> std::io::Result<T> {
    tokio::task::spawn_blocking(move || {
        moto_sdk::async_runtime::LocalRuntime::try_new()?
            .block_on(async { operation(connect()?).await })
    })
    .await
    .map_err(std::io::Error::other)?
    .map_err(io_error)
}

/// Connects to sys-io's filesystem service. It keeps a few listeners waiting
/// and adds one only when a client takes one, so sessions that connect together
/// can find none left, which it reports as NotReady. rt.vdso waits for its own
/// connection; this one gets the same waits: 50 usec at first, four times as
/// long after each refusal, every wait +/-50%. A wait that would take the
/// total past 10 seconds is the last: it ends at a random moment between 10
/// and 15 seconds in all, and the next refusal stands. moto-sdk 0.2, which
/// russhd builds with, has no call that does this.
pub fn connect() -> moto_sdk::rt::Result<Rc<FsClient>> {
    // The last wait ends between these two totals.
    const MIN_WAITED_USEC: u64 = 10_000_000;
    const MAX_WAITED_USEC: u64 = 15_000_000;

    let mut wait_usec = 50;
    let mut waited_usec = 0;
    loop {
        match FsClient::connect() {
            Err(moto_sdk::rt::Error::NotReady) if waited_usec < MIN_WAITED_USEC => {}
            result => return result,
        }
        // The timestamp counter is the random number: it differs between
        // sessions that were refused at the same moment.
        let random = moto_sdk::rt::time::Instant::now().as_u64();
        let mut wait = wait_usec / 2 + random % (wait_usec + 1);
        if waited_usec + wait > MIN_WAITED_USEC {
            let waited = MIN_WAITED_USEC + random % (MAX_WAITED_USEC - MIN_WAITED_USEC + 1);
            wait = waited - waited_usec;
        }
        std::thread::sleep(std::time::Duration::from_micros(wait));
        waited_usec += wait;
        wait_usec *= 4;
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test(flavor = "current_thread")]
    async fn filesystem_operation_runs_off_the_ssh_event_loop() {
        let (started, worker_started) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let operation = super::with_client(async move |client| {
            started.send(()).unwrap();
            released
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("SSH event loop stalled during a filesystem operation");
            client.stat("/").await
        });
        let event_loop = async {
            worker_started.await.unwrap();
            release.send(()).unwrap();
        };
        let (result, ()) = tokio::join!(operation, event_loop);
        result.unwrap();
    }
}
