//! Async runtime for sys-io.
//!
//! Using tokio runtime, or some other runtime, would mean
//! we will have to express Motor OS wait/wake primitives
//! in terms of this runtime; see e.g. how tokio runtime
//! for Motor OS implemented via Mio via FDs and Registry
//! in rt.vdso.
//!
//! But in sys-io we only deal with VirtIO and our own
//! IPC constructs, so having a small/compact runtime
//! makes things much cleaner (and faster?).

use moto_ipc::io_channel;

mod local_executor;

fn local_start() {
    const MIN_LISTENERS: usize = 3;
    for _ in 0..MIN_LISTENERS {
        let listener = match io_channel::ServerConnection::create("sys-io-async") {
            Ok(server) => server,
            Err(err) => {
                panic!("Failed to spawn an async sys-io listener: {err:?}");
            }
        };

        let handle = listener.wait_handle();

        local_executor::add_task(local_executor::Task::new(
            handle,
            server_fn(listener),
            #[cfg(debug_assertions)]
            "server task".to_owned(),
        ));

        #[cfg(debug_assertions)]
        log::debug!("new listener handle 0x{:x}", handle.as_u64());
    }

    log::debug!("Starting sys-io async runtime");
    local_executor::run_local();
}

pub fn start() {
    let _ = std::thread::Builder::new()
        .name("async-runtime".into())
        .spawn(|| local_start());
}

async fn server_fn(mut server: io_channel::ServerConnection) {
    if let Err(err) = unsafe { server.accept() } {
        log::error!("accept() failed: {err:?}");
        return;
    }

    while let Ok(msg) = server.recv_async().await {
        todo!()
    }
}
