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

fn post_listener() {
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

async fn server_fn(mut server: io_channel::ServerConnection) {
    // Safety: our executor ensures the server won't be polled unless
    // a wakeup is received.
    if let Err(err) = unsafe { server.accept() } {
        log::error!("accept() failed: {err:?}");
        return;
    }

    // Create a replacement listener.
    post_listener();

    while let Ok(msg) = server.recv_async().await {
        if msg.status() != moto_rt::E_NOT_READY {
            log::error!(
                "Dropping conn 0x{:x} due to bad sqe {} {:?}.",
                server.wait_handle().as_u64(),
                msg.command,
                msg.status()
            );
            break;
        }

        match msg.command {
            io_channel::CMD_NOOP_OK => {
                let mut cqe = msg;
                if cqe.flags == io_channel::FLAG_CMD_NOOP_OK_TIMESTAMP {
                    cqe.payload.args_64_mut()[2] = moto_rt::time::Instant::now().as_u64();
                }

                cqe.status = moto_rt::E_OK;
                if let Err(err) = server.send_async(cqe).await {
                    log::error!(
                        "Dropping conn 0x{:x} due to send error {err:?}.",
                        server.wait_handle().as_u64(),
                    );
                    break;
                } else {
                    if let Err(err) = moto_sys::SysCpu::wake(server.wait_handle()) {
                        log::error!(
                            "Dropping conn 0x{:x} due to wake error {err:?}.",
                            server.wait_handle().as_u64(),
                        );
                        break;
                    }
                }
            }

            moto_sys_io::api_net::CMD_MIN..=moto_sys_io::api_net::CMD_MAX => {
                todo!()
            }
            _ => {
                log::info!(
                    "Dropping conn 0x{:x} due to bad sqe.",
                    server.wait_handle().as_u64(),
                );
                break;
            }
        }

        todo!()
    }
}

fn local_start() {
    const MIN_LISTENERS: usize = 3;
    for _ in 0..MIN_LISTENERS {
        post_listener();
    }

    log::debug!("Starting sys-io async runtime");
    local_executor::run_local();
}

pub fn start() {
    let _ = std::thread::Builder::new()
        .name("async-runtime".into())
        .spawn(|| local_start());
}
