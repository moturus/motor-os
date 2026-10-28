//! The daemon's single control listener and connection, independent of forwarding.
use super::{Ready, stats::Shared};
use crate::{config::Result, control::*, motor_ipc as ipc};
use moto_sdk::ipc::sync::{ChannelSize, LocalServer};
use moto_sdk::rt;
use moto_sdk::sys::{SysCpu, SysHandle, SysObj};
use std::sync::Arc;

pub(super) struct Service {
    shared: Shared,
    ring: ipc::Handle,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Service {
    pub(super) fn start(
        shared: Shared,
        ready: Arc<Ready>,
        deadline: Option<rt::time::Instant>,
    ) -> Result<Self> {
        let (ring, wait) = SysObj::create_ipc_pair(SysHandle::SELF, SysHandle::SELF, 0)
            .map_err(|_| "cannot create control wakeup")?;
        let ring = ipc::Handle(ring);
        let wait = ipc::Handle(wait);
        let values = shared.clone();
        let (started, outcome) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("wg:control".into())
            .spawn(move || {
                let server = LocalServer::new(
                    &format!("wg-control-{}", moto_sdk::sys::current_pid()),
                    ChannelSize::Small,
                    1,
                    1,
                );
                match server {
                    Ok(server) => {
                        if started.send(Ok(())).is_ok()
                            && serve(server, &wait, &values, &ready).is_err()
                        {
                            ready.stop(true);
                        }
                    }
                    Err(_) => {
                        let _ = started.send(Err("cannot create control endpoint"));
                    }
                }
            })
            .map_err(|_| "cannot start control service")?;
        if let Some(deadline) = deadline {
            outcome
                .recv_timeout(deadline.duration_since(rt::time::Instant::now()))
                .map_err(|_| "control service did not become ready before startup deadline")??;
        } else {
            outcome
                .recv()
                .map_err(|_| "control service exited during startup")??;
        }
        Ok(Self {
            shared,
            ring,
            thread: Some(thread),
        })
    }

    pub(super) fn finish(&mut self, result: Result<()>) {
        self.shared.lock().unwrap().cleanup = Some(result);
        let _ = SysCpu::wake(self.ring.0);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.finish(Err("daemon exited before cleanup completed"));
        }
    }
}

fn acknowledge_stop(server: &mut LocalServer, handle: SysHandle, result: Result<()>) {
    let Some(connection) = server.get_connection(handle) else {
        return;
    };
    let status = if result.is_ok() {
        rt::E_OK
    } else {
        rt::E_NOT_READY
    };
    if ipc::respond(connection, status, &[]).is_err() {
        return;
    }
    // Keep the channel alive until its sole client consumes the reply and
    // closes it. No listener/client timers.
    while server.wait(SysHandle::NONE, &[]).is_ok() {
        if let Some(connection) = server.get_connection(handle)
            && connection.have_req()
        {
            let _ = ipc::respond(connection, rt::E_NOT_READY, &[]);
        }
    }
}

fn serve(
    mut server: LocalServer,
    wake: &ipc::Handle,
    shared: &Shared,
    ready: &Ready,
) -> Result<()> {
    let mut snapshot: Option<Snapshot> = None;
    let mut stopping = None;
    loop {
        if let Some(result) = shared.lock().unwrap().cleanup {
            if let Some(handle) = stopping.take() {
                acknowledge_stop(&mut server, handle, result);
            }
            return Ok(());
        }
        let wakers = match server.wait(SysHandle::NONE, &[wake.0]) {
            Ok(wakers) => wakers,
            Err(handles) => {
                if handles.contains(&wake.0) {
                    return Err("control wakeup failed");
                }
                snapshot = None;
                // With one connection, this error belongs to the sole client.
                // Forget its pending reply; the scheduler still completes STOP.
                stopping = None;
                continue;
            }
        };
        for handle in wakers {
            if handle == wake.0 {
                continue;
            }
            let Some(connection) = server.get_connection(handle) else {
                continue;
            };
            if !connection.connected() {
                continue;
            }
            if ipc::authenticate(handle, None).is_err() {
                connection.disconnect();
                snapshot = None;
                continue;
            }
            if !connection.have_req() || stopping.is_some() {
                continue;
            }
            let result = match ipc::request(connection) {
                Ok((GET_INTERFACE, payload)) if payload.is_empty() => {
                    let mut captured = shared.lock().unwrap().snapshot.clone();
                    captured.interface.age_ms = millis(captured.captured.elapsed());
                    let reply = captured.interface.encode();
                    snapshot = Some(captured);
                    reply
                }
                Ok((GET_PEER, payload)) if payload.len() == 2 => {
                    let index = u16::from_le_bytes(payload.try_into().unwrap()) as usize;
                    snapshot
                        .as_ref()
                        .and_then(|snapshot| snapshot.peers.get(index))
                        .ok_or("invalid peer index or missing interface query")
                        .and_then(Peer::encode)
                }
                Ok((STOP, payload)) if payload.is_empty() && snapshot.is_some() => {
                    shared.lock().unwrap().snapshot.interface.state = State::Stopping;
                    stopping = Some(handle);
                    ready.stop(false);
                    continue;
                }
                _ => Err("invalid control request"),
            };
            let (status, payload) = match result {
                Ok(payload) => (rt::E_OK, payload),
                Err(_) => (rt::E_INVALID_ARGUMENT, Vec::new()),
            };
            if ipc::respond(connection, status, &payload).is_err() {
                snapshot = None;
            }
        }
    }
}
