//! sys-io stats provider: a synchronous-RPC service ("sys-io-stats") that
//! exposes sys-io's metrics via the moto-stats protocol.
//!
//! sys-io's NET and FS stats live inside single-threaded async runtimes, so they
//! cannot be read from this thread directly. On `CMD_QUERY_METRICS` we poll them
//! out of those runtimes (see [`crate::runtime::net::stats`] and
//! [`crate::runtime::fs::stats`]); `CMD_DESCRIBE` is answered from static
//! metadata. Best effort, never precise — consistent with the rest of Motor OS
//! stats.

use moto_sdk::ipc::sync::*;
use moto_sys::SysHandle;

/// This provider's service URL and registry name.
const STATS_URL: &str = "sys-io-stats";
const PROVIDER_NAME: &str = "sys-io";

/// Spawn the stats-server thread. Safe to call before the net runtime is up: the
/// provider simply returns empty metrics until the net runtime's responder task
/// is running.
pub fn start() {
    let _ = std::thread::Builder::new()
        .name("sys-io:stats".to_owned())
        .spawn(stats_thread);
}

/// Register this provider with the stats registry. strobe, which runs the
/// registry, starts after sys-io, so the first attempts can fail.
fn register_stats_provider() -> bool {
    const ATTEMPTS: u64 = 40;
    for tries in 0..ATTEMPTS {
        if moto_sdk::stats::Collector::register(PROVIDER_NAME, STATS_URL).is_ok() {
            log::debug!("sys-io: registered stats provider after {tries} tries");
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // Give up loudly.
    log::warn!("sys-io: stats registry (strobe) unreachable");
    false
}

fn stats_thread() {
    // Listen before registering: a provider that the registry lists must
    // already accept connections.
    let mut server = match LocalServer::new(STATS_URL, ChannelSize::Small, 4, 2) {
        Ok(s) => s,
        Err(err) => {
            log::error!("sys-io: failed to start stats server: {err:?}");
            return;
        }
    };
    if !register_stats_provider() {
        return;
    }

    log::debug!("sys-io stats server started");

    loop {
        match server.wait(SysHandle::NONE, &[]) {
            Ok(wakers) => {
                for waker in wakers {
                    process(&mut server, waker);
                }
            }
            // Dropped connections are already cleaned up by wait(); nothing to do.
            Err(_dropped) => {}
        }
    }
}

fn process(server: &mut LocalServer, waker: SysHandle) {
    let Some(conn) = server.get_connection(waker) else {
        return;
    };
    if !conn.connected() || !conn.have_req() {
        return;
    }

    let (cmd, start_index) = {
        let raw = conn.raw_channel();
        let req = unsafe { raw.get::<moto_sdk::stats::PagedRequest>() };
        (req.header.cmd, req.start_index)
    };

    match cmd {
        moto_sdk::stats::CMD_QUERY_METRICS => {
            let mut entries = crate::runtime::net::stats::query_metrics();
            entries.extend(crate::runtime::fs::stats::query_metrics());
            moto_sdk::stats::respond_pods(conn.data_mut(), &entries, start_index);
        }
        moto_sdk::stats::CMD_DESCRIBE => {
            let mut descs = crate::runtime::net::stats::descriptors();
            descs.extend(crate::runtime::fs::stats::descriptors());
            moto_sdk::stats::respond_pods(conn.data_mut(), &descs, start_index);
        }
        _ => {
            let raw = conn.raw_channel();
            unsafe {
                raw.get_mut::<ResponseHeader>().result = moto_rt::E_INVALID_ARGUMENT;
            }
        }
    }

    let _ = conn.finish_rpc();
}
