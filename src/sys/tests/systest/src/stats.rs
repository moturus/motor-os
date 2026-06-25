//! End-to-end test of the moto-stats federated metrics protocol.
//!
//! This process plays both roles: it stands up a stats provider exposing a
//! couple of test metrics, registers it with the registry daemon, then acts as
//! a collector — discovering the provider through the registry, describing and
//! reading its metrics — and finally unregisters it and verifies it is no longer
//! discoverable. (The kernel handles same-process shared-memory IPC, so serving
//! and connecting from the same process is fine.)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use moto_ipc::sync::*;
use moto_stats::{Collector, MetricDescWire, MetricEntry, PagedRequest, ProviderInfo};
use moto_sys::SysHandle;

/// The provider's registry name and the URL it serves metrics on.
const PROVIDER_NAME: &str = "systest-stats";
const STATS_URL: &str = "systest-stats-svc";

/// This test provider's (provider-private) metric ids. A collector learns their
/// names dynamically via `CMD_DESCRIBE` — nothing here is hardcoded on the
/// reading side.
mod ids {
    pub const ALPHA: u32 = 0;
    pub const BETA: u32 = 1;
}

const ALPHA_NAME: &str = "test.alpha";
const BETA_NAME: &str = "test.beta";
const ALPHA_VALUE: u64 = 42;
const BETA_VALUE: u64 = 1000;

fn descriptors() -> Vec<MetricDescWire> {
    vec![
        MetricDescWire::new(ids::ALPHA, ALPHA_NAME),
        MetricDescWire::new(ids::BETA, BETA_NAME),
    ]
}

fn entries() -> Vec<MetricEntry> {
    vec![
        MetricEntry::global(ids::ALPHA, ALPHA_VALUE),
        MetricEntry::global(ids::BETA, BETA_VALUE),
    ]
}

/// The provider's sync-RPC server loop (runs on its own thread). Answers
/// `CMD_DESCRIBE` and `CMD_QUERY_METRICS`; blocks forever like every other
/// moto-stats provider, and is torn down when the process exits.
fn run_server(ready: Arc<AtomicBool>) {
    let mut server = LocalServer::new(STATS_URL, ChannelSize::Small, 4, 2)
        .expect("systest stats: failed to start provider endpoint");
    ready.store(true, Ordering::Release);

    loop {
        match server.wait(SysHandle::NONE, &[]) {
            Ok(wakers) => {
                for waker in wakers {
                    process(&mut server, waker);
                }
            }
            // Dropped connections are already cleaned up by wait().
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
        let req = unsafe { raw.get::<PagedRequest>() };
        (req.header.cmd, req.start_index)
    };

    match cmd {
        moto_stats::CMD_QUERY_METRICS => {
            moto_stats::respond_pods(conn.data_mut(), &entries(), start_index);
        }
        moto_stats::CMD_DESCRIBE => {
            moto_stats::respond_pods(conn.data_mut(), &descriptors(), start_index);
        }
        _ => unsafe {
            conn.raw_channel().get_mut::<ResponseHeader>().result = moto_rt::E_INVALID_ARGUMENT;
        },
    }

    let _ = conn.finish_rpc();
}

fn find_provider() -> Option<ProviderInfo> {
    Collector::provider_by_name(PROVIDER_NAME)
}

/// The registry daemon (sys-stats-reg) is normally up by the time systest runs,
/// but register defensively with a few retries (mirrors `sys-io`'s registration).
fn register_with_retry() {
    for _ in 0..100 {
        if Collector::register(PROVIDER_NAME, STATS_URL).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("systest: failed to register stats provider with the registry");
}

pub fn test_stats_provider() {
    // 1. Stand up the provider endpoint and wait for it to be listening.
    let ready = Arc::new(AtomicBool::new(false));
    {
        let ready = ready.clone();
        std::thread::Builder::new()
            .name("systest:stats".to_owned())
            .spawn(move || run_server(ready))
            .unwrap();
    }
    while !ready.load(Ordering::Acquire) {
        std::thread::yield_now();
    }

    // 2. Register with the stats registry.
    register_with_retry();

    // 3. Discover ourselves through the collector and read the metrics back,
    //    resolving metric ids by name (as a real collector would).
    let provider = find_provider().expect("stats provider not discoverable after register");
    assert_eq!(provider.name, PROVIDER_NAME);

    let descs = Collector::describe(&provider).expect("describe failed");
    let alpha = descs
        .iter()
        .find(|m| m.name == ALPHA_NAME)
        .expect("test.alpha descriptor missing");
    let beta = descs
        .iter()
        .find(|m| m.name == BETA_NAME)
        .expect("test.beta descriptor missing");

    assert_eq!(
        Collector::read(&provider, alpha.id, moto_stats::SCOPE_GLOBAL).unwrap(),
        ALPHA_VALUE
    );
    assert_eq!(
        Collector::read(&provider, beta.id, moto_stats::SCOPE_GLOBAL).unwrap(),
        BETA_VALUE
    );

    // 4. Unregister and verify the provider is no longer discoverable.
    Collector::unregister().expect("unregister failed");
    assert!(
        find_provider().is_none(),
        "stats provider still discoverable after unregister"
    );

    println!("test_stats_provider PASS");
}
