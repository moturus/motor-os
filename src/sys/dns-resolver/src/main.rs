mod bridge;

use std::sync::mpsc;
use std::time::Duration;

use moto_dns::{
    validate_request, Address, AddressFamily, Client, ClientError, LookupRequest, LookupResponse,
    LookupResult, Status, MAX_NAME_LEN, PROTOCOL_VERSION, RESPONSE_FLAG_TRUNCATED, SERVICE_URL,
};
use moto_ipc::sync::{ChannelSize, ClientConnection, LocalServer};
use moto_sys::SysHandle;

const WORKER_COUNT: usize = 4;
const CONNECTIONS_PER_WORKER: u64 = 8;
const LISTENERS_PER_WORKER: u64 = 2;

fn initialize_logging() {
    for _ in 0..500 {
        if moto_log::init("dns-resolver").is_ok() {
            log::set_max_level(log::LevelFilter::Info);
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = moto_sys::SysRay::log("dns-resolver: logging is unavailable");
}

fn write_response(
    conn: &mut moto_ipc::sync::LocalServerConnection,
    request_id: u64,
    header_result: moto_rt::ErrorCode,
    result: Option<bridge::Result>,
) {
    let response = conn.resp::<LookupResponse>();
    response.header.result = header_result;
    response.header.ver = PROTOCOL_VERSION;
    response.request_id = request_id;
    response.status = Status::InvalidRequest as u8;
    response.address_count = 0;
    response.flags = 0;
    response.reserved = 0;
    response.addresses.fill(Address::zeroed());

    if let Some(result) = result {
        response.status = result.status as u8;
        if result.status == Status::Ok {
            response.address_count = result.len as u8;
            response.addresses[..result.len].copy_from_slice(&result.addresses[..result.len]);
            if result.truncated {
                response.flags |= RESPONSE_FLAG_TRUNCATED;
            }
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

    let request_id = conn.req::<LookupRequest>().request_id;
    let request = conn.req::<LookupRequest>();
    let validated = validate_request(request).map(|(name, family)| (name.to_vec(), family));
    match validated {
        Ok((name, family)) => {
            let result = bridge::lookup(&name, family);
            write_response(conn, request_id, moto_rt::E_OK, Some(result));
        }
        Err(error) => {
            log::warn!("dns-resolver: rejected malformed request: {error:?}");
            write_response(conn, request_id, moto_rt::E_INVALID_ARGUMENT, None);
        }
    }
    let _ = conn.finish_rpc();
}

fn worker(worker_id: usize, ready: mpsc::Sender<std::result::Result<(), moto_rt::ErrorCode>>) {
    let mut server = match LocalServer::new(
        SERVICE_URL,
        ChannelSize::Small,
        CONNECTIONS_PER_WORKER,
        LISTENERS_PER_WORKER,
    ) {
        Ok(server) => {
            let _ = ready.send(Ok(()));
            server
        }
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };

    loop {
        match server.wait(SysHandle::NONE, &[]) {
            Ok(wakers) => {
                for waker in wakers {
                    process(&mut server, waker);
                }
            }
            Err(dropped) => {
                log::debug!(
                    "dns-resolver worker {worker_id}: dropped {} connection(s)",
                    dropped.len()
                );
            }
        }
    }
}

fn run_service() -> ! {
    initialize_logging();
    let (ready_tx, ready_rx) = mpsc::channel();
    let mut workers = Vec::with_capacity(WORKER_COUNT);
    for worker_id in 0..WORKER_COUNT {
        let ready_tx = ready_tx.clone();
        workers.push(
            std::thread::Builder::new()
                .name(format!("dns-resolver:{worker_id}"))
                .spawn(move || worker(worker_id, ready_tx))
                .expect("dns-resolver: failed to spawn worker"),
        );
    }
    drop(ready_tx);

    for _ in 0..WORKER_COUNT {
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                log::error!("dns-resolver: failed to create service endpoint: {error}");
                std::process::exit(1);
            }
            Err(_) => {
                log::error!("dns-resolver: worker exited during startup");
                std::process::exit(1);
            }
        }
    }
    log::info!("dns-resolver: started {WORKER_COUNT} resolver workers");

    // Every worker serves forever. Joining makes an unexpected first-worker
    // exit fatal instead of silently turning the daemon into an idle process.
    let _ = workers.remove(0).join();
    std::process::exit(1);
}

fn assert_v4(address: &Address, expected: [u8; 4]) {
    assert_eq!(address.family, AddressFamily::V4 as u8);
    assert_eq!(&address.bytes[..4], &expected);
    assert_eq!(address.bytes[4..], [0; 12]);
}

/// A live external lookup can transiently fail right after boot, before the
/// network stack and the upstream resolver are reachable. TemporaryFailure,
/// TimedOut, and Busy all map to E_NOT_READY -- "ask again" -- so poll to a
/// deadline instead of betting the very first query succeeds. Terminal statuses
/// (Ok, NotFound, a malformed answer) return at once for the caller to assert on.
fn resolve_external(name: &[u8], family: AddressFamily) -> bridge::Result {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let result = bridge::lookup(name, family);
        match result.status {
            Status::TemporaryFailure | Status::TimedOut | Status::Busy
                if std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => return result,
        }
    }
}

fn bridge_self_test() {
    let numeric = bridge::lookup(b"192.0.2.1", AddressFamily::Any);
    assert_eq!(numeric.status, Status::Ok);
    assert_eq!(numeric.len, 1);
    assert_v4(&numeric.addresses[0], [192, 0, 2, 1]);

    let hosts = bridge::lookup(b"motor-dns-test", AddressFamily::Any);
    assert_eq!(hosts.status, Status::Ok);
    assert!(hosts.len >= 2);
    assert_eq!(hosts.addresses[0].family, AddressFamily::V4 as u8);
    let first_v6 = hosts
        .addresses
        .iter()
        .take(hosts.len)
        .position(|address| address.family == AddressFamily::V6 as u8)
        .expect("hosts-file lookup did not return IPv6");
    assert!(hosts.addresses[..first_v6]
        .iter()
        .all(|address| address.family == AddressFamily::V4 as u8));
    let hosts_v4 = bridge::lookup(b"motor-dns-test", AddressFamily::V4);
    assert_eq!(hosts_v4.status, Status::Ok);
    assert!(hosts_v4.addresses[..hosts_v4.len]
        .iter()
        .all(|address| address.family == AddressFamily::V4 as u8));
    let hosts_v6 = bridge::lookup(b"motor-dns-test", AddressFamily::V6);
    assert_eq!(hosts_v6.status, Status::Ok);
    assert!(hosts_v6.addresses[..hosts_v6.len]
        .iter()
        .all(|address| address.family == AddressFamily::V6 as u8));

    let dns = resolve_external(b"google.com", AddressFamily::V4);
    assert_eq!(dns.status, Status::Ok);
    assert!(dns.len > 0);
    assert!(dns.addresses[..dns.len]
        .iter()
        .all(|address| address.family == AddressFamily::V4 as u8));

    let embedded_nul = bridge::lookup(b"bad\0name", AddressFamily::V4);
    assert_eq!(embedded_nul.status, Status::InvalidRequest);
    let overlong = vec![b'a'; MAX_NAME_LEN + 1];
    let overlong = bridge::lookup(&overlong, AddressFamily::V4);
    assert_eq!(overlong.status, Status::InvalidRequest);

    for _ in 0..64 {
        let repeated = bridge::lookup(b"motor-dns-test", AddressFamily::Any);
        assert_eq!(repeated.status, Status::Ok);
        assert!(repeated.len >= 2);
    }
}

fn connect_with_retry() -> Client {
    for _ in 0..100 {
        match Client::connect() {
            Ok(client) => return client,
            Err(ClientError::ServiceUnavailable) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => panic!("unexpected resolver connection error: {error:?}"),
        }
    }
    panic!("resolver service did not become available");
}

fn send_malformed_request(
    connection: &mut ClientConnection,
    request_id: u64,
    mutate: impl FnOnce(&mut LookupRequest),
) {
    {
        let request = connection.req::<LookupRequest>();
        request.header.cmd = moto_dns::CMD_LOOKUP;
        request.header.ver = PROTOCOL_VERSION;
        request.header.flags = 0;
        request.request_id = request_id;
        request.name_len = 3;
        request.family = AddressFamily::V4 as u8;
        request.reserved_0 = 0;
        request.reserved_1 = 0;
        request.name.fill(0);
        request.name[..3].copy_from_slice(b"bad");
        request.reserved_tail.fill(0);
        mutate(request);
    }
    let deadline = moto_rt::time::Instant::now()
        .checked_add_duration(&Duration::from_secs(1))
        .unwrap();
    connection.do_rpc(Some(deadline)).unwrap();
    let response = connection.resp::<LookupResponse>();
    assert_eq!(response.header.result, moto_rt::E_INVALID_ARGUMENT);
    assert_eq!(response.header.ver, PROTOCOL_VERSION);
    assert_eq!(response.request_id, request_id);
    assert_eq!(response.status, Status::InvalidRequest as u8);
    assert_eq!(response.address_count, 0);
}

fn malformed_ipc_test() {
    let mut connection = ClientConnection::new(ChannelSize::Small).unwrap();
    connection.connect(SERVICE_URL).unwrap();
    send_malformed_request(&mut connection, 1, |request| request.family = 0xff);
    send_malformed_request(&mut connection, 2, |request| request.name_len = 0);
    send_malformed_request(&mut connection, 3, |request| {
        request.name_len = (MAX_NAME_LEN + 1) as u16;
    });
    send_malformed_request(&mut connection, 4, |request| {
        request.name[..3].copy_from_slice(b"a\0b");
    });
    send_malformed_request(&mut connection, 5, |request| request.header.ver += 1);
    send_malformed_request(&mut connection, 6, |request| request.reserved_1 = 1);
}

/// The IPC counterpart of `resolve_external`: retry a live lookup over the
/// resolver service while it reports a transient condition. A transient
/// resolver status arrives as `Resolver(TemporaryFailure|TimedOut|Busy)`, and a
/// cold upstream that never answers within the per-family timeout as `TimedOut`.
fn client_resolve_external(
    client: &mut Client,
    name: &str,
    family: AddressFamily,
) -> Result<LookupResult, ClientError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match client.lookup(name, family) {
            Err(ClientError::Resolver(
                Status::TemporaryFailure | Status::TimedOut | Status::Busy,
            ))
            | Err(ClientError::TimedOut)
                if std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(100));
            }
            other => return other,
        }
    }
}

fn ipc_self_test() {
    assert!(matches!(
        Client::connect_to("moto-dns-resolver-intentionally-missing"),
        Err(ClientError::ServiceUnavailable)
    ));

    let mut client = connect_with_retry();
    let numeric = client.lookup("192.0.2.1", AddressFamily::Any).unwrap();
    assert_eq!(numeric.addresses.len(), 1);
    assert_v4(&numeric.addresses[0], [192, 0, 2, 1]);

    let hosts = client.lookup("motor-dns-test", AddressFamily::Any).unwrap();
    assert!(hosts.addresses.len() >= 2);
    assert_eq!(hosts.addresses[0].family, AddressFamily::V4 as u8);

    let dns = client_resolve_external(&mut client, "google.com", AddressFamily::V4).unwrap();
    assert!(!dns.addresses.is_empty());

    malformed_ipc_test();
    let after_bad_request = client.lookup("192.0.2.2", AddressFamily::V4).unwrap();
    assert_v4(&after_bad_request.addresses[0], [192, 0, 2, 2]);

    for _ in 0..8 {
        assert!(matches!(
            client.lookup(
                "motor-os-resolver-does-not-exist.invalid",
                AddressFamily::V4
            ),
            Err(ClientError::Resolver(Status::NotFound))
        ));
    }

    for _ in 0..32 {
        let mut short_lived = connect_with_retry();
        let result = short_lived
            .lookup("motor-dns-test", AddressFamily::Any)
            .unwrap();
        assert!(result.addresses.len() >= 2);
    }

    let mut threads = Vec::new();
    for _ in 0..(WORKER_COUNT * 2) {
        threads.push(std::thread::spawn(|| {
            let mut client = connect_with_retry();
            let result = client.lookup("motor-dns-test", AddressFamily::Any).unwrap();
            assert!(result.addresses.len() >= 2);
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }

    println!("dns-resolver self-test PASS");
}

fn main() {
    let mut args = std::env::args();
    let _program = args.next();
    match args.next().as_deref() {
        None => run_service(),
        Some("--self-test") if args.next().is_none() => {
            bridge_self_test();
            ipc_self_test();
        }
        _ => {
            eprintln!("usage: dns-resolver [--self-test]");
            std::process::exit(2);
        }
    }
}
