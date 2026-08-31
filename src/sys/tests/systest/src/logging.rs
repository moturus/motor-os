use moto_io::fs::{AccessPermissions, FsClient, RolePermissions};
use moto_ipc::sync::{ChannelSize, ClientConnection, RequestHeader, ResponseHeader};
use moto_log::implementation::{
    CMD_LOG, ConnectRequest, ConnectResponse, LogRequest, RawLogRequest,
};
use std::io::Write;
use std::mem::size_of;
use std::time::{Duration, Instant};

const UNAUTHORIZED_CHILD: &str = "sys-log-unauthorized-child";
const FALLBACK_CHILD: &str = "sys-log-fallback-child";
const NONE_LOG_CHILD: &str = "sys-log-none-child";
const NONE_ACCESS_CHILD: &str = "sys-log-none-access-child";

// Full-test supports at most eight concurrent systest suites on one image.
const TEST_TAG_SLOTS: [&str; 8] = [
    "systest-0",
    "systest-1",
    "systest-2",
    "systest-3",
    "systest-4",
    "systest-5",
    "systest-6",
    "systest-7",
];
const LOG_FILE_PERMISSIONS: RolePermissions = RolePermissions::new(
    AccessPermissions::Rw,
    AccessPermissions::R,
    AccessPermissions::None,
);
const LOG_DIR_PERMISSIONS: RolePermissions = RolePermissions::new(
    AccessPermissions::Rwx,
    AccessPermissions::Rx,
    AccessPermissions::None,
);
const LOG_FILE_MAX_BYTES: u64 = 4 * 1024 * 1024;
const MIN_LOG_AVAILABLE_BYTES: u64 = 50 * 1024 * 1024;

pub fn is_child(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| {
        matches!(
            arg.as_str(),
            UNAUTHORIZED_CHILD | FALLBACK_CHILD | NONE_LOG_CHILD | NONE_ACCESS_CHILD
        )
    })
}

fn raw_connection() -> ClientConnection {
    let mut conn = ClientConnection::new(ChannelSize::Small).unwrap();
    conn.connect("sys-log").unwrap();
    conn
}

fn rpc_result(conn: &mut ClientConnection) -> u16 {
    conn.do_rpc(None).unwrap();
    conn.resp::<ResponseHeader>().result
}

fn connect_tag(conn: &mut ClientConnection, tag: &str) -> Result<u64, u16> {
    ConnectRequest::prepare(conn.data_mut(), tag);
    conn.do_rpc(None)?;
    ConnectResponse::parse(conn.data())
}

fn connected_tag(tag: &str) -> (ClientConnection, u64) {
    let mut conn = raw_connection();
    let tag_id = connect_tag(&mut conn, tag)
        .unwrap_or_else(|err| panic!("CONNECT for {tag:?} failed with {err}"));
    (conn, tag_id)
}

fn derived_tag(slot: &str, suffix: &str) -> String {
    let tag = format!("{slot}-{suffix}");
    assert!(tag.len() <= moto_log::MAX_TAG_LEN);
    tag
}

fn log_path(tag: &str) -> String {
    format!("/system/logs/{tag}.log")
}

fn claim_tag_slot() -> (&'static str, ClientConnection) {
    for slot in TEST_TAG_SLOTS {
        let mut conn = raw_connection();
        match connect_tag(&mut conn, slot) {
            Ok(_) => return (slot, conn),
            Err(moto_rt::E_ALREADY_IN_USE) => {}
            Err(err) => panic!("CONNECT for test slot {slot:?} failed with {err}"),
        }
    }
    panic!("all {} logging test slots are active", TEST_TAG_SLOTS.len())
}

fn prepare_log(conn: &mut ClientConnection, tag_id: u64, payload: &[u8]) {
    let req = conn.req::<LogRequest>();
    req.header.cmd = CMD_LOG;
    req.header.ver = 0;
    req.log_level = moto_log::implementation::LOG_LEVEL_INFO;
    req.payload_size = payload.len() as u32;
    req.tag_id = tag_id;
    req.timestamp = moto_rt::time::Instant::now().as_u64();
    conn.data_mut()[size_of::<LogRequest>()..size_of::<LogRequest>() + payload.len()]
        .copy_from_slice(payload);
}

fn expect_error_and_disconnect(mut conn: ClientConnection, expected: u16) {
    assert_eq!(expected, rpc_result(&mut conn));
    assert_eq!(Err(moto_rt::E_BAD_HANDLE), conn.do_rpc(None));
    assert!(!conn.connected());
}

pub fn run_child(args: &[String]) -> ! {
    let tag = args.get(2).expect("logging child tag");
    match args[1].as_str() {
        UNAUTHORIZED_CHILD => {
            let mut conn = raw_connection();
            ConnectRequest::prepare(conn.data_mut(), tag);
            expect_error_and_disconnect(conn, moto_rt::E_NOT_ALLOWED);
        }
        FALLBACK_CHILD => {
            moto_log::init(tag).unwrap();
            moto_log::test_set_tag_id(u64::MAX);
            log::error!("first failed RPC fallback");
            assert!(!moto_log::test_rpc_enabled());
            log::error!("second disabled RPC fallback");
        }
        NONE_LOG_CHILD => {
            moto_log::init(tag).unwrap();
            log::set_max_level(log::LevelFilter::Info);
            log::info!("{}", args.get(3).expect("logging child marker"));
        }
        NONE_ACCESS_CHILD => {
            let err = std::fs::read_to_string(tag).unwrap_err();
            assert_eq!(std::io::ErrorKind::PermissionDenied, err.kind());
        }
        _ => unreachable!(),
    }
    std::process::exit(0)
}

fn child_output(mode: &str, caps: u64, args: &[&str]) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().unwrap())
        .arg(mode)
        .args(args)
        .env(moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY, format!("0x{caps:x}"))
        .output()
        .unwrap()
}

fn protocol_hardening(slot: &str) {
    let interactive = moto_sys::caps::CAP_SPAWN | moto_sys::caps::CAP_INTERACTIVE;
    let unauthorized = derived_tag(slot, "unauthorized");
    let output = child_output(UNAUTHORIZED_CHILD, interactive, &[&unauthorized]);
    assert!(output.status.success(), "{output:?}");

    let mut conn = raw_connection();
    ConnectRequest::prepare(conn.data_mut(), "kernel");
    expect_error_and_disconnect(conn, moto_rt::E_NOT_ALLOWED);

    let (mut conn, tag_id) = connected_tag(&derived_tag(slot, "raw"));
    RawLogRequest::prepare(conn.data_mut(), tag_id, b"raw bytes");
    expect_error_and_disconnect(conn, moto_rt::E_NOT_ALLOWED);

    let health_tag = derived_tag(slot, "health");
    let (mut health, health_id) = connected_tag(&health_tag);

    let mut conn = raw_connection();
    prepare_log(&mut conn, health_id, b"");
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let mut conn = raw_connection();
    ConnectRequest::prepare(conn.data_mut(), &derived_tag(slot, "version"));
    conn.req::<RequestHeader>().ver = 1;
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let mut conn = raw_connection();
    ConnectRequest::prepare(
        conn.data_mut(),
        "x".repeat(moto_log::MAX_TAG_LEN + 1).as_str(),
    );
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let repeat = derived_tag(slot, "repeat");
    let (mut conn, _) = connected_tag(&repeat);
    ConnectRequest::prepare(conn.data_mut(), &repeat);
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let (mut conn, tag_id) = connected_tag(&derived_tag(slot, "bad-tag"));
    prepare_log(&mut conn, tag_id + 1, b"bad tag id");
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let (mut conn, tag_id) = connected_tag(&derived_tag(slot, "payload"));
    prepare_log(&mut conn, tag_id, b"");
    conn.req::<LogRequest>().payload_size = u32::MAX;
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let (mut conn, tag_id) = connected_tag(&derived_tag(slot, "utf8"));
    prepare_log(&mut conn, tag_id, &[0xff]);
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let collision_a = derived_tag(slot, "collision.a");
    let collision_alias = derived_tag(slot, "collision/a");
    let collision_b = derived_tag(slot, "collision-b");
    let (first, _) = connected_tag(&collision_a);
    let mut second = raw_connection();
    assert_eq!(
        Err(moto_rt::E_ALREADY_IN_USE),
        connect_tag(&mut second, &collision_alias)
    );
    assert!(second.connected());
    connect_tag(&mut second, &collision_b).unwrap();
    drop(first);
    let third = connected_tag(&collision_a).0;
    drop((second, third));

    prepare_log(&mut health, health_id, b"protocol tests complete");
    assert_eq!(moto_rt::E_OK, rpc_result(&mut health));
    drop(health);

    let fallback = derived_tag(slot, "fallback");
    let output = child_output(
        FALLBACK_CHILD,
        interactive | moto_sys::caps::CAP_LOG,
        &[&fallback],
    );
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("first failed RPC fallback"), "{stderr:?}");
    assert!(
        stderr.contains("second disabled RPC fallback"),
        "{stderr:?}"
    );
    println!("logging::protocol_hardening test PASS");
}

/// Read the log once it holds at least `want` complete lines.
///
/// `moto_log::init()` and each `log!` are synchronous RPCs to strobe, but its
/// RPC thread only queues the record: a separate io thread creates the file and
/// writes it. So both the file's existence and its contents lag the client by an
/// unbounded amount under load, and a fixed sleep here is a race. Requiring a
/// trailing newline keeps a half-written record from being counted as a line.
fn wait_for_records(path: &str, records: &[String]) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let log = std::fs::read_to_string(path).unwrap_or_default();
        if log.ends_with('\n') && records.iter().all(|record| log.contains(record)) {
            return log;
        }
        assert!(
            Instant::now() < deadline,
            "{path}: missing one of {records:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_permissions(path: &str, expected: RolePermissions) {
    let permissions = moto_async::LocalRuntime::new().block_on(async {
        let client = FsClient::connect().unwrap();
        let (entry_id, _) = client.stat(path).await.unwrap();
        client
            .metadata(entry_id)
            .await
            .unwrap()
            .permissions()
            .unwrap()
    });
    assert_eq!(expected, permissions, "{path}");
}

fn fs_available_bytes() -> u64 {
    let provider = moto_stats::Collector::provider_by_name("sys-io").unwrap();
    let metric = moto_stats::Collector::describe(&provider)
        .unwrap()
        .into_iter()
        .find(|metric| metric.name == "fs.available_bytes")
        .unwrap();
    moto_stats::Collector::read(&provider, metric.id, moto_stats::SCOPE_GLOBAL).unwrap()
}

fn previous_log_bytes() -> u64 {
    std::fs::read_dir("/system/logs")
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".prev"))
        })
        .filter_map(|entry| entry.metadata().ok())
        .map(|metadata| metadata.len())
        .sum()
}

fn rotation_and_space_cleanup(slot: &str) {
    let tag = derived_tag(slot, "rotation");
    let path = log_path(&tag);
    let previous_path = format!("{path}.prev");
    let (mut conn, tag_id) = connected_tag(&tag);
    let payload = vec![b'x'; conn.data().len() - size_of::<LogRequest>()];

    for _ in 0..(LOG_FILE_MAX_BYTES / payload.len() as u64 + 8) {
        prepare_log(&mut conn, tag_id, &payload);
        assert_eq!(moto_rt::E_OK, rpc_result(&mut conn));
    }
    let marker = format!("rotation complete {:016x}", std::random::random::<u64>(..));
    prepare_log(&mut conn, tag_id, marker.as_bytes());
    assert_eq!(moto_rt::E_OK, rpc_result(&mut conn));
    wait_for_records(&path, std::slice::from_ref(&marker));

    let previous_size = std::fs::metadata(&previous_path).unwrap().len();
    assert!(previous_size <= LOG_FILE_MAX_BYTES, "{previous_size}");
    assert!(previous_size > LOG_FILE_MAX_BYTES / 2, "{previous_size}");
    assert!(std::fs::metadata(&path).unwrap().len() <= LOG_FILE_MAX_BYTES);
    drop(conn);

    let other_previous_bytes = previous_log_bytes() - previous_size;
    let target_available = MIN_LOG_AVAILABLE_BYTES
        .saturating_sub(other_previous_bytes)
        .saturating_sub(2 * 1024 * 1024)
        .max(8 * 1024 * 1024);
    let fill_path = crate::temp_path(&format!(
        "strobe-space-{:016x}",
        std::random::random::<u64>(..)
    ));
    let mut fill = std::fs::File::create(&fill_path).unwrap();
    let chunk = vec![0_u8; 1024 * 1024];
    while fs_available_bytes() > target_available {
        fill.write_all(&chunk).unwrap();
        fill.flush().unwrap();
    }

    let trigger = derived_tag(slot, "cleanup-trigger");
    let trigger_path = log_path(&trigger);
    let (mut trigger_conn, trigger_id) = connected_tag(&trigger);
    prepare_log(&mut trigger_conn, trigger_id, b"cleanup complete");
    assert_eq!(moto_rt::E_OK, rpc_result(&mut trigger_conn));
    wait_for_records(&trigger_path, &["cleanup complete".to_string()]);
    assert!(!std::fs::exists(&previous_path).unwrap(), "{previous_path}");

    drop((trigger_conn, fill));
    std::fs::remove_file(fill_path).unwrap();
    println!("logging::rotation_and_space_cleanup test PASS");
}

fn basic(slot: &str) {
    let path = log_path(slot);
    moto_log::init(slot).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    let marker = format!(
        "pid={} nonce={:016x}",
        moto_sys::current_pid(),
        std::random::random::<u64>(..)
    );

    // Anchor the expected `target:line` suffixes to where the calls actually
    // are, so editing this file cannot silently break the assertions below.
    let info_line = line!() + 1;
    log::info!("{marker} foo");
    log::warn!("{marker} bar");
    log::debug!("{marker} another debug string");
    log::trace!("{marker} baz"); // should flush.

    let records = [
        format!(":I - systest::logging:{info_line} - {marker} foo"),
        format!(":W - systest::logging:{} - {marker} bar", info_line + 1),
        format!(
            ":D - systest::logging:{} - {marker} another debug string",
            info_line + 2
        ),
        format!(":T - systest::logging:{} - {marker} baz", info_line + 3),
    ];
    let log = wait_for_records(&path, &records);
    assert!(log.contains(&format!("started log for '{slot}'")));
    assert_permissions("/system/logs", LOG_DIR_PERMISSIONS);
    assert_permissions(&path, LOG_FILE_PERMISSIONS);
    assert_permissions(&format!("{path}.prev"), LOG_FILE_PERMISSIONS);

    let mut append = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    assert_eq!(
        std::io::ErrorKind::PermissionDenied,
        append
            .write_all(b"unauthorized mutation\n")
            .unwrap_err()
            .kind()
    );
    assert_eq!(
        std::io::ErrorKind::PermissionDenied,
        std::fs::remove_file(&path).unwrap_err().kind()
    );

    let none_tag = derived_tag(slot, "none");
    let none_marker = format!("none-role nonce={:016x}", std::random::random::<u64>(..));
    let output = child_output(
        NONE_LOG_CHILD,
        moto_sys::caps::CAP_LOG,
        &[&none_tag, &none_marker],
    );
    assert!(output.status.success(), "{output:?}");
    let none_path = log_path(&none_tag);
    wait_for_records(&none_path, std::slice::from_ref(&none_marker));
    let output = child_output(NONE_ACCESS_CHILD, 0, &[&none_path]);
    assert!(output.status.success(), "{output:?}");

    println!("logging::basic test PASS");
}

pub fn run_all_tests() {
    if !crate::has_cap_log() {
        crate::skip_without_cap_log("logging::protocol_hardening");
        crate::skip_without_cap_log("logging::basic");
        return;
    }
    let (slot, claim) = claim_tag_slot();
    protocol_hardening(slot);
    wait_for_records(&log_path(slot), &[]);
    drop(claim);
    basic(slot);
    rotation_and_space_cleanup(slot);
}
