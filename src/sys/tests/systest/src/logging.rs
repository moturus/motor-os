use moto_ipc::sync::{ChannelSize, ClientConnection, RequestHeader, ResponseHeader};
use moto_log::implementation::{CMD_LOG, ConnectRequest, ConnectResponse, LogRequest};
use std::mem::size_of;
use std::time::{Duration, Instant};

const LOG_PATH: &str = "/system/logs/systest.log";
const UNAUTHORIZED_CHILD: &str = "sys-log-unauthorized-child";
const FALLBACK_CHILD: &str = "sys-log-fallback-child";

pub fn is_child(args: &[String]) -> bool {
    args.get(1)
        .is_some_and(|arg| arg == UNAUTHORIZED_CHILD || arg == FALLBACK_CHILD)
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
    match args[1].as_str() {
        UNAUTHORIZED_CHILD => {
            let mut conn = raw_connection();
            ConnectRequest::prepare(conn.data_mut(), "systest-unauthorized");
            expect_error_and_disconnect(conn, moto_rt::E_NOT_ALLOWED);
        }
        FALLBACK_CHILD => {
            moto_log::init("systest-fallback").unwrap();
            moto_log::test_set_tag_id(u64::MAX);
            log::error!("first failed RPC fallback");
            assert!(!moto_log::test_rpc_enabled());
            log::error!("second disabled RPC fallback");
        }
        _ => unreachable!(),
    }
    std::process::exit(0)
}

fn child_output(mode: &str, caps: u64) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().unwrap())
        .arg(mode)
        .env(moto_sys::caps::MOTOR_OS_CAPS_ENV_KEY, format!("0x{caps:x}"))
        .output()
        .unwrap()
}

fn protocol_hardening() {
    let interactive = moto_sys::caps::CAP_SPAWN | moto_sys::caps::CAP_INTERACTIVE;
    let output = child_output(UNAUTHORIZED_CHILD, interactive);
    assert!(output.status.success(), "{output:?}");

    let (mut health, health_id) = connected_tag("systest-proto-health");

    let mut conn = raw_connection();
    prepare_log(&mut conn, health_id, b"");
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let mut conn = raw_connection();
    ConnectRequest::prepare(conn.data_mut(), "systest-proto-version");
    conn.req::<RequestHeader>().ver = 1;
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let mut conn = raw_connection();
    ConnectRequest::prepare(
        conn.data_mut(),
        "x".repeat(moto_log::MAX_TAG_LEN + 1).as_str(),
    );
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let (mut conn, _) = connected_tag("systest-proto-repeat");
    ConnectRequest::prepare(conn.data_mut(), "systest-proto-repeat");
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let (mut conn, tag_id) = connected_tag("systest-proto-bad-tag");
    prepare_log(&mut conn, tag_id + 1, b"bad tag id");
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let (mut conn, tag_id) = connected_tag("systest-proto-payload");
    prepare_log(&mut conn, tag_id, b"");
    conn.req::<LogRequest>().payload_size = u32::MAX;
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let (mut conn, tag_id) = connected_tag("systest-proto-utf8");
    prepare_log(&mut conn, tag_id, &[0xff]);
    expect_error_and_disconnect(conn, moto_rt::E_INVALID_ARGUMENT);

    let (first, _) = connected_tag("systest-proto-collision.a");
    let mut second = raw_connection();
    assert_eq!(
        Err(moto_rt::E_ALREADY_IN_USE),
        connect_tag(&mut second, "systest-proto-collision/a")
    );
    assert!(second.connected());
    connect_tag(&mut second, "systest-proto-collision-b").unwrap();
    drop(first);
    let third = connected_tag("systest-proto-collision.a").0;
    drop((second, third));

    prepare_log(&mut health, health_id, b"protocol tests complete");
    assert_eq!(moto_rt::E_OK, rpc_result(&mut health));
    drop(health);

    let output = child_output(FALLBACK_CHILD, interactive | moto_sys::caps::CAP_LOG);
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
fn wait_for_lines(want: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let log = std::fs::read_to_string(LOG_PATH).unwrap_or_default();
        if log.ends_with('\n') {
            let lines: Vec<String> = log.lines().map(str::to_owned).collect();
            if lines.len() >= want {
                return lines;
            }
        }
        assert!(
            Instant::now() < deadline,
            "{LOG_PATH}: want {want} lines, have {:?}",
            log.lines().count()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn basic() {
    let _ = std::fs::remove_file(LOG_PATH);

    moto_log::init("systest").unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    let lines = wait_for_lines(1);
    assert_eq!(1, lines.len());
    assert!(lines[0].contains(":I - started log for 'systest'"));

    // Anchor the expected `target:line` suffixes to where the calls actually
    // are, so editing this file cannot silently break the assertions below.
    let info_line = line!() + 1;
    log::info!("foo");
    log::warn!("bar");
    log::debug!("another debug string");
    log::trace!("baz"); // should flush.

    let lines = wait_for_lines(5);
    assert_eq!(5, lines.len());
    assert!(lines[0].ends_with(":I - started log for 'systest'"));
    assert!(lines[1].ends_with(&format!(":I - systest::logging:{info_line} - foo")));
    assert!(lines[2].ends_with(&format!(":W - systest::logging:{} - bar", info_line + 1)));
    assert!(lines[3].ends_with(&format!(
        ":D - systest::logging:{} - another debug string",
        info_line + 2
    )));
    assert!(lines[4].ends_with(&format!(":T - systest::logging:{} - baz", info_line + 3)));

    println!("logging::basic test PASS");
}

pub fn run_all_tests() {
    protocol_hardening();
    basic();
}
