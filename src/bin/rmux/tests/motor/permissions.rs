use super::support::*;
use moto_sdk::sys::caps::{CAP_INTERACTIVE, CAP_NET, CAP_SPAWN, CAP_SPAWN_DETACHED};

fn refused(s: &Session, args: &[&str], mask: u64) {
    let output = s.output(PROBE, args, mask);
    assert_eq!(output.status.code(), Some(3), "{args:?}: {output:?}");
    assert!(output.stdout.starts_with(b"refused: "), "{output:?}");
}

fn pane(s: &Session, name: &str, mask: u64) -> String {
    let file = s.root.join(format!("{name}-pane"));
    let mut client = s.client(RMUX, &["new", "-s", name], mask);
    client.text("motor-os");
    client.send(format!("{PROBE} whoami > {}\n", file.display()).as_bytes());
    until("pane capabilities", || {
        std::fs::read_to_string(&file).is_ok_and(|s| s.starts_with("caps="))
    });
    client.send(b"\x01d");
    client.finish(0);
    std::fs::read_to_string(file).unwrap()
}

#[test]
fn capability_isolation_pool_pressure_and_connection_pairing() {
    let s = Session::new("caps");
    let own = caps();
    assert_eq!(
        s.success(PROBE, &["errors"], own),
        "opening and poll refusals preserved; closed peer remains EOF"
    );
    let closing = s.output(PROBE, &["closing"], own);
    assert_eq!(closing.status.code(), Some(5));
    assert_eq!(closing.stdout, b"final input acknowledged; exit=5\n");

    let who = s.success(PROBE, &["whoami"], own);
    let profile = who.split_once("profile=").unwrap().1;
    let mask = u64::from_str_radix(profile.trim_start_matches("0x"), 16).unwrap();
    let service = format!("rmux/{mask:x}/{}", s.root.display());
    let report = pane(&s, "priv", own);
    assert_eq!(
        report.split_whitespace().next().unwrap(),
        format!("caps={profile}")
    );
    assert_eq!(
        s.success(PROBE, &["ls", &service, profile], own),
        "sessions: priv: 1 window"
    );

    let minimal = own & (CAP_SPAWN | CAP_INTERACTIVE);
    let mut silent = s.client(PROBE, &["silent", &service], minimal);
    silent.text("silent rejected\n");
    assert_eq!(s.success(RMUX, &["ls"], own), "priv: 1 window");
    silent.send(b"done\n");
    silent.finish(0);

    let mut full = s.client(PROBE, &["saturate", &service, profile], own);
    full.text("pool full\n");
    for arguments in [
        &["ls"][..],
        &["attach", "-t", "priv"],
        &["new", "-s", "overflow"],
    ] {
        let output = s.output(RMUX, arguments, own);
        assert!(!output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("the rmux server is busy"),
            "{output:?}"
        );
    }
    full.send(b"done\n");
    full.finish(0);
    assert_eq!(
        s.success(PROBE, &["parallel", &service, profile], own),
        ["sessions: priv: 1 window"; 3].join("\n")
    );

    let mut half = s.client(PROBE, &["half", &service], own);
    half.text("\n");
    let token = String::from_utf8(half.bytes.clone()).unwrap();
    refused(
        &s,
        &[
            "pair",
            &service,
            token.trim().strip_prefix("token=").unwrap(),
        ],
        own,
    );
    drop(half);

    for reduced in [minimal, mask & !CAP_NET, mask & !CAP_INTERACTIVE] {
        if reduced == mask {
            continue;
        } // None cannot test removing Interactive.
        assert_eq!(s.success(RMUX, &["ls"], reduced), "");
        refused(&s, &["ls", &service, profile], reduced);
        for request in ["new", "attach", "kill"] {
            refused(&s, &[request, &service, profile, "priv"], reduced);
        }
        refused(&s, &["raw", &service], reduced);
    }
    assert_eq!(s.success(RMUX, &["ls"], mask), "priv: 1 window");

    let narrow = (own | CAP_SPAWN_DETACHED) & !CAP_NET;
    let who = s.success(PROBE, &["whoami"], narrow);
    let narrow_profile = who.split_once("profile=").unwrap().1;
    assert_ne!(narrow_profile, profile);
    let report = pane(&s, "narrow", narrow);
    assert_eq!(
        report.split_whitespace().next().unwrap(),
        format!("caps={narrow_profile}")
    );
    assert_eq!(s.success(RMUX, &["ls"], narrow), "narrow: 1 window");
    assert_eq!(s.success(RMUX, &["ls"], own), "priv: 1 window");
    s.kill_session("narrow", narrow);

    let output = s.output(RMUX, &["new"], minimal);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("starting one needs CAP_SPAWN_DETACHED"),
        "{output:?}"
    );
    s.kill_session("priv", own);
}
