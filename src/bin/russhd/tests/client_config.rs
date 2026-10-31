use std::path::Path;

use russhd::client::args::{ConnectionOptions, Destination};
use russhd::client::config::{Config, ResolvedHost};

fn config(text: &str) -> Config {
    Config::parse(text, Path::new("fixture/config")).unwrap()
}

fn resolve(text: &str, target: &str, options: &ConnectionOptions) -> Vec<ResolvedHost> {
    config(text)
        .resolve(
            options,
            &Destination::parse_with_default(target, "local").unwrap(),
        )
        .unwrap()
}

#[test]
fn exact_requested_file_resolves_aliases_and_jump_users() {
    let text = "Host moto-hi\n    HostName 66.165.239.34\n    User posk\n\nHost posk-dt\n    HostName 10.0.0.4\n    User posk\n    ProxyJump moto-hi\n";
    let route = resolve(text, "posk-dt", &ConnectionOptions::default());
    assert_eq!(route.len(), 2);
    assert_eq!(route[0].destination.host, "66.165.239.34");
    assert_eq!(route[1].destination.host, "10.0.0.4");
    for hop in &route {
        assert_eq!(hop.destination.user, "posk");
        assert_eq!(hop.options.port, 22);
    }
    assert_eq!(
        resolve(text, "moto-hi", &ConnectionOptions::default()).len(),
        1
    );
    let route = resolve(text, "other@posk-dt", &ConnectionOptions::default());
    assert_eq!(route[0].destination.user, "posk");
    assert_eq!(route[1].destination.user, "other");
}

#[test]
fn patterns_precedence_and_identity_lists_follow_file_order() {
    let text = r#"
  # comments and quoted paths
Host db? *.example !blocked.example
  hOsTnAmE = "192.0.2.1" # comment
  User=config-user
  Port 2222
  IdentityFile "/keys/a b#c=key"
  IdentityFile /keys/second
Host *
  User fallback
  Port 3333
  IdentityFile /keys/second
  IdentityFile /keys/third
"#;
    let mut options = ConnectionOptions::default();
    options.apply_o("Port = 4444").unwrap();
    options.add_identity("/keys/cli").unwrap();
    let route = resolve(text, "db1", &options);
    let host = &route[0];
    assert_eq!(host.destination.user, "config-user");
    assert_eq!(host.destination.host, "192.0.2.1");
    assert_eq!(host.options.port, 4444);
    assert_eq!(
        host.options.identities,
        [
            "/keys/cli",
            "/keys/a b#c=key",
            "/keys/second",
            "/keys/third"
        ]
        .map(std::path::PathBuf::from)
    );
    let route = resolve(text, "blocked.example", &ConnectionOptions::default());
    assert_eq!(route[0].destination.user, "fallback");
    assert_eq!(route[0].destination.host, "blocked.example");
    assert_eq!(route[0].options.port, 3333);
    // HostName changes the connection address, not subsequent Host matching.
    let route = resolve(
        "Host alias\nHostName actual\nHost actual\nUser wrong\n",
        "alias",
        &ConnectionOptions::default(),
    );
    assert_eq!(route[0].destination.user, "local");
}

#[test]
fn jump_chains_resolve_each_hop_and_reject_cycles_before_connecting() {
    let text = "Host first\nHostName 192.0.2.1\nUser one\nPort 1001\nHost second\nHostName 192.0.2.2\nUser two\nPort 1002\nProxyJump unwanted\nHost target\nHostName 192.0.2.3\nUser three\nProxyJump explicit@first:2001,second\n";
    let route = resolve(text, "target", &ConnectionOptions::default());
    assert_eq!(
        route
            .iter()
            .map(|hop| hop.alias.as_str())
            .collect::<Vec<_>>(),
        ["first", "second", "target"]
    );
    assert_eq!(route[0].destination.user, "explicit");
    assert_eq!(route[0].options.port, 2001);
    assert_eq!(route[1].destination.user, "two");
    assert_eq!(route[1].options.port, 1002);
    let text = "Host target\nProxyJump middle\nHost middle\nProxyJump first\n";
    assert_eq!(
        resolve(text, "target", &ConnectionOptions::default()).len(),
        3
    );
    let mut options = ConnectionOptions::default();
    options.apply_o("ProxyJump=none").unwrap();
    assert_eq!(resolve(text, "target", &options).len(), 1);
    for text in [
        "Host *\nProxyJump self\n",
        "Host a\nProxyJump b\nHost b\nProxyJump a\n",
        "Host a\nHostName same\nProxyJump b\nHost b\nHostName same\n",
    ] {
        let error = config(text)
            .resolve(
                &ConnectionOptions::default(),
                &Destination::parse("a").unwrap(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("cycle"), "{error}");
    }
    let text = (0..17)
        .map(|i| format!("Host host{i}\nProxyJump host{}\n", i + 1))
        .collect::<String>();
    assert!(
        config(&text)
            .resolve(
                &ConnectionOptions::default(),
                &Destination::parse("host0").unwrap()
            )
            .unwrap_err()
            .to_string()
            .contains("exceeds")
    );
}

#[test]
fn jump_ipv6_and_per_hop_settings_do_not_inherit_target_overrides() {
    let text = "Host target\nProxyJump jumpuser@[::1]:2222\nHost ::1\nUser fileuser\nPort 3333\nIdentityFile /jump/key\n";
    let mut options = ConnectionOptions::default();
    options.set_port("4444").unwrap();
    options.apply_o("User=targetuser").unwrap();
    options.add_identity("/target/key").unwrap();
    let route = resolve(text, "target", &options);
    assert_eq!(route[0].destination.host, "::1");
    assert_eq!(route[0].destination.user, "jumpuser");
    assert_eq!(route[0].options.port, 2222);
    assert_eq!(
        route[0].options.identities,
        [std::path::PathBuf::from("/jump/key")]
    );
    assert_eq!(route[1].destination.user, "targetuser");
    assert_eq!(route[1].options.port, 4444);
}

#[test]
fn malformed_and_unsupported_settings_name_the_file_and_line() {
    for bad in [
        "Match all",
        "Include other",
        "ProxyCommand sh",
        "User",
        "User \"unterminated",
        "Port 0",
        "Host",
        "Host !",
        "ProxyJump a,",
        "ProxyJump ssh://host",
        "ProxyJump [::1]junk",
        "IdentityFile ~/.ssh/key",
        "HostName %h",
        "HostName [bad",
        "HostName []",
        "UserKnownHostsFile ${HOME}/hosts",
        "User a b",
        "User \"\"",
    ] {
        let error = Config::parse(&format!("# comment\n{bad}\n"), Path::new("bad-config"))
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("bad-config:2:"), "{bad}: {error}");
    }
    for path in ["none", "/dev/null"] {
        assert_eq!(
            Config::load(Some(Path::new(path)))
                .unwrap()
                .resolve(
                    &ConnectionOptions::default(),
                    &Destination::parse("host").unwrap()
                )
                .unwrap()
                .len(),
            1
        );
    }
    let path = Path::new("/nonexistent-motor-ssh-config/absent");
    assert!(
        Config::load(Some(path))
            .unwrap_err()
            .to_string()
            .contains(path.to_str().unwrap())
    );
}

#[cfg(unix)]
#[test]
fn supported_resolution_matches_openssh_without_network_access() {
    use std::process::Command;
    let root = std::env::temp_dir().join(format!("motor-ssh-config-oracle-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("config");
    let cli_identity = root.join("cli-identity");
    std::fs::write(&cli_identity, "identity fixture").unwrap();
    let text = "Host db? *.example !blocked.example UPPER\nHostName 192.0.2.10\nUser configured\nPort 2222\nIdentityFile /keys/one\nIdentityFile /keys/two\nHost *\nUser fallback\nPort 3333\nIdentityFile /keys/two\n";
    std::fs::write(&path, text).unwrap();
    for name in [
        "db1",
        "a.example",
        "blocked.example",
        "other",
        "UPPER",
        "upper",
        "explicit@db1",
    ] {
        let output = Command::new("ssh")
            .args(["-G", "-F"])
            .arg(&path)
            .args(["-p", "4444", "-i"])
            .arg(&cli_identity)
            .arg(name)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let mut options = ConnectionOptions::default();
        options.set_port("4444").unwrap();
        options
            .add_identity(cli_identity.to_str().unwrap())
            .unwrap();
        let route = config(text)
            .resolve(&options, &Destination::parse(name).unwrap())
            .unwrap();
        let host = &route[0];
        let effective = String::from_utf8(output.stdout).unwrap();
        for expected in [
            format!("hostname {}", host.destination.host),
            format!("user {}", host.destination.user),
            format!("port {}", host.options.port),
        ] {
            assert!(
                effective.lines().any(|line| line == expected),
                "{name}: missing {expected}\n{effective}"
            );
        }
        let identities = effective
            .lines()
            .filter_map(|line| line.strip_prefix("identityfile "))
            .map(std::path::PathBuf::from)
            .collect::<Vec<_>>();
        assert_eq!(host.options.identities, identities, "{name}");
    }
    std::fs::remove_dir_all(root).unwrap();
}
