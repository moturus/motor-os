#![cfg(unix)]

use std::path::Path;
use std::process::Command;

use russhd::client::args::{ConnectionOptions, Destination};
use russhd::client::config::Config;
use russhd::client::forward_args::LocalForward;

#[test]
fn accumulated_local_forwards_match_openssh_without_network_access() {
    let root = std::env::temp_dir().join(format!("motor-local-config-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("config");
    let text = "Host target.invalid\nLocalForward [::1]:8081 [::2]:81\nGatewayPorts no\nExitOnForwardFailure no\nHost *\nLocalForward 8082 localhost.:82\n";
    std::fs::write(&path, text).unwrap();
    for gateway in [false, true] {
        let mut command = Command::new("ssh");
        command.args(["-G", "-F"]).arg(&path).args([
            "-L",
            "8080:MiXeD.Example.:80",
            "-L",
            "*:8084:[::1]:84",
            "-o",
            "LocalForward=8083 cli:83",
            "-o",
            "ExitOnForwardFailure=yes",
        ]);
        if gateway {
            command.arg("-g");
        }
        let output = command.arg("target.invalid").output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let effective = String::from_utf8(output.stdout).unwrap();
        let mut options = ConnectionOptions::default();
        options.add_local_forward("8080:MiXeD.Example.:80").unwrap();
        options.add_local_forward("*:8084:[::1]:84").unwrap();
        options.apply_o("LocalForward=8083 cli:83").unwrap();
        options.apply_o("ExitOnForwardFailure=yes").unwrap();
        if gateway {
            options.apply_o("GatewayPorts=yes").unwrap();
        }
        let route = Config::parse(text, Path::new("config"))
            .unwrap()
            .resolve(&options, &Destination::parse("target.invalid").unwrap())
            .unwrap();
        let forwards = effective
            .lines()
            .filter_map(|line| line.strip_prefix("localforward "))
            .map(|line| {
                let (listen, target) = line.split_once(' ').unwrap();
                LocalForward::parse_config(listen, target).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(route[0].options.local_forwards, forwards, "{effective}");
        assert!(route[0].options.exit_on_forward_failure);
        assert!(
            effective
                .lines()
                .any(|line| line == "exitonforwardfailure yes")
        );
        assert_eq!(route[0].options.gateway_ports, gateway);
        assert!(
            effective
                .lines()
                .any(|line| line == format!("gatewayports {}", if gateway { "yes" } else { "no" }))
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
