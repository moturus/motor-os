#![cfg(unix)]

use std::path::Path;
use std::process::Command;

use russhd::client::args::{ConnectionOptions, Destination};
use russhd::client::config::Config;
use russhd::client::forward_args::LocalForward;

#[test]
fn mixed_dynamic_and_fixed_configuration_matches_openssh_without_network_access() {
    let root = std::env::temp_dir().join(format!("motor-socks-config-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("config");
    let text = "Host target.invalid\nDynamicForward [::1]:1081\nLocalForward 8081 [::2]:81\nGatewayPorts no\nHost *\nDynamicForward 1082\n";
    std::fs::write(&path, text).unwrap();
    let output = Command::new("ssh")
        .args(["-G", "-F"])
        .arg(&path)
        .args([
            "-L",
            "8080:localhost:80",
            "-D",
            "1080",
            "-o",
            "DynamicForward=*:1083",
            "-g",
            "target.invalid",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let effective = String::from_utf8(output.stdout).unwrap();
    let mut options = ConnectionOptions::default();
    options.add_local_forward("8080:localhost:80").unwrap();
    options.add_dynamic_forward("1080").unwrap();
    options.apply_o("DynamicForward=*:1083").unwrap();
    options.apply_o("GatewayPorts=yes").unwrap();
    let route = Config::parse(text, Path::new("config"))
        .unwrap()
        .resolve(&options, &Destination::parse("target.invalid").unwrap())
        .unwrap();
    let forwards = &route[0].options.local_forwards;
    let dynamic = effective
        .lines()
        .filter_map(|line| line.strip_prefix("dynamicforward "))
        .map(|line| LocalForward::parse_dynamic(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        forwards
            .iter()
            .filter(|f| f.target.is_none())
            .cloned()
            .collect::<Vec<_>>(),
        dynamic,
        "{effective}"
    );
    let fixed = effective
        .lines()
        .filter_map(|line| line.strip_prefix("localforward "))
        .map(|line| {
            let (listen, target) = line.split_once(' ').unwrap();
            LocalForward::parse_config(listen, target).unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        forwards
            .iter()
            .filter(|f| f.target.is_some())
            .cloned()
            .collect::<Vec<_>>(),
        fixed,
        "{effective}"
    );
    assert_eq!(
        forwards.iter().map(|f| f.listen.port).collect::<Vec<_>>(),
        [8080, 1080, 1083, 1081, 8081, 1082]
    );
    assert!(route[0].options.gateway_ports);
    assert!(effective.lines().any(|line| line == "gatewayports yes"));
    std::fs::remove_dir_all(root).unwrap();
}
