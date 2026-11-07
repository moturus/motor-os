#![cfg(unix)]

use std::path::Path;
use std::process::Command;

use russhd::client::args::{ConnectionOptions, Destination};
use russhd::client::config::Config;
use russhd::client::forward_args::RemoteForward;

#[test]
fn accumulated_remote_forwards_and_duplicates_match_openssh_without_network_access() {
    let root = std::env::temp_dir().join(format!("motor-remote-config-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("config");
    let text = "Host target.invalid\nRemoteForward [::1]:0 localhost:81\nRemoteForward 9001 [::2]:82\nHost *\nRemoteForward 9002 localhost:83\nRemoteForward [::1]:0 localhost:81\n";
    std::fs::write(&path, text).unwrap();
    let output = Command::new("ssh")
        .args(["-G", "-F"])
        .arg(&path)
        .args([
            "-R",
            "0:localhost:80",
            "-R",
            "0:localhost:80",
            "-o",
            "RemoteForward=*:9003 localhost:84",
            "target.invalid",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let effective = String::from_utf8(output.stdout).unwrap();
    let mut options = ConnectionOptions::default();
    options.add_remote_forward("0:localhost:80").unwrap();
    options.add_remote_forward("0:localhost:80").unwrap();
    options
        .apply_o("RemoteForward=*:9003 localhost:84")
        .unwrap();
    let route = Config::parse(text, Path::new("config"))
        .unwrap()
        .resolve(&options, &Destination::parse("target.invalid").unwrap())
        .unwrap();
    let expected = effective
        .lines()
        .filter_map(|line| line.strip_prefix("remoteforward "))
        .map(|line| {
            let (listen, target) = line.split_once(' ').unwrap();
            RemoteForward::parse_config(listen, target).unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(route[0].options.remote_forwards, expected, "{effective}");
    assert_eq!(
        expected
            .iter()
            .map(|forward| forward.listen.port)
            .collect::<Vec<_>>(),
        [0, 9003, 0, 9001, 9002]
    );
    std::fs::remove_dir_all(root).unwrap();
}
