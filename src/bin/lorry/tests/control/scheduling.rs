use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::support::Project;

fn event(root: &Path, kind: &str, name: &str) {
    let mut log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("events"))
        .unwrap();
    log.write_all(format!("{kind} {name}\n").as_bytes())
        .unwrap();
}

fn events(root: &Path) -> String {
    fs::read_to_string(root.join("events")).unwrap_or_default()
}

pub fn compiler() {
    let root = std::env::var_os("LORRY_SCHEDULING_ROOT").unwrap();
    let root = Path::new(&root);
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let name = args
        .windows(2)
        .find(|args| args[0] == "--crate-name")
        .map(|args| args[1].to_str().unwrap())
        .unwrap_or("query");
    event(root, "start", name);
    let status = Command::new(std::env::var_os("LORRY_SCHEDULING_RUSTC").unwrap())
        .args(args.iter())
        .status()
        .unwrap();
    if name == "base" {
        let deadline = Instant::now() + Duration::from_secs(60);
        while root.join("linger").exists() {
            if fs::read_to_string(root.join("linger")).unwrap() == "middle"
                && events(root).lines().any(|line| line == "start middle")
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "dependent never started while base had metadata"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        if root.join("edit").is_file() {
            fs::copy(root.join("edit"), root.join("base/src/lib.rs")).unwrap();
            fs::remove_file(root.join("edit")).unwrap();
        }
    }
    event(root, "end", name);
    std::process::exit(status.code().unwrap_or(101));
}

fn command(p: &Project) -> Command {
    let mut command = p.command(&["build", "--locked", "--offline", "-j2"]);
    command
        .env("RUSTC", std::env::current_exe().unwrap())
        .env("LORRY_SCHEDULING_ROOT", &p.root)
        .env("LORRY_SCHEDULING_RUSTC", p.rustc());
    command
}

fn build(p: &Project) {
    let output = command(p).output().unwrap();
    assert!(output.status.success(), "{output:?}");
}

fn value(p: &Project, value: u32) {
    let output = Command::new(p.root.join("target/lorry/debug/app"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, format!("{value}\n").as_bytes());
}

pub fn run() {
    let p = Project::new();
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers=[\"app\",\"base\",\"middle\"]\nresolver=\"2\"\n",
    );
    p.package("base", "base", "");
    p.write("base/src/lib.rs", "pub fn value() -> u32 { 1 }\n");
    p.package(
        "middle",
        "middle",
        "[dependencies]\nbase={path=\"../base\"}\n",
    );
    p.write(
        "middle/src/lib.rs",
        "pub fn value() -> u32 { base::value() + 1 }\n",
    );
    p.package(
        "app",
        "app",
        "[dependencies]\nmiddle={path=\"../middle\"}\n",
    );
    p.write(
        "app/src/main.rs",
        "fn main() { println!(\"{}\", middle::value()); }\n",
    );
    p.lock(&[("app", &["middle"]), ("middle", &["base"]), ("base", &[])]);
    p.admit();
    // Motor deliberately waits for a dependency's complete library.
    let pipelining = !cfg!(target_os = "motor");
    if pipelining {
        p.write("linger", "middle");
    }
    build(&p);
    value(&p, 2);
    let log = events(&p.root);
    let position = |event| log.lines().position(|line| line == event).unwrap();
    assert_eq!(
        position("start middle") < position("end base"),
        pipelining,
        "{log}"
    );
    assert!(position("start app") > position("end base"), "{log}");
    assert!(position("start app") > position("end middle"), "{log}");
    if pipelining {
        fs::remove_file(p.root.join("linger")).unwrap();
    }
    p.write("events", "");
    build(&p);
    for name in ["base", "middle", "app"] {
        assert!(!events(&p.root).contains(&format!("start {name}\n")));
    }

    // Only pipelined libraries publish metadata from an unfinished unit.
    // Motor's worker cancellation and staging recovery are tested in cancel.rs.
    if pipelining {
        p.write(
            "base/src/lib.rs",
            "pub fn value() -> u32 { 1 } // interrupted\n",
        );
        p.write("linger", "killed");
        p.write("events", "");
        let mut child = command(&p)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while !events(&p.root).contains("start middle\n") {
            assert!(
                child.try_wait().unwrap().is_none(),
                "build ended before middle started"
            );
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                fs::remove_file(p.root.join("linger")).unwrap();
                panic!("interrupted build did not publish metadata");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        fs::remove_file(p.root.join("linger")).unwrap();
        p.write("events", "");
        build(&p);
        let log = events(&p.root);
        assert!(log.contains("start base\n"), "{log}");
        value(&p, 2);
        println!("PASS: interrupted metadata builds rebuild");
    }

    p.write(
        "base/src/lib.rs",
        "pub fn value() -> u32 { 1 } // edit race\n",
    );
    p.write("edit", "pub fn value() -> u32 { 2 }\n");
    build(&p);
    assert!(!p.root.join("edit").exists());
    p.write("events", "");
    build(&p);
    for name in ["base", "middle", "app"] {
        assert!(events(&p.root).contains(&format!("start {name}\n")));
    }
    value(&p, 3);
    println!("PASS: dependency scheduling, freshness and edits during compilation");
}
