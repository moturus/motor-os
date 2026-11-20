use super::registry::Registry;
use crate::support::Project;
use std::fs;
use std::io::Write;
use std::process::{Command, Output, Stdio};

fn command(registry: &Registry, project: &Project, args: &[&str]) -> Command {
    let command = project.command(args);
    #[cfg(unix)]
    {
        let mut command = command;
        command.env("HOME", registry.project.root.join("home"));
        command
    }
    #[cfg(target_os = "motor")]
    {
        let _ = registry;
        command
    }
}

fn run(r: &Registry, p: &Project, args: &[&str], error: Option<&str>) -> Output {
    let output = command(r, p, args).output().unwrap();
    if let Some(error) = error {
        assert!(!output.status.success(), "{args:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(error),
            "{output:?}"
        );
    } else {
        assert!(output.status.success(), "{args:?}: {output:?}");
    }
    output
}

fn answer(r: &Registry, p: &Project, yes: bool) -> Output {
    let mut command = command(r, p, &["vendor", "--locked", "--offline"]);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(target_os = "linux")]
    let (mut input, child) = {
        use std::os::fd::FromRawFd;
        let mut master = -1;
        let mut slave = -1;
        // openpty returns two fresh descriptors, each owned by exactly one File.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let master = unsafe { fs::File::from_raw_fd(master) };
        let slave = unsafe { fs::File::from_raw_fd(slave) };
        command.stdin(slave);
        (master, command.spawn().unwrap())
    };
    #[cfg(target_os = "motor")]
    let (mut input, child) = {
        command
            .stdin(Stdio::piped())
            .env("MOTURUS_STDIO_IS_TERMINAL", "true");
        let mut child = command.spawn().unwrap();
        (child.stdin.take().unwrap(), child)
    };
    input.write_all(if yes { b"y\n" } else { b"n\n" }).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.success(), yes, "{output:?}");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        text.matches("Approve this dependency and capability change?")
            .count(),
        1,
        "{text}"
    );
    output
}

pub fn run_all() {
    let r = Registry::new();
    let p = &r.project;
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers=[\"app\",\"tool\"]\nresolver=\"2\"\n",
    );
    p.package("app", "app", "[dependencies]\ntool={path=\"../tool\"}\n");
    p.write(
        "app/src/main.rs",
        "fn main() { println!(\"{}\", tool::VALUE); }\n",
    );
    p.package("tool", "tool", "");
    p.write(
        "tool/src/lib.rs",
        "pub const VALUE: &str = env!(\"FROM_SCRIPT\");\n",
    );
    p.write(
        "tool/build.rs",
        "fn main() { println!(\"cargo:rustc-env=FROM_SCRIPT=scripted\"); }\n",
    );
    p.lock(&[("app", &["tool"]), ("tool", &[])]);
    let output = run(
        &r,
        p,
        &["build", "--offline"],
        Some("build script without an explicit matching policy grant"),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&format!(
        "[workspaces.{:?}.policy.rules.allow-tool-1_0_0]",
        p.root.to_str().unwrap()
    )));
    assert!(stderr.contains("interactive `lorry vendor` review"));
    run(
        &r,
        p,
        &["vendor", "--locked", "--offline", "--accept-all"],
        None,
    );
    let decisions = r.decision(&p.root).unwrap();
    assert!(
        fs::read_to_string(&decisions)
            .unwrap()
            .contains("accept-all = true")
    );
    assert_eq!(
        run(&r, p, &["run", "--offline", "-q"], None).stdout,
        b"scripted\n"
    );

    let copy = Project::new();
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "app/Cargo.toml",
        "app/src/main.rs",
        "tool/Cargo.toml",
        "tool/src/lib.rs",
        "tool/build.rs",
        ".lorry/dependencies-v2.toml",
    ] {
        copy.write(path, fs::read(p.root.join(path)).unwrap());
    }
    let unapproved = "you have not approved this workspace's dependency review";
    run(&r, &copy, &["build", "--offline"], Some(unapproved));
    let output = answer(&r, &copy, false);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("Build-time code to approve (1):"));
    assert!(text.contains("+ tool (path): build script"));
    assert!(r.decision(&copy.root).is_none());
    answer(&r, &copy, true);
    let record = fs::read_to_string(r.decision(&copy.root).unwrap()).unwrap();
    assert!(!record.contains("accept-all"));
    assert!(record.contains("name = \"tool\""));
    assert!(record.contains("approved-review-sha256 = "));
    assert_eq!(
        run(&r, &copy, &["run", "--offline", "-q"], None).stdout,
        b"scripted\n"
    );
    copy.write(
        "app/build.rs",
        "fn main() { println!(\"cargo:rustc-env=APP_SCRIPT=yes\"); }\n",
    );
    run(
        &r,
        &copy,
        &["build", "--offline"],
        Some("package `app 1.0.0` contains a build script"),
    );
    let output = answer(&r, &copy, true);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("Build-time code to approve (1):"));
    assert!(text.contains("+ app (path): build script"));
    run(&r, &copy, &["build", "--offline", "-q"], None);

    let risky = "[target.x86_64-pc-windows-msvc]\nlinker=\"/unselected/linker\"\n";
    copy.write(".cargo/config.toml", risky);
    run(
        &r,
        &copy,
        &["build", "--offline"],
        Some("you have not approved the repository's Cargo configuration"),
    );
    let output = answer(&r, &copy, false);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(text.contains("Repository Cargo configuration to approve (1):"));
    assert!(
        !fs::read_to_string(r.decision(&copy.root).unwrap())
            .unwrap()
            .contains("cargo-config")
    );
    answer(&r, &copy, true);
    assert!(
        fs::read_to_string(r.decision(&copy.root).unwrap())
            .unwrap()
            .contains("[[cargo-config]]")
    );
    run(&r, &copy, &["build", "--offline", "-q"], None);
    copy.write(
        ".cargo/config.toml",
        risky.replace("/unselected/linker", "/changed/linker"),
    );
    run(
        &r,
        &copy,
        &["build", "--offline"],
        Some("you have not approved the repository's Cargo configuration"),
    );
    copy.write(
        ".cargo/config.toml",
        "[build]\nrustflags=[\"--cfg\",\"harmless\"]\n",
    );
    run(&r, &copy, &["build", "--offline", "-q"], None);
    p.write(".cargo/config.toml", risky);
    run(&r, p, &["build", "--offline", "-q"], None);
    fs::remove_file(decisions).unwrap();
    run(
        &r,
        p,
        &["build", "--offline"],
        Some("you have not approved the repository's Cargo configuration"),
    );
    fs::remove_file(p.root.join(".cargo/config.toml")).unwrap();
    run(&r, p, &["build", "--offline"], Some(unapproved));
    println!("PASS: workspace trust, one prompt per review and Cargo configuration approval");
}
