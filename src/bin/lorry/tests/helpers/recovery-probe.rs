use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    let args = env::args_os().collect::<Vec<_>>();
    if let Some(root) = env::var_os("LORRY_RECOVERY_PROBE_ROOT") {
        let root = Path::new(&root);
        if root.join("verify").is_file() && args.iter().any(|arg| arg == "--crate-name") {
            // Even the first compiler must see every unit's interrupted state
            // recovered, including units scheduled after this compiler.
            for path in fs::read_to_string(root.join("verify")).unwrap().lines() {
                assert!(
                    !Path::new(path).exists(),
                    "compiler started before recovery of {path}"
                );
            }
        }
        let status = Command::new(env::var_os("LORRY_RECOVERY_REAL_RUSTC").unwrap())
            .args(&args[1..])
            .status()
            .unwrap();
        std::process::exit(status.code().unwrap_or(101));
    }
    assert_eq!(args.len(), 3, "usage: recovery-probe LORRY FIXTURE-ROOT");
    let root = Path::new(&args[2]);
    fs::create_dir_all(root.join("src/bin")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"recovery-probe\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        root.join("Cargo.lock"),
        "version = 4\n[[package]]\nname = \"recovery-probe\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let build = |jobs: &str| {
        let output = Command::new(&args[1])
            .args(["build", "--bins", "-j", jobs])
            .current_dir(root)
            .env("RUSTC", env::current_exe().unwrap())
            .env("LORRY_RECOVERY_PROBE_ROOT", root)
            .env(
                "LORRY_RECOVERY_REAL_RUSTC",
                env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "recovery build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    for name in ["first", "second"] {
        fs::write(root.join(format!("src/bin/{name}.rs")), "fn main() {}\n").unwrap();
    }
    build("1");
    let parent = root.join("target/lorry/debug/build/recovery-probe");
    let units = fs::read_dir(&parent)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(units.len(), 2);
    let mut interrupted = Vec::new();
    for unit in units {
        let name = unit.file_name().unwrap().to_str().unwrap();
        let previous = parent.join(format!(".{name}.lorry-previous-probe"));
        let staging = parent.join(format!(".{name}.lorry-staging-probe"));
        fs::rename(&unit, &previous).unwrap();
        fs::create_dir(&staging).unwrap();
        interrupted.extend([
            previous.display().to_string(),
            staging.display().to_string(),
        ]);
    }
    fs::write(root.join("verify"), interrupted.join("\n")).unwrap();
    for (jobs, message) in [("1", "recovered"), ("2", "parallel")] {
        for name in ["first", "second"] {
            fs::write(
                root.join(format!("src/bin/{name}.rs")),
                format!("fn main() {{ println!(\"{message}\"); }}\n"),
            )
            .unwrap();
        }
        build(jobs);
        for name in ["first", "second"] {
            let output = Command::new(root.join(format!("target/lorry/debug/{name}")))
                .output()
                .unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, format!("{message}\n").as_bytes());
        }
    }
    println!("PASS: all units recover before compilation and still rebuild in parallel");
}
