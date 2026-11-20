// Serial Motor capability tests also act as their own child probe.

#[cfg(not(target_os = "motor"))]
fn main() {}

#[cfg(target_os = "motor")]
fn main() {
    motor::run();
}

#[cfg(target_os = "motor")]
mod motor {

    use moto_sys::caps::{
        CAP_FS_WRITE, CAP_INTERACTIVE, CAP_LOG, CAP_NET, CAP_SPAWN, CAP_SPAWN_DETACHED, CAP_VSOCK,
        MOTOR_OS_CAPS_ENV_KEY,
    };

    const PRINT_CAPS: &str = "print-caps";

    pub fn is_print_caps_child(args: &[String]) -> bool {
        args.len() == 3 && args[1] == PRINT_CAPS
    }

    /// Prints `<label>=0x<caps>` for this process.
    pub fn run_print_caps_child(args: &[String]) -> ! {
        println!(
            "{}=0x{:x}",
            args[2],
            moto_sys::ProcessStaticPage::get().capabilities
        );
        std::process::exit(0)
    }

    fn rush(caps: u64, script: &str) -> std::process::Output {
        std::process::Command::new(env!("CARGO_BIN_EXE_rush"))
            .arg("-c")
            .arg(script)
            .env(MOTOR_OS_CAPS_ENV_KEY, format!("0x{caps:x}"))
            .output()
            .unwrap()
    }

    fn scripts(root: &std::path::Path, own: u64) {
        use std::fs;
        let probe = std::env::current_exe().unwrap();
        let parent = own & (CAP_INTERACTIVE | CAP_SPAWN | CAP_NET | CAP_FS_WRITE);
        let restricted = parent & !(CAP_NET | CAP_FS_WRITE);
        for interpreter in ["rush", "sh"] {
            let shell = root.join(interpreter);
            fs::copy(env!("CARGO_BIN_EXE_rush"), &shell).unwrap();
            executable(&shell);
            let script = root.join(format!("{interpreter}-script"));
            fs::write(&script, format!("#!{}\necho script=$$\necho mask=${{MOTOR_OS_CAPS-unset}}\nunset MOTOR_OS_CAPS\nif echo changed > \"$1\"; then echo write=allowed; else echo write=denied; fi\n\"$2\" print-caps descendant\necho spawn=$?\nexit 7\n", shell.display())).unwrap();
            executable(&script);
            for case in [
                "default",
                "assigned",
                "exported",
                "override",
                "zero",
                "invalid-assigned",
                "invalid-exported",
                "empty",
                "command",
                "exec",
                "function",
                "function-raise",
            ] {
                let mask = format!("0x{restricted:x}");
                let prefix = match case {
                    "default" => String::new(),
                    "assigned" => format!("MOTOR_OS_CAPS={mask}"),
                    "exported" => format!("export MOTOR_OS_CAPS={mask};"),
                    "override" => format!("export MOTOR_OS_CAPS=zz; MOTOR_OS_CAPS={mask}"),
                    "zero" => "MOTOR_OS_CAPS=0".into(),
                    "invalid-assigned" => "MOTOR_OS_CAPS=zz".into(),
                    "invalid-exported" => "export MOTOR_OS_CAPS=zz;".into(),
                    "empty" => "MOTOR_OS_CAPS=".into(),
                    "command" => format!("MOTOR_OS_CAPS={mask} command"),
                    "exec" => format!("(MOTOR_OS_CAPS={mask} exec"),
                    "function" => {
                        format!("f() {{ unset MOTOR_OS_CAPS; \"$@\"; }}; MOTOR_OS_CAPS={mask} f")
                    }
                    "function-raise" => format!(
                        "f() {{ MOTOR_OS_CAPS=0x{parent:x} \"$@\"; }}; MOTOR_OS_CAPS={mask} f"
                    ),
                    _ => unreachable!(),
                };
                let effect = root.join(format!("{interpreter}-{case}"));
                let suffix = if case == "exec" { ")" } else { "" };
                let output = rush(
                    parent,
                    &format!(
                        "echo parent=$$; {prefix} {} {} {}{suffix}",
                        script.display(),
                        effect.display(),
                        probe.display()
                    ),
                );
                let stdout = String::from_utf8(output.stdout).unwrap();
                let (parent_pid, body) = stdout.split_once('\n').unwrap();
                let parent_pid: u64 = parent_pid.strip_prefix("parent=").unwrap().parse().unwrap();
                if case.starts_with("invalid-")
                    || matches!(case, "empty" | "function" | "function-raise")
                {
                    assert_eq!(output.status.code(), Some(126), "{case}: {body}");
                    assert!(body.is_empty(), "{case}: {body}");
                } else {
                    assert_eq!(output.status.code(), Some(7), "{case}: {body}");
                    let (script_pid, body) = body.split_once('\n').unwrap();
                    let script_pid: u64 =
                        script_pid.strip_prefix("script=").unwrap().parse().unwrap();
                    assert_eq!(parent_pid == script_pid, case == "default", "{case}");
                    let expected = match case {
                        "default" => {
                            format!("mask=unset\nwrite=allowed\ndescendant=0x{parent:x}\nspawn=0\n")
                        }
                        "zero" => "mask=unset\nwrite=denied\nspawn=126\n".into(),
                        _ => format!(
                            "mask=unset\nwrite=denied\ndescendant=0x{restricted:x}\nspawn=0\n"
                        ),
                    };
                    assert_eq!(body, expected, "{interpreter}/{case}");
                }
                if case == "default" {
                    assert_eq!(fs::read(effect).unwrap(), b"changed\n");
                } else {
                    assert!(!effect.exists(), "{interpreter}/{case}");
                }
            }
        }
    }

    fn chmod(path: &std::path::Path, mode: &str) {
        assert!(
            std::process::Command::new("/user/bin/chmod")
                .arg(mode)
                .arg(path)
                .status()
                .unwrap()
                .success()
        );
    }

    fn executable(path: &std::path::Path) {
        // Set the caller's access without narrowing a higher role's modes.
        moto_rt::fs::set_perm(
            path.to_str().unwrap(),
            moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC,
        )
        .unwrap();
    }

    fn in_process(root: &std::path::Path, own: u64) {
        let parent = own & (CAP_INTERACTIVE | CAP_SPAWN | CAP_NET | CAP_FS_WRITE);
        let restricted = parent & !(CAP_NET | CAP_FS_WRITE);
        let body = root.join("body");
        let effect = root.join("effect");
        let redirect = root.join("redirect");
        let function_redirect = root.join("function-redirect");
        let probe = std::env::current_exe().unwrap();
        std::fs::write(
            &body,
            "echo entered > \"$target\"\nunset MOTOR_OS_CAPS\n\"$probe\" print-caps escaped\n",
        )
        .unwrap();
        for exported in [false, true] {
            let prefix = if exported {
                String::new()
            } else {
                format!("MOTOR_OS_CAPS=0x{restricted:x}")
            };
            let setup = if exported {
                format!("export MOTOR_OS_CAPS=0x{restricted:x};")
            } else {
                String::new()
            };
            for kind in [
                "function",
                "eval",
                "source",
                "builtin",
                "alias",
                "command",
                "command-source",
                "nested-command",
                "inspect",
                "exec",
                "pipeline",
                "background",
                "substitution",
                "redirection",
                "compound",
                "subshell",
                "shadow-command",
                "exit",
                "return",
                "break",
                "continue",
                "wait",
                "unset",
                "trap",
                "if",
                "for",
                "while",
            ] {
                if !exported && matches!(kind, "compound" | "subshell" | "if" | "for" | "while") {
                    continue;
                }
                let mut expected = 126;
                let mut definitions = "";
                let invocation = match kind {
                    "function" => format!("{prefix} f > {}", redirect.display()),
                    "eval" => format!("{prefix} eval f > {}", redirect.display()),
                    "source" => format!("{prefix} . {} > {}", body.display(), redirect.display()),
                    "builtin" => format!("{prefix} echo entered > {}", redirect.display()),
                    "alias" => format!("{prefix} guarded > {}", redirect.display()),
                    "command" => {
                        format!("{prefix} command -- echo entered > {}", redirect.display())
                    }
                    "command-source" => format!(
                        "{prefix} command -p . {} > {}",
                        body.display(),
                        redirect.display()
                    ),
                    "nested-command" => {
                        format!("{prefix} command command eval f > {}", redirect.display())
                    }
                    "inspect" => format!("{prefix} command -v f > {}", redirect.display()),
                    "exec" => format!("{prefix} exec > {}", redirect.display()),
                    "pipeline" => format!(
                        "{prefix} f > {} | {} -c :",
                        redirect.display(),
                        env!("CARGO_BIN_EXE_rush")
                    ),
                    "background" => {
                        if exported {
                            expected = 0;
                        }
                        format!(
                            "{prefix} f > {} & {}",
                            redirect.display(),
                            if exported { "" } else { "wait %1" }
                        )
                    }
                    "substitution" => format!("result=$({prefix} f > {})", redirect.display()),
                    "redirection" => format!("{prefix} > {}", redirect.display()),
                    "compound" => format!("{{ f; }} > {}", redirect.display()),
                    "subshell" => format!("(f) > {}", redirect.display()),
                    "shadow-command" => {
                        definitions = "command() { f; };";
                        format!("{prefix} command /user/bin/sh > {}", redirect.display())
                    }
                    "unset" => format!("{prefix} unset MOTOR_OS_CAPS"),
                    "trap" => format!("{prefix} trap : EXIT"),
                    "if" => "if true; then f; fi".into(),
                    "for" => "for x in a; do f; done".into(),
                    "while" => "while false; do f; done".into(),
                    _ => format!("{prefix} {kind}"),
                };
                let output = rush(
                    parent,
                    &format!(
                        "probe={}; target={}; f() {{ . {}; }} > {}; alias guarded=f; set -o pipefail; {definitions} {setup} {invocation}",
                        probe.display(),
                        effect.display(),
                        body.display(),
                        function_redirect.display()
                    ),
                );
                assert_eq!(
                    output.status.code(),
                    Some(expected),
                    "{exported}/{kind}: {output:?}"
                );
                assert!(output.stdout.is_empty(), "{exported}/{kind}: {output:?}");
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains("requires a child process"),
                    "{exported}/{kind}: {output:?}"
                );
                for path in [&effect, &redirect, &function_redirect] {
                    assert!(!path.exists(), "{exported}/{kind}: {}", path.display());
                }
            }
        }
    }

    /// Run with `0x3ec` so the shell can pass detach authority to the probe, which
    /// is copied under rush.toml's trusted basename `rmux`.
    pub fn test_detach_grant_precedence() {
        let full = CAP_SPAWN
            | CAP_LOG
            | CAP_SPAWN_DETACHED
            | CAP_INTERACTIVE
            | CAP_VSOCK
            | CAP_NET
            | CAP_FS_WRITE;
        assert_eq!(0x3ec, full);
        assert_eq!(full, moto_sys::ProcessStaticPage::get().capabilities & full);

        let dir = std::path::Path::new("/none/tmp").join(format!(
            "systest-rush-caps-{}",
            moto_sys::ProcessStaticPage::get().pid
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let probe = dir.join("rmux");
        std::fs::copy(std::env::current_exe().unwrap(), &probe).unwrap();
        let probe = probe.to_str().unwrap();
        moto_rt::fs::set_perm(probe, moto_rt::fs::PERM_READ | moto_rt::fs::PERM_EXEC).unwrap();

        let script = format!(
            "P={probe}; $P {PRINT_CAPS} default; \
         MOTOR_OS_CAPS=0x2ec $P {PRINT_CAPS} no-net; \
         MOTOR_OS_CAPS=0x1ec $P {PRINT_CAPS} no-fs-write; \
         MOTOR_OS_CAPS=0xec $P {PRINT_CAPS} neither; \
         MOTOR_OS_CAPS=0 $P {PRINT_CAPS} zero; \
         MOTOR_OS_CAPS=zz $P {PRINT_CAPS} malformed; echo malformed-status=$?; \
         export MOTOR_OS_CAPS=0x2ec; $P {PRINT_CAPS} exported; \
         MOTOR_OS_CAPS=0x1ec $P {PRINT_CAPS} assigned"
        );
        let output = rush(full, &script);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            "default=0x3ec\nno-net=0x2ec\nno-fs-write=0x1ec\nneither=0xec\nzero=0x0\n\
         malformed-status=126\nexported=0x2ec\nassigned=0x1ec\n",
            String::from_utf8(output.stdout).unwrap()
        );
        // Debug runtimes also log to stderr; the malformed mask reached spawn
        // validation rather than being replaced by the grant.
        let stderr = String::from_utf8(output.stderr).unwrap();
        let invalid = format!(
            "rush: {probe}: InvalidArgument (os error {})\n",
            moto_rt::E_INVALID_ARGUMENT
        );
        assert!(stderr.contains(&invalid), "{stderr:?}");

        // Without a mask, the grant is still limited to what the shell holds.
        for shell in [full & !CAP_NET, full & !CAP_FS_WRITE] {
            let output = rush(shell, &format!("{probe} {PRINT_CAPS} default"));
            assert!(output.status.success(), "{output:?}");
            assert_eq!(
                format!("default=0x{shell:x}\n"),
                String::from_utf8(output.stdout).unwrap()
            );
        }

        std::fs::remove_dir_all(dir).unwrap();
        println!("rush_caps::test_detach_grant_precedence PASS");
    }

    fn explicit_masks(root: &std::path::Path, own: u64) {
        let parent = own & (CAP_INTERACTIVE | CAP_SPAWN | CAP_NET | CAP_FS_WRITE);
        let reduced = parent & !(CAP_NET | CAP_FS_WRITE);
        let probe = std::env::current_exe().unwrap();
        let probe = probe.display();
        let check = |script: String, status: i32, stdout: String, diagnostic: &str| {
            let output = rush(parent, &script);
            assert_eq!(output.status.code(), Some(status), "{script}: {output:?}");
            assert_eq!(String::from_utf8_lossy(&output.stdout), stdout, "{script}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(diagnostic),
                "{script}: {output:?}"
            );
        };
        for mask in ["0", "", "zz"] {
            check(
                format!("f() {{ echo entered; }}; MOTOR_OS_CAPS={mask} f"),
                126,
                String::new(),
                "requires a child process",
            );
        }
        check(
            format!("export MOTOR_OS_CAPS=0x{reduced:x}; exit 23; {probe} print-caps after-exit"),
            0,
            format!("after-exit=0x{reduced:x}\n"),
            "rush: exit:",
        );
        let effect = root.join("exit-effect");
        check(
            format!(
                "trap \"echo entered >{}\" EXIT; export MOTOR_OS_CAPS=0x{reduced:x}",
                effect.display()
            ),
            0,
            String::new(),
            "rush: echo:",
        );
        assert!(!effect.exists());
        for (first, second) in [(reduced, parent), (parent, reduced)] {
            check(
                format!(
                    "export MOTOR_OS_CAPS=0x{first:x}; MOTOR_OS_CAPS=0x{second:x} exec {probe} print-caps requested & {probe} print-caps later"
                ),
                0,
                format!("requested=0x{second:x}\nlater=0x{first:x}\n"),
                "",
            );
            check(
                format!(
                    "export MOTOR_OS_CAPS=0x{first:x}; result=$(MOTOR_OS_CAPS=0x{second:x} exec {probe} print-caps requested); {probe} print-caps later"
                ),
                0,
                format!("later=0x{first:x}\n"),
                "",
            );
        }
        let sh = root.join("sh");
        for mask in [reduced, reduced | CAP_FS_WRITE] {
            let allowed = mask & CAP_FS_WRITE != 0;
            let status = if allowed { 0 } else { 2 };
            let error = if allowed { "" } else { "rush:" };
            check(
                format!(
                    "MOTOR_OS_CAPS=0x{mask:x} {} -c 'printf \"a\\nb\\n\" | /user/bin/rg \"^b$\"'",
                    sh.display()
                ),
                status,
                if allowed { "b\n" } else { "" }.into(),
                error,
            );
            check(
                format!(
                    "MOTOR_OS_CAPS=0x{mask:x} {} -c 'x=$(printf hi)'",
                    sh.display()
                ),
                status,
                String::new(),
                error,
            );
            check(
                format!(
                    "MOTOR_OS_CAPS=0x{mask:x} {} -c 'set -e; x=$(printf hi); echo \"$x\"'",
                    sh.display()
                ),
                status,
                if allowed { "hi\n" } else { "" }.into(),
                error,
            );
        }
        let inside = root.join("inside");
        std::fs::write(&inside, format!("#!{}\nf() {{ \"$1\" print-caps inside; }}\nunset MOTOR_OS_CAPS\neval 'f \"$1\"'\nMOTOR_OS_CAPS=0x{parent:x} \"$1\" print-caps forbidden\necho upward=$?\n", sh.display())).unwrap();
        executable(&inside);
        check(
            format!(
                "MOTOR_OS_CAPS=0x{reduced:x} {} {} {probe}",
                sh.display(),
                inside.display()
            ),
            0,
            format!("inside=0x{reduced:x}\nupward=126\n"),
            "permission denied",
        );
        check(
            format!("MOTOR_OS_CAPS=zz {} {probe}", inside.display()),
            126,
            String::new(),
            &format!("rush: {}:", inside.display()),
        );
    }

    pub fn run() {
        let args: Vec<_> = std::env::args().collect();
        if is_print_caps_child(&args) {
            run_print_caps_child(&args);
        }
        let own = moto_sys::ProcessStaticPage::get().capabilities;
        if own & CAP_INTERACTIVE != 0 {
            test_detach_grant_precedence();
        }
        let root = std::path::Path::new("/none/tmp").join(format!(
            "rush-caps-{}",
            moto_sys::ProcessStaticPage::get().pid
        ));
        std::fs::create_dir(&root).unwrap();
        if own & CAP_INTERACTIVE != 0 {
            chmod(&root, "rwxrwxrwx");
        }
        scripts(&root, own);
        in_process(&root, own);
        explicit_masks(&root, own);
        std::fs::remove_dir_all(root).unwrap();
    }
}
