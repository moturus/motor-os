//! Phase 3 golden tests (milestone M1): shell variables and `$?`, the word
//! expansion engine, command substitution, arithmetic, globbing, multi-stage
//! pipelines, and the full redirection set — the jump that makes `rush` an
//! actual shell. Expected values match `dash`/`bash` where they agree.

use std::process::Command;

const RUSH: &str = env!("CARGO_BIN_EXE_rush");

struct Run {
    stdout: String,
    code: i32,
}

fn run_c(script: &str) -> Run {
    let out = Command::new(RUSH)
        .arg("-c")
        .arg(script)
        .output()
        .expect("failed to spawn rush");
    Run {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn tmp(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("rush_phase3_{}_{}", std::process::id(), tag))
}

fn write_executable(path: &std::path::Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

// ---- variables & $? --------------------------------------------------------

#[test]
fn variable_assignment_and_reference() {
    assert_eq!(run_c("x=hello; echo $x world").stdout, "hello world\n");
    assert_eq!(run_c("x=5; echo ${x}0").stdout, "50\n");
}

#[test]
fn status_variable() {
    assert_eq!(run_c("false; echo $?").stdout, "1\n");
    assert_eq!(run_c("true; echo $?").stdout, "0\n");
    assert_eq!(run_c("false; true; echo $?").stdout, "0\n");
}

#[test]
fn inline_assignment_scopes_to_the_command() {
    // A prefix assignment reaches the child's environment...
    assert!(run_c("FOO=bar env").stdout.lines().any(|l| l == "FOO=bar"));
    // ...but does not persist as a shell variable afterward.
    assert_eq!(run_c("FOO=bar true; echo \"[$FOO]\"").stdout, "[]\n");
}

#[test]
fn command_resolved_via_unexported_shell_path() {
    // Regression (Motor OS): command search must use the shell's own PATH
    // variable, even when PATH is not exported to the process environment
    // (POSIX §2.9.1.1; matches dash). Motor's resolver reads only the process
    // env and has no default-PATH fallback, so the shell must resolve PATH.
    let dir = tmp("pathbin");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cmd = dir.join("mycmd");
    write_executable(&cmd, "#!/bin/sh\necho CUSTOM\n");
    // env_clear() removes the inherited PATH, so PATH exists only as an
    // (unexported) shell variable set inside the script — exactly the Motor case.
    let out = Command::new(RUSH)
        .env_clear()
        .arg("-c")
        .arg(format!("PATH={}; mycmd", dir.display()))
        .output()
        .expect("failed to spawn rush");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "CUSTOM\n");
}

#[test]
fn rush_and_sh_scripts_run_in_the_current_process() {
    for (tag, interpreter) in [("rush_script", RUSH), ("sh_script", "/bin/sh")] {
        let script = tmp(tag);
        write_executable(
            &script,
            &format!("#!{interpreter}\nprintf '%s\\n' \"$$\" \"$0\" \"$1\"\nexit 7\n"),
        );
        let run = run_c(&format!(
            "printf '%s\\n' \"$$\"; {} argument; printf '%s\\n' \"$?\" \"$$\"",
            script.display()
        ));
        let _ = std::fs::remove_file(&script);

        let lines: Vec<&str> = run.stdout.lines().collect();
        assert_eq!(lines.len(), 6, "{}", run.stdout);
        assert_eq!(lines[0], lines[1], "script should retain rush's pid");
        assert_eq!(lines[2], script.to_str().unwrap());
        assert_eq!(lines[3], "argument");
        assert_eq!(lines[4], "7");
        assert_eq!(lines[0], lines[5]);
        assert_eq!(run.code, 0);
    }
}

#[test]
fn in_process_script_state_is_isolated_and_redirections_apply() {
    let script = tmp("isolated_script");
    let output = tmp("isolated_output");
    let _ = std::fs::remove_file(&output);
    write_executable(
        &script,
        &format!(
            "#!{RUSH}\nprintf 'child:%s:%s\\n' \"$RUSH_INPROC_PREFIX\" \
             \"${{RUSH_INPROC_SECRET-unset}}\"\n\
             export RUSH_INPROC_LEAK=bad\ncd /\n"
        ),
    );
    let command = format!(
        "RUSH_INPROC_SECRET=outer; RUSH_INPROC_PREFIX=child {} > {}; \
         printf 'parent:%s:%s:%s\\n' \"${{RUSH_INPROC_PREFIX-unset}}\" \
         \"${{RUSH_INPROC_LEAK-unset}}\" \"$RUSH_INPROC_SECRET\"; pwd",
        script.display(),
        output.display()
    );
    let out = Command::new(RUSH)
        .env_remove("RUSH_INPROC_PREFIX")
        .env_remove("RUSH_INPROC_SECRET")
        .env_remove("RUSH_INPROC_LEAK")
        .arg("-c")
        .arg(command)
        .output()
        .expect("failed to spawn rush");

    let _ = std::fs::remove_file(&script);
    assert_eq!(
        std::fs::read_to_string(&output).unwrap(),
        "child:child:unset\n"
    );
    let _ = std::fs::remove_file(&output);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some("parent:unset:unset:outer"));
    assert_eq!(lines.next(), std::env::current_dir().unwrap().to_str());
    assert_eq!(lines.next(), None);
    assert!(out.status.success());
}

#[cfg(unix)]
#[test]
fn in_process_script_restores_signal_dispositions() {
    let script = tmp("signal_script");
    write_executable(&script, &format!("#!{RUSH}\ntrap '' TERM\n"));
    let run = run_c(&format!(
        "trap 'echo restored' TERM; {}; kill -TERM $$; echo after",
        script.display()
    ));
    let _ = std::fs::remove_file(&script);

    assert_eq!(run.stdout, "restored\nafter\n");
    assert_eq!(run.code, 0);
}

#[test]
fn in_process_script_exit_boundaries_return_to_the_host_shell() {
    let cases = [
        (
            "exec_boundary",
            format!("exec {RUSH} -c 'exit 9'\necho unreached\n"),
            9,
        ),
        (
            "errexit_boundary",
            "set -e\nfalse\necho unreached\n".to_string(),
            1,
        ),
        (
            "fatal_boundary",
            "readonly value=1\nvalue=2\necho unreached\n".to_string(),
            2,
        ),
    ];
    for (tag, body, status) in cases {
        let script = tmp(tag);
        write_executable(&script, &format!("#!{RUSH}\n{body}"));
        let run = run_c(&format!("{}; echo status=$?; echo after", script.display()));
        let _ = std::fs::remove_file(&script);

        assert_eq!(run.stdout, format!("status={status}\nafter\n"));
        assert_eq!(run.code, 0);
    }
}

#[test]
fn background_shell_script_keeps_a_real_child_process() {
    let script = tmp("background_script");
    let output = tmp("background_output");
    let _ = std::fs::remove_file(&output);
    write_executable(&script, &format!("#!{RUSH}\necho $$\n"));
    let run = run_c(&format!(
        "{} > {} & child=$!; wait $child; echo $$:$child:$(cat {})",
        script.display(),
        output.display(),
        output.display()
    ));
    let _ = std::fs::remove_file(&script);
    let _ = std::fs::remove_file(&output);

    let pids: Vec<&str> = run.stdout.trim().split(':').collect();
    assert_eq!(pids.len(), 3, "{}", run.stdout);
    assert_ne!(pids[0], pids[1]);
    assert_eq!(pids[1], pids[2]);
    assert_eq!(run.code, 0);
}

#[test]
fn in_process_script_parse_errors_follow_stderr_redirection() {
    let script = tmp("parse_error_script");
    let errors = tmp("parse_error_output");
    let _ = std::fs::remove_file(&errors);
    write_executable(&script, &format!("#!{RUSH}\nif true\n"));
    let run = run_c(&format!(
        "{} 2> {}; echo status=$?",
        script.display(),
        errors.display()
    ));
    let _ = std::fs::remove_file(&script);

    assert_eq!(run.stdout, "status=2\n");
    assert!(
        std::fs::read_to_string(&errors)
            .unwrap()
            .contains("unexpected end")
    );
    let _ = std::fs::remove_file(&errors);
    assert_eq!(run.code, 0);
}

// ---- parameter expansion ---------------------------------------------------

#[test]
fn default_and_alternate_modifiers() {
    assert_eq!(run_c("echo ${u:-default}").stdout, "default\n");
    assert_eq!(run_c("u=set; echo ${u:-default}").stdout, "set\n");
    assert_eq!(run_c("u=set; echo ${u:+yes}").stdout, "yes\n");
    assert_eq!(run_c("echo ${u:+yes}").stdout, "\n");
    // := assigns and expands.
    assert_eq!(
        run_c("echo ${w:=assigned}; echo $w").stdout,
        "assigned\nassigned\n"
    );
}

#[test]
fn length_and_trimming() {
    assert_eq!(run_c("s=hello; echo ${#s}").stdout, "5\n");
    assert_eq!(run_c("p=/usr/local/bin; echo ${p##*/}").stdout, "bin\n");
    assert_eq!(
        run_c("p=/usr/local/bin; echo ${p%/*}").stdout,
        "/usr/local\n"
    );
    assert_eq!(run_c("f=a.tar.gz; echo ${f%%.*}").stdout, "a\n");
}

// ---- quoting & field splitting ---------------------------------------------

#[test]
fn field_splitting_respects_quotes() {
    // Unquoted expansion field-splits; quoted stays one field.
    assert_eq!(run_c("x='a b c'; printf '[%s]' $x").stdout, "[a][b][c]");
    assert_eq!(run_c("x='a b c'; printf '[%s]' \"$x\"").stdout, "[a b c]");
    // Empty quoted string is one empty field.
    assert_eq!(run_c("printf '[%s]' \"\"").stdout, "[]");
}

#[test]
fn custom_ifs_preserves_empty_fields() {
    assert_eq!(
        run_c("IFS=:; p=a:b::c; printf '<%s>' $p").stdout,
        "<a><b><><c>"
    );
}

// ---- command substitution --------------------------------------------------

#[test]
fn command_substitution_dollar_and_backtick() {
    assert_eq!(run_c("echo \"x $(echo mid) y\"").stdout, "x mid y\n");
    assert_eq!(run_c("echo `echo hi`").stdout, "hi\n");
    // Nested.
    assert_eq!(run_c("echo $(echo $(echo deep))").stdout, "deep\n");
    // Trailing newlines are stripped.
    assert_eq!(
        run_c("x=$(printf 'a\\nb\\n'); printf '[%s]' \"$x\"").stdout,
        "[a\nb]"
    );
}

#[test]
fn command_substitution_is_isolated() {
    // A `cd` inside the substitution does not move the parent shell.
    let r = run_c("here=$(cd / && pwd); echo sub=$here; pwd");
    let mut lines = r.stdout.lines();
    assert_eq!(lines.next(), Some("sub=/"));
    assert_ne!(lines.next(), Some("/"), "parent cwd must be unchanged");
}

// ---- arithmetic ------------------------------------------------------------

#[test]
fn arithmetic_expansion() {
    assert_eq!(run_c("echo $(( (2 + 3) * 4 ))").stdout, "20\n");
    assert_eq!(run_c("a=3; b=4; echo $((a*a + b*b))").stdout, "25\n");
    assert_eq!(run_c("echo $((7 / 2)) $((7 % 2))").stdout, "3 1\n");
}

// ---- pipelines -------------------------------------------------------------

#[test]
fn multi_stage_pipeline() {
    assert_eq!(
        run_c("printf 'c\\nb\\na\\n' | sort | head -1").stdout,
        "a\n"
    );
    // Pipeline status is the last stage's.
    assert_eq!(run_c("false | true").code, 0);
    assert_eq!(run_c("true | false").code, 1);
}

// ---- redirections ----------------------------------------------------------

#[test]
fn file_redirections_round_trip() {
    let path = tmp("redir");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        run_c(&format!("echo one > {p}", p = path.display())).code,
        0
    );
    assert_eq!(
        run_c(&format!("echo two >> {p}", p = path.display())).code,
        0
    );
    assert_eq!(
        run_c(&format!("wc -l < {p}", p = path.display()))
            .stdout
            .trim(),
        "2"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\n");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn stderr_redirection_and_dup() {
    let path = tmp("err");
    let _ = std::fs::remove_file(&path);
    // 2> sends only stderr to the file; stdout stays empty.
    let r = run_c(&format!("ls /no_such_rush_dir 2> {p}", p = path.display()));
    assert_eq!(r.stdout, "");
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("no_such_rush_dir")
    );

    // > file 2>&1 merges both streams into the file.
    let both = tmp("both");
    let _ = std::fs::remove_file(&both);
    run_c(&format!(
        "ls /no_such_rush_dir > {p} 2>&1",
        p = both.display()
    ));
    assert!(
        std::fs::read_to_string(&both)
            .unwrap()
            .contains("no_such_rush_dir")
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&both);
}

// ---- here-documents --------------------------------------------------------

#[test]
fn here_document_expands_body() {
    let r = run_c("x=world\ncat <<EOF\nhello $x\nsum=$((1+1))\nEOF\n");
    assert_eq!(r.stdout, "hello world\nsum=2\n");
}

#[test]
fn here_document_quoted_delimiter_is_literal() {
    let r = run_c("cat <<'EOF'\nno $expansion $(here)\nEOF\n");
    assert_eq!(r.stdout, "no $expansion $(here)\n");
}

// ---- globbing --------------------------------------------------------------

#[test]
fn pathname_expansion() {
    let dir = tmp("glob");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for f in ["a.txt", "b.txt", "c.log"] {
        std::fs::write(dir.join(f), "").unwrap();
    }
    let base = dir.display();

    let r = run_c(&format!("echo {base}/*.txt"));
    assert_eq!(r.stdout, format!("{base}/a.txt {base}/b.txt\n"));

    // No match: the pattern is left literal.
    assert_eq!(
        run_c(&format!("echo {base}/*.zzz")).stdout,
        format!("{base}/*.zzz\n")
    );

    // Quoted metacharacters are literal.
    assert_eq!(
        run_c(&format!("echo \"{base}/*.txt\"")).stdout,
        format!("{base}/*.txt\n")
    );

    let _ = std::fs::remove_dir_all(&dir);
}
