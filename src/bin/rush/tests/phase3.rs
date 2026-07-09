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
    std::fs::write(&cmd, "#!/bin/sh\necho CUSTOM\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cmd, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
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

// ---- parameter expansion ---------------------------------------------------

#[test]
fn default_and_alternate_modifiers() {
    assert_eq!(run_c("echo ${u:-default}").stdout, "default\n");
    assert_eq!(run_c("u=set; echo ${u:-default}").stdout, "set\n");
    assert_eq!(run_c("u=set; echo ${u:+yes}").stdout, "yes\n");
    assert_eq!(run_c("echo ${u:+yes}").stdout, "\n");
    // := assigns and expands.
    assert_eq!(run_c("echo ${w:=assigned}; echo $w").stdout, "assigned\nassigned\n");
}

#[test]
fn length_and_trimming() {
    assert_eq!(run_c("s=hello; echo ${#s}").stdout, "5\n");
    assert_eq!(run_c("p=/usr/local/bin; echo ${p##*/}").stdout, "bin\n");
    assert_eq!(run_c("p=/usr/local/bin; echo ${p%/*}").stdout, "/usr/local\n");
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
    assert_eq!(run_c("IFS=:; p=a:b::c; printf '<%s>' $p").stdout, "<a><b><><c>");
}

// ---- command substitution --------------------------------------------------

#[test]
fn command_substitution_dollar_and_backtick() {
    assert_eq!(run_c("echo \"x $(echo mid) y\"").stdout, "x mid y\n");
    assert_eq!(run_c("echo `echo hi`").stdout, "hi\n");
    // Nested.
    assert_eq!(run_c("echo $(echo $(echo deep))").stdout, "deep\n");
    // Trailing newlines are stripped.
    assert_eq!(run_c("x=$(printf 'a\\nb\\n'); printf '[%s]' \"$x\"").stdout, "[a\nb]");
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
    assert_eq!(run_c("printf 'c\\nb\\na\\n' | sort | head -1").stdout, "a\n");
    // Pipeline status is the last stage's.
    assert_eq!(run_c("false | true").code, 0);
    assert_eq!(run_c("true | false").code, 1);
}

// ---- redirections ----------------------------------------------------------

#[test]
fn file_redirections_round_trip() {
    let path = tmp("redir");
    let _ = std::fs::remove_file(&path);
    assert_eq!(run_c(&format!("echo one > {p}", p = path.display())).code, 0);
    assert_eq!(run_c(&format!("echo two >> {p}", p = path.display())).code, 0);
    assert_eq!(run_c(&format!("wc -l < {p}", p = path.display())).stdout.trim(), "2");
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
    assert!(std::fs::read_to_string(&path).unwrap().contains("no_such_rush_dir"));

    // > file 2>&1 merges both streams into the file.
    let both = tmp("both");
    let _ = std::fs::remove_file(&both);
    run_c(&format!(
        "ls /no_such_rush_dir > {p} 2>&1",
        p = both.display()
    ));
    assert!(std::fs::read_to_string(&both).unwrap().contains("no_such_rush_dir"));

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
    assert_eq!(run_c(&format!("echo {base}/*.zzz")).stdout, format!("{base}/*.zzz\n"));

    // Quoted metacharacters are literal.
    assert_eq!(run_c(&format!("echo \"{base}/*.txt\"")).stdout, format!("{base}/*.txt\n"));

    let _ = std::fs::remove_dir_all(&dir);
}
