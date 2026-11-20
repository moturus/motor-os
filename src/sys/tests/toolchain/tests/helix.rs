use crate::{
    editor::Editor,
    rustfmt::input,
    support::{Scratch, command, success},
};
use std::{fs, path::Path};

const MAIN: &str = "#![feature(motor_ext)]\n\nmod greeting;\n\nfn main() {\n    let answer: u32 = greeting::ANSWER;\n    println!(\"Hello from Motor OS! The answer is {answer}.\");\n    println!(\"Runtime version: {}\", std::os::motor::rt_version());\n}\n";
const GREETING: &str = "/// A small constant to explore with hover, completion, and go-to-definition.\npub const ANSWER: u32 = 42;\n";
const CHECK_END: &str = "\"token\":\"rust-analyzer/flycheck/0\",\"value\":{\"kind\":\"end\"";

pub fn run() {
    // Keep editor logs and temporary workspaces on memfs, as the old runner did.
    let s = Scratch::under("/none/tmp", "helix");
    for language in [
        "rust",
        "toml",
        "markdown",
        "markdown.inline",
        "html",
        "c",
        "cpp",
        "json",
        "yaml",
        "bash",
        "lua",
    ] {
        let out = success(
            command(&s.0, "/user/bin/dev/hx")
                .env("NO_COLOR", "1")
                .args(["--health", language]),
            b"",
        );
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(text.contains("Tree-sitter parser: ✓"), "{language}: {text}");
        if language == "rust" {
            assert!(
                text.contains("✓ rust-analyzer: /user/lib/rust/bin/rust-analyzer"),
                "{text}"
            );
        }
    }
    let health = success(
        command(&s.0, "/user/bin/dev/hx")
            .env("NO_COLOR", "1")
            .arg("--health"),
        b"",
    );
    assert!(String::from_utf8_lossy(&health.stdout).contains("/user/lib/helix/runtime"));
    let version = success(command(&s.0, "/user/bin/dev/hx").arg("--version"), b"");
    let version = String::from_utf8(version.stdout).unwrap();
    let revision = version
        .trim()
        .strip_prefix("helix 25.07.1 (")
        .and_then(|v| v.strip_suffix(')'))
        .unwrap();
    assert!(
        revision.len() == 8 && revision.bytes().all(|b| b.is_ascii_hexdigit()),
        "{version}"
    );
    basics(&s);
    rmux(&s);
    unprepared_workspace(&s);
    // Opening, changing and undoing during analysis must not kill Salsa work.
    let demo = project(&s, "open-project");
    let log = s.0.join("open.log");
    let mut e = Editor::new(&demo, &log, &[]);
    e.text("[scratch]");
    open(&mut e, "src/main.rs", "main.rs");
    e.message("\"method\":\"textDocument/didOpen\"");
    e.keys(b"i// analysis edit");
    e.text("INS");
    e.keys(b"\x1b");
    e.text("NOR");
    e.keys(b"u");
    e.log("analysis after edit", true, |s| {
        s.contains(CHECK_END) && s.matches("\"method\":\"textDocument/didChange\"").count() >= 2
    });
    formatting(&mut e, &demo);
    open(&mut e, "src/main.rs", "main.rs");
    e.keys(b"6G32lgd");
    e.text("greeting.rs");
    e.finish_lsp();
    semantic_project(&s);
    let processes = success(&mut command(&s.0, "/user/bin/ps"), b"");
    assert!(
        !String::from_utf8_lossy(&processes.stdout).contains("/user/lib/rust/bin/rust-analyzer"),
        "Helix left a language server running"
    );
    println!("native Helix editing, formatting and language server: PASS");
}

fn rmux(s: &Scratch) {
    let path = s.write("helix-rmux-edit.rs", "");
    let log = s.0.join("rmux.log");
    let mut e = Editor::rmux(&s.0, &log);
    e.text("motor-os");
    e.keys(
        format!(
            "/user/bin/dev/hx -v --log {} {}\n",
            log.display(),
            path.display()
        )
        .as_bytes(),
    );
    e.text("helix-rmux-edit.rs");
    e.keys(b"iHELIX_RMUX_OK");
    e.text("INS");
    e.keys(b"\x1b");
    e.text("NOR");
    e.keys(b":wq\r");
    e.text("motor-os");
    e.finish_shell();
    assert_eq!(fs::read(path).unwrap(), b"HELIX_RMUX_OK\n");
}

fn basics(s: &Scratch) {
    s.write("edit.rs", "");
    let mut e = Editor::new(&s.0, &s.0.join("basic.log"), &["edit.rs"]);
    e.text("edit.rs");
    e.keys(b"iHELIX_SAVE_OK");
    e.text("INS");
    e.keys(b"\x1b");
    e.text("NOR");
    e.keys(b":w\r");
    e.text("written");
    assert_eq!(fs::read(s.0.join("edit.rs")).unwrap(), b"HELIX_SAVE_OK\n");
    e.finish();

    // Ctrl+C comments the selected line. Start on a populated line, as the
    // original terminal check did, rather than the empty line after an edit.
    s.write("ctrl.rs", "HELIX_CTRL_C_PROBE\n");
    let mut e = Editor::new(&s.0, &s.0.join("ctrl.log"), &["ctrl.rs"]);
    e.text("ctrl.rs");
    e.keys(b"\x03");
    e.text("[+]");
    e.finish();

    s.write("resize.rs", "HELIX_RESIZE_PROBE\n");
    let mut e = Editor::new(&s.0, &s.0.join("resize.log"), &["resize.rs"]);
    e.text("resize.rs");
    e.keys(b"\x1b[48;20;60;0;0t");
    e.text("resize.rs");
    e.finish();

    s.write("shell.rs", "HELIX_SHELL_PROBE\n");
    let mut e = Editor::new(&s.0, &s.0.join("shell.log"), &["shell.rs"]);
    e.text("shell.rs");
    e.keys(b":");
    e.text(":");
    // Helix displays stderr instead of stdout when the shell emits diagnostics.
    // Debug Motor startup logs use stderr, so put the probe in that stream too.
    e.keys(b"\x1b[200~sh echo HELIX_SHELL_OK >&2\x1b[201~");
    e.text("HELIX_SHELL_OK");
    e.keys(b"\r");
    e.text("HELIX_SHELL_OK");
    e.keys(b"\x1b");
    e.text("  ~");
    e.finish();
}

fn project(s: &Scratch, prefix: &str) -> std::path::PathBuf {
    for (name, text) in [
        (
            "Cargo.toml",
            "[package]\nname = \"helix-rust-demo\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n",
        ),
        (
            "Cargo.lock",
            "version = 4\n[[package]]\nname = \"helix-rust-demo\"\nversion = \"0.1.0\"\n",
        ),
        ("src/main.rs", MAIN),
        ("src/greeting.rs", GREETING),
    ] {
        s.write(&format!("{prefix}/{name}"), text);
    }
    // Prepare all sources before indexing starts, as the former upload did.
    // Creating them during formatting tests would also trigger project reloads.
    for (path, name) in [
        ("src/format.rs", "in-place.in.rs"),
        ("src/width-case/input.rs", "width.in.rs"),
        ("src/width-case/rustfmt.toml", "width.toml"),
        ("src/error.rs", "stdin.in.rs"),
    ] {
        s.write(&format!("{prefix}/{path}"), input(name));
    }
    s.0.join(prefix)
}

fn open(e: &mut Editor, path: &str, title: &str) {
    e.keys(format!(":o {path}\r").as_bytes());
    e.text(title);
}

fn formatting(e: &mut Editor, root: &Path) {
    for (path, before, after) in [
        ("src/format.rs", "in-place.in.rs", "in-place.expected.rs"),
        (
            "src/width-case/input.rs",
            "width.in.rs",
            "width.expected.rs",
        ),
    ] {
        open(e, path, path.rsplit('/').next().unwrap());
        e.mark();
        e.keys(b":format\r");
        e.message("\"method\":\"textDocument/formatting\"");
        e.log("formatting edits", false, |s| {
            s.contains("rust-analyzer <- ") && s.contains("\"result\":[")
        });
        assert_eq!(fs::read_to_string(root.join(path)).unwrap(), input(before));
        e.save();
        assert_eq!(fs::read_to_string(root.join(path)).unwrap(), input(after));
    }
    open(e, "src/format.rs", "format.rs");
    e.replace("pub fn calculate(value:i32)->i32{if value>0{value*2}else{0}}");
    e.save();
    assert_eq!(
        fs::read_to_string(root.join("src/format.rs")).unwrap(),
        input("in-place.expected.rs")
    );
    open(e, "src/error.rs", "error.rs");
    e.replace("fn main() { let value = ; }");
    e.save();
    e.message("rustfmt exited with status 1");
    assert_eq!(
        fs::read_to_string(root.join("src/error.rs")).unwrap(),
        input("parser-error.rs")
    );
    e.replace("fn main(){let values=vec![3,1,2];println!(\"{:?}\",values);}");
    e.save();
    assert_eq!(
        fs::read_to_string(root.join("src/error.rs")).unwrap(),
        input("stdin.expected.rs")
    );
}

fn unprepared_workspace(s: &Scratch) {
    for (name, text) in [
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"member\", \"shared\"]\nresolver = \"2\"\n",
        ),
        (
            "member/Cargo.toml",
            "[package]\nname = \"workspace-navigation\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dev-dependencies]\nunprepared = \"1\"\n",
        ),
        (
            "member/src/main.rs",
            "mod definitions;\n\nfn local_value() -> u32 {\n    definitions::MODULE_VALUE\n}\n\nfn main() {\n    let _value = local_value();\n}\n",
        ),
        (
            "member/src/definitions.rs",
            "pub const MODULE_VALUE: u32 = 42;\n",
        ),
        (
            "shared/Cargo.toml",
            "[package]\nname = \"workspace-shared\"\nversion = \"0.1.0\"\nedition = \"2021\"\nresolver = \"2\"\n",
        ),
        ("shared/src/lib.rs", "pub fn shared() {}\n"),
        (".git/.keep", ""),
    ] {
        s.write(&format!("workspace/{name}"), text);
    }
    let root = s.0.join("workspace");
    let mut e = Editor::new(&root.join("member"), &s.0.join("workspace.log"), &[]);
    e.text("[scratch]");
    open(&mut e, "src/main.rs", "main.rs");
    e.log("workspace loaded", true, |s| {
        s.contains("rustAnalyzer/Roots Scanned")
    });
    e.mark();
    e.keys(b"8G17lgd");
    e.log("same-file definition", false, |s| {
        s.lines().any(|l| {
            l.contains("rust-analyzer <- ")
                && l.contains("/member/src/main.rs")
                && l.contains("\"line\":2")
        })
    });
    e.mark();
    e.keys(b"4G17lgd");
    e.text("definitions.rs");
    e.message("/member/src/definitions.rs");
    e.finish_lsp();
    assert!(!root.join("Cargo.lock").exists());
    assert!(!root.join("member/.lorry").exists());
}

fn semantic_project(s: &Scratch) {
    let root = project(s, "rust project");
    let mut e = Editor::new(&root, &s.0.join("semantic.log"), &["src/main.rs:6:33"]);
    e.text("main.rs");
    e.log("initial analysis", true, |s| s.contains(CHECK_END));
    formatting(&mut e, &root);
    open(&mut e, "src/main.rs", "main.rs");
    e.keys(b"6G32l k");
    e.text("small constant");
    e.keys(b"\x1b");
    e.text(" ~");
    e.keys(b"gd");
    e.text("greeting.rs");
    e.keys(b"\x0f");
    e.text("main.rs");
    e.mark();
    e.keys(b"6G32lv5lc");
    e.text("INS");
    e.keys(b"\x18");
    e.text("ANSWER");
    e.message("\"method\":\"textDocument/completion\"");
    e.keys(b"\x0e\r");
    e.message("\"method\":\"completionItem/resolve\"");
    e.keys(b"\x1b");
    e.text("NOR");
    e.mark();
    e.keys(b"6G16lv2lcbool");
    e.text("INS");
    e.keys(b"\x1b");
    e.text("NOR");
    e.save();
    e.log("rustc diagnostic", false, |s| {
        s.lines()
            .any(|l| l.contains("\"code\":\"E0308\"") && l.contains("\"source\":\"rustc\""))
    });
    e.message(CHECK_END);
    e.keys(b" d");
    e.text("mismatched types");
    e.keys(b"\x1b");
    e.text("rt_version");
    e.mark();
    e.keys(b"6G16lv3lcu32");
    e.text("INS");
    e.keys(b"\x1b");
    e.text("NOR");
    e.save();
    e.message(CHECK_END);
    e.log("diagnostics cleared", false, |s| {
        s.lines().any(|l| {
            l.contains("publishDiagnostics")
                && l.contains("/src/main.rs")
                && l.contains("\"diagnostics\":[]")
        })
    });
    assert_eq!(fs::read_to_string(root.join("src/main.rs")).unwrap(), MAIN);
    e.keys(b"8G/rt_version\r");
    e.mark();
    e.keys(b"gd");
    e.text("RT_VERSION");
    e.message("file:///user/lib/rust/lib/rustlib/src/rust/library/std/src/os/motor/mod.rs");
    e.finish_lsp();
}
