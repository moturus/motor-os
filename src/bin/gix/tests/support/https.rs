use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::mpsc::{self, Receiver},
    time::Duration,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[path = "push_pack.rs"]
mod push_pack;
#[path = "repository.rs"]
mod repository;

struct Test(PathBuf);

impl Test {
    fn command(&self, program: &str, directory: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(directory)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.0.join("home"))
            .env("XDG_CONFIG_HOME", self.0.join("xdg"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_TEMPLATE_DIR", self.0.join("template"));
        command
    }

    fn git(&self, directory: &Path, args: &[&str]) -> String {
        success(
            self.command("git", directory)
                .args(["-c", "core.hooksPath=/dev/null"])
                .args(args),
        )
    }

    fn gix(&self, directory: &Path) -> Command {
        let mut command = self.command(env!("CARGO_BIN_EXE_gix"), directory);
        command.args([
            "-c",
            &format!(
                "http.sslCAInfo={}/tests/https-test-ca.pem",
                env!("CARGO_MANIFEST_DIR")
            ),
        ]);
        command
    }
}

impl Drop for Test {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("gix HTTPS evidence: {}", self.0.display());
        } else {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

fn success(command: &mut Command) -> String {
    let output = command.output().unwrap();
    assert!(output.status.success(), "{command:?}: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

fn rejected(output: Output, expected: &str) {
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "{expected}: {output:?}"
    );
}

struct Server {
    child: Child,
    lines: Receiver<String>,
    origin: String,
    stderr: PathBuf,
}

impl Server {
    fn new(test: &Test, name: &str) -> Self {
        let stderr = test.0.join(format!("{name}.stderr"));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg(test.0.join("remote.git"))
            .arg(test.0.join("push.git"))
            .arg(test.0.join(name))
            .arg("127.0.0.1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(fs::File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let ready = lines.recv_timeout(Duration::from_secs(20)).unwrap();
        let port: u16 = ready.strip_prefix("HTTPS_READY=").unwrap().parse().unwrap();
        Self {
            child,
            lines,
            origin: format!("https://localhost:{port}"),
            stderr,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin)
    }

    fn requests(&self, expected: &[&str]) {
        for expected in expected {
            let actual = self.lines.recv_timeout(Duration::from_secs(20)).unwrap();
            assert!(
                actual.starts_with(expected),
                "expected {expected:?}, got {actual:?}"
            );
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let alive = self.child.try_wait().unwrap().is_none();
        if alive {
            self.child.kill().unwrap();
        }
        self.child.wait().unwrap();
        if !std::thread::panicking() {
            assert!(alive, "HTTPS server exited early");
            assert!(fs::read(&self.stderr).unwrap().is_empty());
        }
    }
}

pub fn run() -> Result {
    let test = Test(std::env::temp_dir().join(format!("gix-https-{}", std::process::id())));
    fs::create_dir(&test.0)?;
    for directory in ["home", "xdg", "template"] {
        fs::create_dir(test.0.join(directory))?;
    }
    let source = test.0.join("source");
    repository::create(&source)?;
    test.git(
        &test.0,
        &["clone", "--bare", "--no-hardlinks", "source", "remote.git"],
    );
    test.git(&test.0, &["init", "--bare", "push.git"]);
    clone_and_fetch(&test)?;
    push_pack::check_push_pack(&test.0)?;
    push(&test)?;
    println!("gix loopback HTTPS tests PASS");
    Ok(())
}

fn clone_and_fetch(test: &Test) -> Result {
    let server = Server::new(test, "clone-server");
    let root = test.0.join("clone");
    success(
        test.gix(&test.0)
            .args(["clone", &server.url("/redirect/repo.git"), "clone"]),
    );
    let initial = test.git(&root, &["rev-parse", "HEAD"]);
    assert_eq!(
        test.git(&root, &["rev-parse", "refs/remotes/origin/main"]),
        initial
    );
    test.git(
        &root,
        &[
            "-c",
            "core.symlinks=false",
            "diff-index",
            "--cached",
            "--quiet",
            "--ignore-submodules=all",
            "HEAD",
            "--",
        ],
    );
    assert!(
        test.git(
            &root,
            &[
                "-c",
                "core.symlinks=false",
                "diff-files",
                "-p",
                "--ignore-submodules=all"
            ]
        )
        .is_empty()
    );
    let index = fs::read(root.join(".git/index"))?;
    test.git(
        &test.0,
        &["clone", "--no-hardlinks", "remote.git", "update"],
    );
    let update = test.0.join("update");
    fs::write(update.join("remote-only"), "remote update\n")?;
    test.git(&update, &["add", "remote-only"]);
    test.git(
        &update,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "remote-update",
        ],
    );
    test.git(&update, &["push", "origin", "main"]);
    success(test.gix(&root).arg("fetch"));
    let remote = test.git(&update, &["rev-parse", "HEAD"]);
    assert_ne!(remote, initial);
    assert_eq!(test.git(&root, &["rev-parse", "HEAD"]), initial);
    assert_eq!(
        test.git(&root, &["rev-parse", "refs/remotes/origin/main"]),
        remote
    );
    assert_eq!(fs::read(root.join(".git/index"))?, index);
    assert!(!root.join("remote-only").exists());
    test.git(&root, &["fsck", "--strict"]);
    for args in [
        &["branch"][..],
        &["branch", "-a"],
        &["branch", "-v"],
        &["branch", "-a", "-v"],
        &["remote"],
        &["remote", "-v"],
    ] {
        let actual = success(test.gix(&root).args(["-c", "core.abbrev=12"]).args(args));
        let mut expected = vec!["-c", "core.abbrev=12"];
        expected.extend_from_slice(args);
        assert_eq!(actual, test.git(&root, &expected));
        if args == ["branch", "-v"] {
            assert!(actual.contains("[behind 1]"));
        }
    }
    checkout(test, &root)?;
    fs::create_dir(test.0.join("preexisting"))?;
    fs::write(test.0.join("preexisting/sentinel"), "preserve\n")?;
    assert!(
        !test
            .gix(&test.0)
            .args(["clone", &server.url("/repo.git"), "preexisting"])
            .output()?
            .status
            .success()
    );
    assert_eq!(
        fs::read(test.0.join("preexisting/sentinel"))?,
        b"preserve\n"
    );
    test.git(
        &root,
        &[
            "config",
            "--replace-all",
            "remote.origin.fetch",
            "+refs/heads/main:refs/heads/forbidden",
        ],
    );
    rejected(
        test.gix(&root).arg("fetch").output()?,
        "not a tracking reference or tag",
    );
    assert!(!root.join(".git/refs/heads/forbidden").exists());
    fs::write(test.0.join("attributes"), "editable filter=blocked\n")?;
    rejected(
        test.gix(&test.0)
            .args([
                "-c",
                &format!("core.attributesFile={}/attributes", test.0.display()),
                "-c",
                "filter.blocked.clean=must-not-run",
                "-c",
                "filter.blocked.required=true",
                "clone",
                &server.url("/repo.git"),
                "filtered",
            ])
            .output()?,
        "unsupported filter 'blocked'",
    );
    let filtered = test.0.join("filtered");
    assert!(!filtered.join("editable").exists() && !filtered.join(".git/index").exists());
    assert!(filtered.join(".git/gix-incomplete-clone").is_file());
    assert!(success(test.gix(&filtered).arg("status")).contains("operation incomplete-clone"));
    rejected(
        test.gix(&filtered).arg("fetch").output()?,
        "gix-incomplete-clone",
    );
    for (route, message) in [
        ("reject-status", "Git HTTP returned status 401"),
        (
            "reject-type",
            "Git HTTP expected content type `application/x-git-upload-pack-advertisement`, got `text/plain`",
        ),
        ("reject-origin", "redirect changed the HTTPS origin"),
    ] {
        rejected(
            test.gix(&test.0)
                .args(["clone", &server.url(&format!("/{route}/repo.git")), route])
                .output()?,
            message,
        );
    }
    assert!(
        !test
            .gix(&test.0)
            .args([
                "clone",
                &server.url("/bad-protocol/repo.git"),
                "bad-protocol"
            ])
            .output()?
            .status
            .success()
    );
    success(
        test.gix(&test.0)
            .args(["clone", &server.url("/repo.git"), "good-after-bad"]),
    );
    Ok(())
}

fn checkout(test: &Test, root: &Path) -> Result {
    let run = |args: &[&str], stdout: &str, stderr: &str| {
        let output = test.gix(root).arg("checkout").args(args).output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(stdout),
            "{output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(stderr),
            "{output:?}"
        );
    };
    run(
        &["-b", "cli-tracked", "origin/main"],
        "branch 'cli-tracked' set up to track 'origin/main'.",
        "Switched to a new branch 'cli-tracked'",
    );
    assert!(root.join("remote-only").is_file());
    run(
        &["main"],
        "Your branch is behind 'origin/main' by 1 commit, and can be fast-forwarded.",
        "Switched to branch 'main'",
    );
    run(&["main"], "", "Already on 'main'");
    fs::write(root.join("editable"), "other\nlocal edit\n")?;
    assert!(
        !test
            .gix(root)
            .args(["checkout", "-b", "cli-refused", "origin/main"])
            .output()?
            .status
            .success()
    );
    assert!(!root.join(".git/refs/heads/cli-refused").exists());
    run(
        &["--track", "-b", "cli-local", "main"],
        "branch 'cli-local' set up to track 'main'.",
        "Switched to a new branch 'cli-local'",
    );
    assert_eq!(
        test.git(root, &["symbolic-ref", "HEAD"]),
        "refs/heads/cli-local\n"
    );
    for (branch, revision, remote) in [
        ("cli-tracked", "origin/main", "origin"),
        ("cli-local", "main", "."),
    ] {
        assert_eq!(
            test.git(root, &["rev-parse", branch]),
            test.git(root, &["rev-parse", revision])
        );
        assert_eq!(
            test.git(root, &["config", &format!("branch.{branch}.remote")])
                .trim(),
            remote
        );
        assert_eq!(
            test.git(root, &["config", &format!("branch.{branch}.merge")]),
            "refs/heads/main\n"
        );
    }
    let diff = test.git(
        root,
        &[
            "-c",
            "core.symlinks=false",
            "diff-files",
            "-p",
            "--ignore-submodules=all",
        ],
    );
    assert_eq!(
        diff.lines()
            .filter(|line| line.starts_with("diff --git"))
            .collect::<Vec<_>>(),
        ["diff --git a/editable b/editable"]
    );
    assert!(!root.join("remote-only").exists());
    test.git(root, &["fsck", "--strict", "--no-dangling"]);
    Ok(())
}

fn push(test: &Test) -> Result {
    let server = Server::new(test, "push-server");
    let source = test.0.join("push-pack/source");
    let c0 = fs::read_to_string(test.0.join("push-pack/C0"))?
        .trim()
        .to_owned();
    let merge = fs::read_to_string(test.0.join("push-pack/M"))?
        .trim()
        .to_owned();
    let url = server.url("/push.git");
    let get = "GET /push.git/info/refs?service=git-receive-pack -> 200";
    let post = "POST /push.git/git-receive-pack -> 200";
    for (args, expected, requests) in [
        (
            vec![url.clone(), format!("{c0}:refs/heads/main")],
            format!("remote accepted: refs/heads/main -> {c0}\n"),
            vec![get, post],
        ),
        (
            vec![
                "--dry-run".into(),
                url.clone(),
                "HEAD:refs/heads/main".into(),
            ],
            format!("would update: refs/heads/main -> {merge}\n"),
            vec![get],
        ),
        (
            vec![url.clone(), "HEAD:refs/heads/main".into()],
            format!("remote accepted: refs/heads/main -> {merge}\n"),
            vec![get, post],
        ),
        (
            vec![url.clone(), "HEAD:refs/heads/main".into()],
            format!("up to date: refs/heads/main -> {merge}\n"),
            vec![get],
        ),
    ] {
        assert_eq!(success(test.gix(&source).arg("push").args(args)), expected);
        server.requests(&requests);
    }
    rejected(
        test.gix(&source)
            .args([
                "push",
                &format!("--force-with-lease=refs/heads/main:{c0}"),
                &url,
                "HEAD:refs/heads/main",
            ])
            .output()?,
        "push lease does not match the advertised destination",
    );
    server.requests(&[get]);
    rejected(
        test.gix(&source)
            .args([
                "push",
                &format!("--force-with-lease=refs/heads/main:{merge}"),
                &server.url("/fast-forward-only/push.git"),
                &format!("{c0}:refs/heads/main"),
            ])
            .output()?,
        "remote rejected the update: non-fast-forward",
    );
    server.requests(&[
        "GET /fast-forward-only/push.git/info/refs?service=git-receive-pack -> 200",
        "POST /fast-forward-only/push.git/git-receive-pack -> 200",
    ]);
    assert_eq!(
        success(test.gix(&source).args([
            "-c",
            &format!("remote.fixture.url={}", server.url("/repo.git")),
            "-c",
            &format!("remote.fixture.pushUrl={url}"),
            "push",
            "fixture",
            &format!("{c0}:refs/tags/published")
        ])),
        format!("remote accepted: refs/tags/published -> {c0}\n")
    );
    server.requests(&[get, post]);
    let remote = test.0.join("push.git");
    assert_eq!(
        test.git(&remote, &["rev-parse", "refs/heads/main"]).trim(),
        merge
    );
    assert_eq!(
        test.git(&remote, &["rev-parse", "refs/tags/published"])
            .trim(),
        c0
    );
    test.git(&remote, &["fsck", "--strict", "--no-dangling"]);
    rejected(
        test.gix(&source)
            .args([
                "push",
                &server.url("/auth/push.git"),
                &format!("{c0}:refs/heads/auth"),
            ])
            .output()?,
        &format!("{} wants a user name and password", server.origin),
    );
    server.requests(&["GET /auth/push.git/info/refs?service=git-receive-pack -> 401 anonymous"]);
    Ok(())
}
