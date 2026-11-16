use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use gix::bstr::ByteSlice;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
#[path = "support/repository.rs"]
mod repository;

struct Client(PathBuf);

impl Client {
    fn new() -> Self {
        let base = if cfg!(target_os = "motor") {
            PathBuf::from("/none/tmp")
        } else {
            std::env::temp_dir()
        };
        let root = base.join(format!(
            "gix-cli-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for directory in ["home", "xdg/git", "bin"] {
            fs::create_dir_all(root.join(directory)).unwrap();
        }
        Self(root)
    }

    fn command(&self, directory: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gix"));
        command
            .current_dir(directory)
            .env_clear()
            .env("HOME", self.0.join("home"))
            .env("XDG_CONFIG_HOME", self.0.join("xdg"))
            .env("PATH", self.0.join("bin"))
            .env("GIX_FAKE_GIT_SENTINEL", self.0.join("git-invoked"))
            .env("GIX_FILTER_SENTINEL", self.0.join("filter-invoked"));
        command
    }

    fn ok(&self, directory: &Path, args: &[&str]) -> String {
        let output = self.command(directory).args(args).output().unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap()
    }

    fn error(&self, directory: &Path, args: &[&str], message: &str) {
        let output = self.command(directory).args(args).output().unwrap();
        assert_error(&output, message);
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("gix CLI evidence: {}", self.0.display());
        } else {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

fn assert_error(output: &Output, message: &str) {
    assert!(!output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(message),
        "expected {message:?}: {output:?}"
    );
}

fn lines(text: &str, expected: &[&str]) {
    for line in expected {
        assert!(
            text.lines().any(|actual| actual == *line),
            "{line:?}: {text}"
        );
    }
}

#[test]
fn init_stage_commit_recover_switch_and_merge() -> Result {
    let client = Client::new();
    let root = client.0.join("repository");
    fs::create_dir(&root)?;
    fs::write(root.join("sentinel"), "preserve\n")?;
    client.ok(&root, &["init"]);
    assert_eq!(fs::read(root.join(".git/HEAD"))?, b"ref: refs/heads/main\n");
    assert_eq!(fs::read(root.join("sentinel"))?, b"preserve\n");
    fs::write(root.join("-leading"), "cli stage\n")?;
    client.ok(&root, &["add", "--", "-leading"]);
    client.ok(&root, &["unstage", "--", "-leading"]);
    assert_eq!(client.ok(&root, &["status"]), "?? -leading\n?? sentinel\n");
    assert_eq!(fs::read(root.join("-leading"))?, b"cli stage\n");
    assert!(!root.join(".git/index.lock").exists());
    client.ok(&root, &["add", "--", "-leading"]);
    client.ok(
        &root,
        &[
            "-c",
            "user.name=CLI",
            "-c",
            "user.email=cli@example.com",
            "commit",
            "-m",
            "cli-initial",
        ],
    );
    let repo = gix::open(&root)?;
    let commit = repo.head_commit()?;
    assert_eq!(commit.message_raw()?.as_bytes(), b"cli-initial");
    assert_eq!(commit.parent_ids().count(), 0);
    let blob = repo
        .rev_parse_single(b"HEAD:-leading".as_bstr())?
        .object()?
        .try_into_blob()?;
    assert_eq!(blob.data, b"cli stage\n");
    fs::write(root.join("-leading"), "dirty\n")?;
    lines(
        &client.ok(&root, &["diff", "--", "-leading"]),
        &["--- a/-leading", "+++ b/-leading", "-cli stage", "+dirty"],
    );
    client.ok(&root, &["restore", "--", "-leading"]);
    assert_eq!(fs::read(root.join("-leading"))?, b"cli stage\n");
    client.ok(&root, &["branch", "create", "cli-topic"]);
    fs::write(root.join(".git/HEAD.lock"), "foreign\n")?;
    assert!(
        !client
            .command(&root)
            .args(["switch", "cli-topic"])
            .output()?
            .status
            .success()
    );
    assert!(root.join(".git/gix-operation").is_file());
    assert_eq!(
        client.ok(&root, &["recover"]),
        "restored recorded original state\n"
    );
    assert!(!root.join(".git/gix-operation").exists());
    assert_eq!(fs::read(root.join(".git/HEAD"))?, b"ref: refs/heads/main\n");
    assert_eq!(fs::read(root.join(".git/HEAD.lock"))?, b"foreign\n");
    fs::remove_file(root.join(".git/HEAD.lock"))?;
    client.ok(&root, &["switch", "cli-topic"]);
    assert_eq!(
        fs::read(root.join(".git/HEAD"))?,
        b"ref: refs/heads/cli-topic\n"
    );
    client.ok(&root, &["merge", "main"]);
    client.error(
        &root,
        &["merge", "--abort"],
        "repository has no ready merge",
    );
    Ok(())
}

// A local upstream (`branch.<name>.remote = .`) exercises everything in pull but the fetch.
#[test]
fn pull_merges_the_upstream_as_git_does() -> Result {
    let client = Client::new();
    let root = client.0.join("repository");
    client.ok(&client.0, &["init", root.to_str().unwrap()]);
    let identity = [
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
    ];
    let commit = |file: &str| {
        fs::write(root.join(file), file).unwrap();
        client.ok(&root, &["add", file]);
        client.ok(&root, &[&identity[..], &["commit", "-m", file]].concat());
    };
    let commit_on_main = |file: &str| {
        client.ok(&root, &["checkout", "main"]);
        commit(file);
        client.ok(&root, &["checkout", "topic"]);
    };
    let tip = |name: &str| {
        let repo = gix::open(&root).unwrap();
        repo.find_reference(name).unwrap().id().detach()
    };
    let head = || gix::open(&root).unwrap().head_id().unwrap().detach();
    commit("base");
    client.error(&root, &["pull"], "branch 'main' has no upstream branch");
    client.ok(&root, &["checkout", "--track", "-b", "topic", "main"]);
    assert_eq!(client.ok(&root, &["pull"]), "Already up to date.\n");
    client.error(
        &root,
        &["pull", "origin"],
        "branch 'topic' has no upstream on remote 'origin'",
    );

    // Behind the upstream: every choice but `pull.ff = false` fast-forwards.
    commit_on_main("upstream-1");
    client.error(
        &root,
        &["-c", "pull.ff=false", "pull"],
        "pull.ff = false asks for a merge commit",
    );
    assert!(!root.join("upstream-1").exists());
    let pulled = client.ok(&root, &["-c", "pull.rebase=true", "pull"]);
    assert!(
        pulled.starts_with("Updating ") && pulled.ends_with("\nFast-forward\n"),
        "{pulled}"
    );
    assert!(root.join("upstream-1").is_file());
    assert_eq!(head(), tip("refs/heads/main"));
    let reflog = fs::read_to_string(root.join(".git/logs/HEAD"))?;
    assert!(
        reflog.trim_end().ends_with("\tpull: Fast-forward"),
        "{reflog}"
    );

    // Diverged: only an explicit choice to merge goes ahead.
    commit("topic-1");
    commit_on_main("upstream-2");
    let ours = head();
    for (args, message) in [
        (
            &["pull"][..],
            "run 'gix pull --rebase' to rebase or 'gix pull --no-rebase' to merge",
        ),
        (&["pull", "--ff-only"], "a fast-forward is not possible"),
        (
            &["-c", "pull.ff=only", "pull"],
            "a fast-forward is not possible",
        ),
        (&["pull", "--rebase", "--no-rebase"], "cannot be used with"),
        (
            &[
                "-c",
                "pull.rebase=false",
                "-c",
                "branch.topic.rebase=merges",
                "pull",
            ],
            "a kind of rebase that gix cannot do",
        ),
        // Empty values: a user configuration outside the test may name an identity.
        (
            &[
                "-c",
                "user.name=",
                "-c",
                "user.email=",
                "pull",
                "--no-rebase",
            ],
            "author identity requires a nonempty name and email",
        ),
    ] {
        client.error(&root, args, message);
    }
    assert_eq!(head(), ours);
    assert!(!root.join("upstream-2").exists());
    let merge = [
        &identity[..],
        &["-c", "pull.ff=only", "pull", "--no-rebase"],
    ]
    .concat();
    assert_eq!(client.ok(&root, &merge), "Merge made.\n");
    let repo = gix::open(&root)?;
    let merged = repo.head_commit()?;
    assert_eq!(
        merged.message_raw()?.as_bytes(),
        b"Merge branch 'main' into topic"
    );
    let theirs = tip("refs/heads/main");
    assert_eq!(
        merged.parent_ids().map(gix::Id::detach).collect::<Vec<_>>(),
        [ours, theirs]
    );
    assert!(root.join("upstream-2").is_file());
    assert_eq!(
        client.ok(&root, &["-c", "pull.rebase=false", "pull", ".", "main"]),
        "Already up to date.\n"
    );

    fs::write(root.join(".git/HEAD"), format!("{theirs}\n"))?;
    client.error(
        &root,
        &["pull", ".", "main"],
        "pull requires HEAD attached to a local branch",
    );
    Ok(())
}

#[test]
fn pull_rebase_replays_local_commits() -> Result {
    let client = Client::new();
    let root = client.0.join("repository");
    client.ok(&client.0, &["init", root.to_str().unwrap()]);
    let identity = [
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
    ];
    let other = [
        "-c",
        "user.name=Other",
        "-c",
        "user.email=other@example.invalid",
    ];
    let commit_file = |who: &[&str], message: &str, file: &str, text: &str| {
        fs::write(root.join(file), text).unwrap();
        client.ok(&root, &["add", file]);
        client.ok(&root, &[who, &["commit", "-m", message]].concat());
    };
    // Most commits write their own name into a file of that name.
    let commit = |name: &str| commit_file(&identity, name, name, name);
    let on_main = |message: &str, file: &str, text: &str| {
        client.ok(&root, &["checkout", "main"]);
        commit_file(&identity, message, file, text);
        client.ok(&root, &["checkout", "topic"]);
    };
    // Subject, author and committer of every commit on the first-parent line, newest first.
    let history = || {
        let repo = gix::open(&root).unwrap();
        let mut commit = repo.head_commit().unwrap();
        let mut seen = Vec::new();
        loop {
            let parent = {
                let decoded = commit.decode().unwrap();
                seen.push(format!(
                    "{} {}/{}",
                    decoded.message.trim().as_bstr(),
                    decoded.author().unwrap().name,
                    decoded.committer().unwrap().name
                ));
                decoded.parents().next()
            };
            let Some(parent) = parent else {
                return seen;
            };
            commit = repo.find_commit(parent).unwrap();
        }
    };
    let pull = |args: &[&str]| client.ok(&root, &[&identity[..], args].concat());
    let last_reflog = |name: &str| {
        let log = fs::read_to_string(root.join(".git/logs").join(name)).unwrap();
        let line = log.lines().last().unwrap();
        line.split_once('\t').unwrap().1.to_owned()
    };
    let rev = |name: &str| {
        let repo = gix::open(&root).unwrap();
        repo.rev_parse_single(name).unwrap().detach().to_string()
    };

    commit("base");
    client.ok(&root, &["checkout", "--track", "-b", "topic", "main"]);
    commit_file(&other, "topic-1", "topic-1", "topic-1");
    assert_eq!(
        pull(&["pull", "--rebase"]),
        "Current branch topic is up to date.\n"
    );

    // The branch has a commit that the upstream has too, and a merge of its own.
    on_main("shared", "shared", "shared");
    on_main("upstream-1", "upstream-1", "upstream-1");
    client.ok(&root, &["checkout", "-b", "side"]);
    commit("side-1");
    client.ok(&root, &["checkout", "topic"]);
    commit("shared");
    let shared = rev("HEAD");
    client.ok(&root, &[&identity[..], &["merge", "side"]].concat());
    commit("topic-2");
    let upstream = rev("main");
    // `--rebase` on the command line overrides a configured `pull.ff = only`.
    assert_eq!(
        pull(&["-c", "pull.ff=only", "pull", "--rebase"]),
        format!(
            "dropping {} (shared) -- patch contents already upstream\n\
             Successfully rebased and updated refs/heads/topic.\n",
            &shared[..7]
        )
    );
    assert_eq!(
        history(),
        [
            "topic-2 Test/Test",
            "side-1 Test/Test",
            "topic-1 Other/Test",
            "upstream-1 Test/Test",
            "shared Test/Test",
            "base Test/Test",
        ]
    );
    let finished = format!("pull --rebase (finish): refs/heads/topic onto {upstream}");
    assert_eq!(last_reflog("HEAD"), finished);
    assert_eq!(last_reflog("refs/heads/topic"), finished);
    assert_eq!(
        fs::read(root.join(".git/HEAD"))?,
        b"ref: refs/heads/topic\n"
    );
    assert_eq!(client.ok(&root, &["status"]), "");
    for file in ["topic-1", "side-1", "topic-2", "shared", "upstream-1"] {
        assert_eq!(fs::read_to_string(root.join(file))?, file);
    }

    // The settings ask for a rebase as well. The one of the branch wins.
    on_main("upstream-2", "upstream-2", "upstream-2");
    commit("topic-3");
    let configured = ["-c", "pull.rebase=false", "-c", "branch.topic.rebase=true"];
    assert_eq!(
        pull(&[&configured[..], &["-c", "pull.ff=false", "pull"]].concat()),
        "Successfully rebased and updated refs/heads/topic.\n"
    );
    assert_eq!(
        history()[..5],
        [
            "topic-3 Test/Test",
            "topic-2 Test/Test",
            "side-1 Test/Test",
            "topic-1 Other/Test",
            "upstream-2 Test/Test",
        ]
    );
    assert!(last_reflog("HEAD").starts_with("pull (finish): refs/heads/topic onto "));

    // A missing identity stops the rebase before anything changes.
    on_main("theirs", "base", "theirs\n");
    commit_file(&identity, "mine", "base", "mine\n");
    let mine = rev("HEAD");
    commit("topic-4");
    let before = rev("HEAD");
    client.error(
        &root,
        &["-c", "user.name=", "-c", "user.email=", "pull", "--rebase"],
        "author identity requires a nonempty name and email",
    );
    assert_eq!(rev("HEAD"), before);
    assert_eq!(client.ok(&root, &["status"]), "");
    assert!(!root.join(".git/gix-operation").exists());

    // A conflict stops the rebase at the last commit that applied, with the conflict in
    // the files. The branch itself does not move.
    let stops_at = |commit: &str, subject: &str| {
        let mut pull = client.command(&root);
        pull.args(identity).args(["pull", "--rebase"]);
        let expected = format!(
            "could not apply {} ({subject})\n\nResolve the conflict in your files",
            &commit[..7]
        );
        assert_error(&pull.output().unwrap(), &expected);
    };
    stops_at(&mine, "mine");
    assert_eq!(
        fs::read_to_string(root.join("base"))?,
        format!(
            "<<<<<<< HEAD\ntheirs\n=======\nmine\n>>>>>>> {} (mine)\n",
            &mine[..7]
        )
    );
    assert_eq!(
        client.ok(&root, &["status"]),
        "operation rebase ready\nUU base\n"
    );
    assert_eq!(
        client.ok(&root, &["branch"]),
        "* (no branch, rebasing topic)\n  main\n  side\n  topic\n"
    );
    assert_eq!(history()[0], "topic-3 Test/Test");
    assert_eq!(rev("refs/heads/topic"), before);
    assert_eq!(
        fs::read_to_string(root.join(".git/HEAD"))?,
        format!("{}\n", rev("HEAD"))
    );
    let in_progress = "a rebase is in progress; run 'gix rebase --continue'";
    for (args, message) in [
        (&["switch", "main"][..], in_progress),
        (&["pull"], in_progress),
        (&["merge", "main"], in_progress),
        (&["recover"], in_progress),
        (&["restore", "base"], in_progress),
        (&["unstage", "base"], in_progress),
        (
            &["commit", "-m", "resolved"],
            "a rebase is stopped at a conflict",
        ),
        (&["merge", "--abort"], "operation is not a ready merge"),
    ] {
        client.error(&root, &[&identity[..], args].concat(), message);
    }

    assert_eq!(client.ok(&root, &["rebase", "--abort"]), "");
    assert_eq!(
        fs::read(root.join(".git/HEAD"))?,
        b"ref: refs/heads/topic\n"
    );
    assert_eq!(rev("HEAD"), before);
    assert_eq!(client.ok(&root, &["status"]), "");
    assert_eq!(fs::read_to_string(root.join("base"))?, "mine\n");
    assert!(!root.join(".git/gix-operation").exists());
    assert_eq!(
        last_reflog("HEAD"),
        "rebase (abort): returning to refs/heads/topic"
    );
    for action in ["--continue", "--skip", "--abort"] {
        client.error(&root, &["rebase", action], "no rebase is in progress");
    }

    // Again. This time the conflict is resolved, and the rebase goes on to its end.
    stops_at(&mine, "mine");
    client.error(
        &root,
        &["rebase", "--continue"],
        "a conflict is not resolved yet",
    );
    fs::write(root.join("base"), "resolved\n")?;
    client.ok(&root, &["add", "base"]);
    fs::write(root.join("topic-1"), "not staged")?;
    client.error(&root, &["rebase", "--continue"], "has local changes");
    fs::write(root.join("topic-1"), "topic-1")?;
    let rebased = "Successfully rebased and updated refs/heads/topic.\n";
    assert_eq!(pull(&["rebase", "--continue"]), rebased);
    assert_eq!(
        history()[..3],
        ["topic-4 Test/Test", "mine Test/Test", "topic-3 Test/Test"]
    );
    assert_eq!(fs::read_to_string(root.join("base"))?, "resolved\n");
    assert_eq!(
        fs::read(root.join(".git/HEAD"))?,
        b"ref: refs/heads/topic\n"
    );
    assert_eq!(client.ok(&root, &["status"]), "");
    assert!(!root.join(".git/gix-operation").exists());
    assert_eq!(
        last_reflog("HEAD"),
        "rebase (finish): returning to refs/heads/topic"
    );
    assert_eq!(
        last_reflog("refs/heads/topic"),
        format!("rebase (finish): refs/heads/topic onto {}", rev("main"))
    );

    // Both sides add the same file. The commit of the branch is skipped.
    on_main("their clash", "clash", "theirs\n");
    commit_file(&identity, "my clash", "clash", "mine\n");
    let clash = rev("HEAD");
    commit("topic-5");
    stops_at(&clash, "my clash");
    assert_eq!(
        client.ok(&root, &["status"]),
        "operation rebase ready\nUU clash\n"
    );
    assert_eq!(pull(&["rebase", "--skip"]), rebased);
    assert_eq!(
        history()[..3],
        ["topic-5 Test/Test", "topic-4 Test/Test", "mine Test/Test"]
    );
    assert_eq!(fs::read_to_string(root.join("clash"))?, "theirs\n");
    assert_eq!(client.ok(&root, &["status"]), "");

    // A resolution that takes the upstream version leaves nothing of the commit, so the
    // commit is dropped.
    on_main("their change", "clash", "theirs again\n");
    commit_file(&identity, "my change", "clash", "mine again\n");
    let change = rev("HEAD");
    commit("topic-6");
    stops_at(&change, "my change");
    fs::write(root.join("clash"), "theirs again\n")?;
    client.ok(&root, &["add", "clash"]);
    assert_eq!(pull(&["rebase", "--continue"]), rebased);
    assert_eq!(history()[..2], ["topic-6 Test/Test", "topic-5 Test/Test"]);
    assert_eq!(fs::read_to_string(root.join("clash"))?, "theirs again\n");
    assert_eq!(client.ok(&root, &["status"]), "");

    // The last commit of the branch conflicts. Resolving it ends the rebase.
    on_main("their end", "clash", "their end\n");
    commit_file(&identity, "my end", "clash", "my end\n");
    stops_at(&rev("HEAD"), "my end");
    fs::write(root.join("clash"), "both ends\n")?;
    client.ok(&root, &["add", "clash"]);
    assert_eq!(pull(&["rebase", "--continue"]), rebased);
    assert_eq!(history()[..2], ["my end Test/Test", "topic-6 Test/Test"]);
    assert_eq!(fs::read_to_string(root.join("clash"))?, "both ends\n");

    // Again the last commit conflicts. Skipping it ends the rebase too, and that makes
    // no commit, so it needs no identity.
    on_main("their close", "close", "their close\n");
    commit_file(&identity, "my close", "close", "my close\n");
    stops_at(&rev("HEAD"), "my close");
    let replayed = rev("HEAD");
    let anonymous = ["-c", "user.name=", "-c", "user.email=", "rebase", "--skip"];
    assert_eq!(client.ok(&root, &anonymous), rebased);
    assert_eq!(history()[0], "my end Test/Test");
    assert_eq!(rev("HEAD"), replayed);
    assert_eq!(fs::read_to_string(root.join("close"))?, "their close\n");
    assert_eq!(client.ok(&root, &["status"]), "");
    Ok(())
}

#[test]
fn rebase_pauses_before_a_conflict_it_cannot_show() -> Result {
    let client = Client::new();
    let root = client.0.join("repository");
    client.ok(&client.0, &["init", root.to_str().unwrap()]);
    let identity = [
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
    ];
    let gix = |args: &[&str]| client.ok(&root, &[&identity[..], args].concat());
    let commit = |message: &str, file: &str, bytes: &[u8]| {
        fs::write(root.join(file), bytes).unwrap();
        gix(&["add", file]);
        gix(&["commit", "-m", message]);
    };
    // Both sides change a binary file. Gix cannot write such a conflict into the file.
    commit("base", "data", &[0, b'b']);
    gix(&["checkout", "--track", "-b", "topic", "main"]);
    commit("first", "first", b"first\n");
    commit("my data", "data", &[0, b'm']);
    let conflicting = gix::open(&root)?.head_id()?.to_string();
    commit("last", "last", b"last\n");
    gix(&["checkout", "main"]);
    commit("their data", "data", &[0, b't']);
    gix(&["checkout", "topic"]);

    let cannot_show = format!(
        "could not apply {} (my data)\n\nGix cannot show this kind of conflict. \
         The rebase is paused before the commit.",
        &conflicting[..7]
    );
    let paused = || {
        assert_eq!(client.ok(&root, &["status"]), "operation rebase paused\n");
        assert_eq!(
            client.ok(&root, &["branch"]),
            "* (no branch, rebasing topic)\n  main\n  topic\n"
        );
        // The files are those of the last commit that applied, on top of the upstream.
        assert_eq!(fs::read(root.join("data")).unwrap(), [0, b't']);
        assert!(root.join("first").is_file() && !root.join("last").exists());
    };
    client.error(
        &root,
        &[&identity[..], &["pull", "--rebase"]].concat(),
        &cannot_show,
    );
    paused();
    // Going on meets the same commit again, and nothing can be staged for it.
    client.error(
        &root,
        &[&identity[..], &["rebase", "--continue"]].concat(),
        &cannot_show,
    );
    paused();
    client.error(&root, &["add", "data"], "a rebase is in progress");

    assert_eq!(
        gix(&["rebase", "--skip"]),
        "Successfully rebased and updated refs/heads/topic.\n"
    );
    assert_eq!(
        fs::read(root.join(".git/HEAD"))?,
        b"ref: refs/heads/topic\n"
    );
    assert_eq!(client.ok(&root, &["status"]), "");
    assert_eq!(fs::read(root.join("data"))?, [0, b't']);
    assert!(root.join("first").is_file() && root.join("last").is_file());
    let subjects: Vec<_> = gix(&["log"])
        .lines()
        .map(|line| line.split_once(' ').unwrap().1.to_owned())
        .collect();
    assert_eq!(subjects, ["last", "first", "their data", "base"]);
    Ok(())
}

#[test]
fn pull_rebase_leaves_out_what_a_rewritten_upstream_dropped() -> Result {
    let client = Client::new();
    let root = client.0.join("repository");
    client.ok(&client.0, &["init", root.to_str().unwrap()]);
    let identity = [
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
    ];
    let gix = |args: &[&str]| client.ok(&root, &[&identity[..], args].concat());
    let commit = |message: &str, file: &str, text: &str| {
        fs::write(root.join(file), text).unwrap();
        gix(&["add", file]);
        gix(&["commit", "-m", message]);
        gix::open(&root).unwrap().head_id().unwrap().to_string()
    };
    // The branch `topic` starts at the commit `dropped` of its upstream `main`.
    let base = commit("base", "base", "base\n");
    let dropped = commit("dropped", "file", "old\n");
    gix(&["checkout", "--track", "-b", "topic", "main"]);
    commit("mine", "mine", "mine\n");
    // Then `main` is rewritten, as by a forced fetch: `kept` takes the place of `dropped`
    // and conflicts with it. Only the reflog of `main` still knows `dropped`.
    gix(&["checkout", "-b", "rewritten", &base]);
    let kept = commit("kept", "file", "new\n");
    gix(&["checkout", "topic"]);
    fs::write(root.join(".git/refs/heads/main"), format!("{kept}\n"))?;
    let log = root.join(".git/logs/refs/heads/main");
    let line = format!("{dropped} {kept} Test <test@example.invalid> 0 +0000\tforced\n");
    fs::write(&log, fs::read_to_string(&log)? + &line)?;

    // The rebase replays `mine` alone. Replaying `dropped` too would stop at a conflict.
    assert_eq!(
        gix(&["pull", "--rebase"]),
        "Successfully rebased and updated refs/heads/topic.\n"
    );
    let subjects: Vec<_> = gix(&["log"])
        .lines()
        .map(|line| line.split_once(' ').unwrap().1.to_owned())
        .collect();
    assert_eq!(subjects, ["mine", "kept", "base"]);
    assert_eq!(fs::read_to_string(root.join("file"))?, "new\n");
    assert_eq!(client.ok(&root, &["status"]), "");

    // A commit counts as dropped by the upstream only if the reflog names it. Here `main`
    // takes `early` and `ahead` in one step, so its reflog names `ahead` alone. Then
    // `main` is rewritten without them. The branch `other` has `early`, and nothing shows
    // that it is not a commit of that branch: it is replayed, and it conflicts.
    gix(&["checkout", "--track", "-b", "other", "main"]);
    let early = commit("early", "file", "early\n");
    commit("late", "late", "late\n");
    gix(&["checkout", "-b", "ahead", &early]);
    let ahead = commit("ahead", "ahead", "ahead\n");
    gix(&["checkout", "-b", "rewritten-again", &kept]);
    let again = commit("kept again", "file", "newer\n");
    gix(&["checkout", "other"]);
    fs::write(root.join(".git/refs/heads/main"), format!("{again}\n"))?;
    let lines = format!(
        "{kept} {ahead} Test <test@example.invalid> 0 +0000\tfast-forward\n\
         {ahead} {again} Test <test@example.invalid> 0 +0000\tforced\n"
    );
    fs::write(&log, fs::read_to_string(&log)? + &lines)?;
    client.error(
        &root,
        &[&identity[..], &["pull", "--rebase"]].concat(),
        &format!("could not apply {} (early)", &early[..7]),
    );
    Ok(())
}

#[test]
fn relative_paths_are_relative_to_the_invocation_directory() -> Result {
    let client = Client::new();
    let root = client.0.join("repository");
    client.ok(&client.0, &["init", root.to_str().unwrap()]);
    let deep = root.join("sub/deep");
    fs::create_dir_all(&deep)?;
    fs::write(deep.join("file"), "base\n")?;
    client.ok(&deep, &["add", "file"]);
    client.ok(
        &root,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            "base",
        ],
    );
    fs::write(deep.join("file"), "changed\n")?;
    fs::write(root.join("root-untracked"), "root\n")?;
    assert_eq!(
        client.ok(&deep, &["status"]),
        "?? ../../root-untracked\n M file\n"
    );
    lines(
        &client.ok(&deep, &["diff", "file"]),
        &[
            "--- a/sub/deep/file",
            "+++ b/sub/deep/file",
            "-base",
            "+changed",
        ],
    );
    client.ok(&deep, &["add", "../.."]);
    assert_eq!(
        client.ok(&deep, &["status"]),
        "A  ../../root-untracked\nM  file\n"
    );
    client.ok(&deep, &["unstage", "file"]);
    assert_eq!(
        client.ok(&deep, &["status"]),
        "A  ../../root-untracked\n M file\n"
    );
    client.ok(&deep, &["restore", "file"]);
    assert_eq!(client.ok(&deep, &["status"]), "A  ../../root-untracked\n");
    assert!(!root.join(".git/index.lock").exists());
    Ok(())
}

#[test]
fn refs_configuration_policy_and_read_only_status() -> Result {
    let client = Client::new();
    let root = client.0.join("repository");
    repository::create(&root)?;
    let opened = motor_gix::repository::open(&root, &[], false)?;
    motor_gix::checkout::initial(&opened, &motor_gix::cancellation::Cancellation::new())?;
    let head = opened.repo.head_id()?.detach();
    let parent = opened.repo.rev_parse_single(b"HEAD^".as_bstr())?.detach();
    client.ok(&root, &["branch", "create", "cli-earlier", "HEAD^"]);
    client.ok(&root, &["tag", "create", "cli-head"]);
    assert_eq!(client.ok(&root, &["branch", "list"]), "cli-earlier\nmain\n");
    assert_eq!(client.ok(&root, &["tag", "list"]), "cli-head\n");
    let repo = gix::open(&root)?;
    assert_eq!(repo.find_reference("refs/heads/cli-earlier")?.id(), parent);
    assert_eq!(repo.find_reference("refs/tags/cli-head")?.id(), head);
    fs::create_dir(root.join(".git/refs/replace"))?;
    fs::write(
        root.join(format!(".git/refs/replace/{head}")),
        format!("{parent}\n"),
    )?;
    fs::write(root.join(".git/info/grafts"), format!("{head}\n"))?;
    let log = format!(
        "{:.12} second\n{:.12} initial\n",
        head.to_string(),
        parent.to_string()
    );
    assert_eq!(client.ok(&root, &["-c", "core.abbrev=12", "log"]), log);
    for variable in ["GIT_INDEX_FILE", "GIT_WORK_TREE"] {
        let output = client
            .command(&root)
            .env(variable, client.0.join("unselected"))
            .arg("log")
            .output()?;
        assert_error(&output, &format!("{variable} is not supported"));
    }
    let config_path = root.join(".git/config");
    let config = fs::read_to_string(&config_path)?;
    fs::write(
        &config_path,
        format!("{config}\n[gitoxide \"core\"]\nindexFile = unselected-index\n"),
    )?;
    client.error(
        &root,
        &["log"],
        "repository configuration selected a different index",
    );
    fs::write(config_path, config)?;
    fs::write(
        root.join(".git/info/attributes"),
        "editable filter=blocked\n",
    )?;
    client.error(
        &root,
        &[
            "-c",
            "filter.blocked.clean=must-not-run",
            "-c",
            "filter.blocked.required=true",
            "status",
        ],
        "path 'editable' uses unsupported filter 'blocked'",
    );
    fs::write(
        root.join(".git/info/attributes"),
        "editable filter=required-only\n",
    )?;
    client.error(
        &root,
        &["-c", "filter.required-only.required=true", "status"],
        "unsupported filter 'required-only'",
    );
    fs::remove_file(root.join(".git/info/attributes"))?;
    fs::write(root.join("café"), "UTF8\n")?;
    let index = fs::read(root.join(".git/index"))?;
    assert_eq!(client.ok(&root, &["status"]), " M café\n");
    assert_eq!(fs::read(root.join(".git/index"))?, index);
    fs::create_dir_all(root.join("discovery/deep"))?;
    assert_eq!(
        client.ok(
            &root.join("discovery/deep"),
            &["-c", "core.abbrev=12", "log"]
        ),
        log
    );
    Ok(())
}

#[test]
#[cfg_attr(
    target_os = "motor",
    ignore = "NLF-001: pipe closure; see docs/plans/new-layout-followups.md"
)]
fn closed_stdout_reports_broken_pipe() -> Result {
    let client = Client::new();
    let root = client.0.join("repository");
    repository::create(&root)?;
    #[cfg(not(target_os = "motor"))]
    let output = {
        let (reader, writer) = std::io::pipe()?;
        drop(reader);
        client
            .command(&root)
            .arg("log")
            .stdout(Stdio::from(writer))
            .stderr(Stdio::piped())
            .output()?
    };
    #[cfg(target_os = "motor")]
    let output = {
        // Motor supports captured child pipes, not std::io::pipe(). A title
        // larger than its one-page pipe makes early successful exit impossible
        // even if gix runs before this parent drops the captured reader.
        let opened = motor_gix::repository::open(
            &root,
            &["user.name=Native Test", "user.email=native@example.test"],
            false,
        )?;
        let head = opened.repo.head_id()?.detach();
        let tree = opened.repo.find_commit(head)?.tree_id()?.detach();
        let commit = opened
            .repo
            .new_commit("x".repeat(64 * 1024), tree, [head])?
            .id;
        fs::write(root.join(".git/HEAD"), format!("{commit}\n"))?;
        let mut child = client
            .command(&root)
            .arg("log")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        drop(child.stdout.take().unwrap());
        child.wait_with_output()?
    };
    assert_error(&output, "Broken pipe");
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostic.starts_with("gix: "), "{diagnostic}");
    assert!(!diagnostic.contains("panicked"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn user_configuration_paths_are_reported_without_running_git() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let client = Client::new();
    let root = client.0.join("repository");
    repository::create(&root)?;
    for (path, text) in [
        ("xdg/git/config", "[core]\nabbrev = 6\n".to_owned()),
        ("included.gitconfig", "[core]\nabbrev = 9\n".to_owned()),
        (
            "command-only.gitconfig",
            "[merge \"path-only\"]\ndriver = must-not-run\n".to_owned(),
        ),
        (
            "home/.gitconfig",
            format!(
                "[core]\nabbrev = 8\n[include]\npath = {}\npath = {}\n",
                client.0.join("included.gitconfig").display(),
                client.0.join("command-only.gitconfig").display()
            ),
        ),
    ] {
        fs::write(client.0.join(path), text)?;
    }
    fs::write(
        client.0.join("bin/git"),
        "#!/bin/sh\n: > \"$GIX_FAKE_GIT_SENTINEL\"\nexit 97\n",
    )?;
    fs::set_permissions(client.0.join("bin/git"), fs::Permissions::from_mode(0o755))?;
    let output = client
        .command(&root)
        .args(["-c", "core.abbrev=12", "--config-paths", "log"])
        .output()?;
    assert!(output.status.success(), "{output:?}");
    let reported = String::from_utf8(output.stderr)?;
    for path in [
        client.0.join("xdg/git/config"),
        client.0.join("home/.gitconfig"),
        client.0.join("included.gitconfig"),
        client.0.join("command-only.gitconfig"),
        root.join(".git/config"),
    ] {
        assert!(
            reported.contains(path.to_str().unwrap()),
            "{}: {reported}",
            path.display()
        );
    }
    let repo = gix::open(&root)?;
    let head = repo.head_id()?.detach();
    let parent = repo.rev_parse_single(b"HEAD^".as_bstr())?.detach();
    assert_eq!(
        String::from_utf8(output.stdout)?,
        format!(
            "{:.12} second\n{:.12} initial\n",
            head.to_string(),
            parent.to_string()
        )
    );
    assert!(!client.0.join("git-invoked").exists());
    Ok(())
}
