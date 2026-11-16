use std::path::Path;

use super::{Result, Server, Test, rejected, success};

const IDENTITY: [&str; 4] = [
    "-c",
    "user.name=Test",
    "-c",
    "user.email=test@example.invalid",
];

/// Run the same rebase with gix and with host Git in twin clones, and compare the results.
pub fn check(test: &Test) -> Result {
    let server = Server::new(test, "rebase-server");
    let (by_gix, by_git) = (test.0.join("rebase-gix"), test.0.join("rebase-git"));
    success(
        test.gix(&test.0)
            .args(["clone", &server.url("/repo.git"), "rebase-gix"]),
    );
    test.git(&test.0, &["clone", "remote.git", "rebase-git"]);
    let git =
        |directory: &Path, args: &[&str]| test.git(directory, &[&IDENTITY[..], args].concat());

    // The same branch in both: a commit by someone else, a commit that the upstream will
    // have too, an empty commit, and a merge of a side branch.
    // Every author date is fixed, so that the twins can be compared.
    for clone in [&by_gix, &by_git] {
        let commit = |name: &str, extra: &[&str]| {
            let date = ["--date=2026-01-02T03:04:05+00:00", "-m", name];
            git(clone, &[&["commit"], &date[..], extra].concat());
        };
        let add = |file: &str, extra: &[&str]| {
            std::fs::write(clone.join(file), file).unwrap();
            git(clone, &["add", file]);
            commit(file, extra);
        };
        add("local-1", &["--author=Other <other@example.invalid>"]);
        git(clone, &["checkout", "-b", "side"]);
        add("side-1", &[]);
        git(clone, &["checkout", "main"]);
        add("both", &[]);
        commit("empty", &["--allow-empty"]);
        git(clone, &["merge", "--no-ff", "-m", "merge", "side"]);
        add("local-2", &[]);
    }
    let update = test.0.join("update");
    for file in ["both", "upstream"] {
        std::fs::write(update.join(file), file)?;
        git(&update, &["add", file]);
        git(&update, &["commit", "-m", file]);
    }
    git(&update, &["push", "origin", "main"]);

    let dropped = git(&by_gix, &["rev-parse", "--short", "HEAD~3"]);
    let pulled = success(test.gix(&by_gix).args(IDENTITY).args(["pull", "--rebase"]));
    assert_eq!(
        pulled,
        format!(
            "dropping {} (both) -- patch contents already upstream\n\
             Successfully rebased and updated refs/heads/main.\n",
            dropped.trim()
        )
    );
    git(&by_git, &["pull", "--rebase"]);

    // Author, author date, committer, subject and tree of every commit, newest first.
    let log = |clone: &Path| git(clone, &["log", "--format=%an|%ae|%ad|%cn|%s|%T"]);
    let (ours, theirs) = (log(&by_gix), log(&by_git));
    assert_eq!(ours, theirs);
    let subjects: Vec<_> = ours
        .lines()
        .take(6)
        .map(|line| line.split('|').nth(4).unwrap())
        .collect();
    assert_eq!(
        subjects,
        ["local-2", "side-1", "empty", "local-1", "upstream", "both"]
    );
    assert!(ours.starts_with("Test|test@example.invalid|"), "{ours}");
    assert!(ours.contains("\nOther|other@example.invalid|"), "{ours}");
    assert_eq!(success(test.gix(&by_gix).arg("status")), "");
    assert_eq!(
        git(&by_gix, &["reflog", "-1", "--format=%gs", "main"]),
        git(&by_git, &["reflog", "-1", "--format=%gs", "main"])
    );
    test.git(&by_gix, &["fsck", "--strict", "--no-dangling"]);
    stop(test, &server)
}

/// A rebase that stops at a conflict must leave what host Git leaves, and abort like it.
fn stop(test: &Test, server: &Server) -> Result {
    let (by_gix, by_git) = (test.0.join("stop-gix"), test.0.join("stop-git"));
    success(
        test.gix(&test.0)
            .args(["clone", &server.url("/repo.git"), "stop-gix"]),
    );
    test.git(&test.0, &["clone", "remote.git", "stop-git"]);
    // With both dates fixed the twins have the same commits, so Git's name for the
    // conflicting commit is the same in both.
    let git = |directory: &Path, args: &[&str]| {
        let mut command = test.command("git", directory);
        for date in ["GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE"] {
            command.env(date, "2026-01-02T03:04:05+00:00");
        }
        command.args(["-c", "core.hooksPath=/dev/null", "-c", "core.abbrev=12"]);
        command.args(IDENTITY).args(args);
        command
    };
    let commit = |clone: &Path, file: &str, text: &str, message: &str| {
        std::fs::write(clone.join(file), text).unwrap();
        success(&mut git(clone, &["add", file]));
        success(&mut git(clone, &["commit", "-m", message]));
    };
    for clone in [&by_gix, &by_git] {
        commit(clone, "before", "before\n", "before");
        commit(clone, "pulled-1", "mine\n", "clash");
        commit(clone, "after", "after\n", "after");
    }
    let update = test.0.join("update");
    commit(&update, "pulled-1", "theirs\n", "theirs");
    success(&mut git(&update, &["push", "origin", "main"]));

    let mut pull = test.gix(&by_gix);
    pull.args(IDENTITY).args(["-c", "core.abbrev=12"]);
    rejected(pull.args(["pull", "--rebase"]).output()?, "could not apply");
    assert!(
        !git(&by_git, &["pull", "--rebase"])
            .output()?
            .status
            .success()
    );

    let same = |args: &[&str]| {
        let ours = success(&mut git(&by_gix, args));
        assert_eq!(ours, success(&mut git(&by_git, args)), "{args:?}");
        ours
    };
    let conflict = std::fs::read_to_string(by_gix.join("pulled-1"))?;
    assert_eq!(conflict, std::fs::read_to_string(by_git.join("pulled-1"))?);
    assert!(conflict.starts_with("<<<<<<< HEAD\ntheirs\n=======\nmine\n>>>>>>> "));
    assert!(conflict.ends_with(" (clash)\n"), "{conflict}");
    // The three versions of the file in the index, HEAD, and the branch that has not moved.
    assert_eq!(same(&["ls-files", "-u"]).lines().count(), 3);
    assert_eq!(
        same(&["status", "--porcelain", "--", "pulled-1"]),
        "UU pulled-1\n"
    );
    let head = same(&["log", "-1", "--format=%an|%ae|%ad|%cn|%s|%T"]);
    assert!(head.contains("|before|"), "{head}");
    assert_eq!(same(&["rev-parse", "--abbrev-ref", "HEAD"]), "HEAD\n");
    assert_eq!(same(&["log", "-1", "--format=%s", "main"]), "after\n");
    same(&["rev-parse", "main"]);

    success(test.gix(&by_gix).args(["rebase", "--abort"]));
    success(&mut git(&by_git, &["rebase", "--abort"]));
    assert_eq!(same(&["rev-parse", "--abbrev-ref", "HEAD"]), "main\n");
    assert_eq!(same(&["log", "-1", "--format=%H %s"]).len(), 47);
    assert_eq!(std::fs::read_to_string(by_gix.join("pulled-1"))?, "mine\n");
    assert_eq!(success(test.gix(&by_gix).arg("status")), "");
    test.git(&by_gix, &["fsck", "--strict", "--no-dangling"]);
    Ok(())
}
