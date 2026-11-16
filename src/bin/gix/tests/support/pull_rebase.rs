use std::path::Path;

use super::{Result, Server, Test, success};

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
    Ok(())
}
