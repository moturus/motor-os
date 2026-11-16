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
    stop(test, &server)?;
    rewritten(test, &server)
}

/// The upstream is rewritten by a forced push. Like host Git, gix must leave out the
/// commit that the upstream dropped: the reflog of `origin/main` shows where the branch
/// began.
fn rewritten(test: &Test, server: &Server) -> Result {
    let (by_gix, by_git) = (test.0.join("fork-gix"), test.0.join("fork-git"));
    success(
        test.gix(&test.0)
            .args(["clone", &server.url("/repo.git"), "fork-gix"]),
    );
    test.git(&test.0, &["clone", "remote.git", "fork-git"]);
    let git =
        |directory: &Path, args: &[&str]| test.git(directory, &[&IDENTITY[..], args].concat());
    for clone in [&by_gix, &by_git] {
        std::fs::write(clone.join("mine"), "mine\n")?;
        git(clone, &["add", "mine"]);
        let date = "--date=2026-01-02T03:04:05+00:00";
        git(clone, &["commit", date, "-m", "mine"]);
    }
    // The new tip changes the same file as the old one, so replaying the old tip on it
    // would stop at a conflict.
    let update = test.0.join("update");
    std::fs::write(update.join("pulled-1"), "rewritten\n")?;
    git(&update, &["add", "pulled-1"]);
    git(&update, &["commit", "--amend", "-m", "rewritten"]);
    git(&update, &["push", "--force", "origin", "main"]);

    let pulled = success(test.gix(&by_gix).args(IDENTITY).args(["pull", "--rebase"]));
    assert_eq!(
        pulled,
        "Successfully rebased and updated refs/heads/main.\n"
    );
    git(&by_git, &["pull", "--rebase"]);
    let log = |clone: &Path| git(clone, &["log", "--format=%an|%ae|%ad|%cn|%s|%T"]);
    let (ours, theirs) = (log(&by_gix), log(&by_git));
    assert_eq!(ours, theirs);
    let subjects: Vec<_> = ours
        .lines()
        .take(2)
        .map(|line| line.split('|').nth(4).unwrap())
        .collect();
    assert_eq!(subjects, ["mine", "rewritten"]);
    assert_eq!(success(test.gix(&by_gix).arg("status")), "");
    test.git(&by_gix, &["fsck", "--strict", "--no-dangling"]);
    Ok(())
}

/// A rebase that stops at a conflict must leave what host Git leaves. Abort, continue and
/// skip must then end where host Git ends.
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
        // `git rebase --continue` must not wait for an editor.
        command.env("GIT_EDITOR", "true");
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

    let gix = |args: &[&str]| {
        let mut command = test.gix(&by_gix);
        command.args(IDENTITY).args(["-c", "core.abbrev=12"]);
        command.args(args);
        command
    };
    let both_stop = || {
        rejected(
            gix(&["pull", "--rebase"]).output().unwrap(),
            "could not apply",
        );
        let pulled = git(&by_git, &["pull", "--rebase"]).output().unwrap();
        assert!(!pulled.status.success(), "{pulled:?}");
    };
    both_stop();

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

    // Stop again, resolve the conflict the same way in both, and continue to the end.
    let rebased = "Successfully rebased and updated refs/heads/main.\n";
    let log = ["log", "--format=%an|%ae|%ad|%cn|%s|%T"];
    both_stop();
    for clone in [&by_gix, &by_git] {
        std::fs::write(clone.join("pulled-1"), "resolved\n")?;
    }
    success(&mut gix(&["add", "pulled-1"]));
    success(&mut git(&by_git, &["add", "pulled-1"]));
    assert_eq!(success(&mut gix(&["rebase", "--continue"])), rebased);
    success(&mut git(&by_git, &["rebase", "--continue"]));
    let subjects = |log: String| -> Vec<String> {
        let subject = |line: &str| line.split('|').nth(4).unwrap().to_owned();
        log.lines().take(4).map(subject).collect()
    };
    assert_eq!(subjects(same(&log)), ["after", "clash", "before", "theirs"]);
    assert_eq!(same(&["rev-parse", "--abbrev-ref", "HEAD"]), "main\n");
    let finished = same(&["reflog", "-1", "--format=%gs", "main"]);
    assert!(finished.starts_with("rebase (finish): refs/heads/main onto "));
    assert_eq!(success(test.gix(&by_gix).arg("status")), "");

    // Now two commits of the branch conflict with the upstream, and both are skipped.
    // The first skip ends at the second conflict. The twins have other commit names by
    // now, so the conflict markers are not compared.
    for clone in [&by_gix, &by_git] {
        commit(clone, "pulled-1", "mine again\n", "clash again");
        commit(clone, "last", "last\n", "last");
    }
    commit(&update, "pulled-1", "theirs again\n", "theirs again");
    success(&mut git(&update, &["push", "origin", "main"]));
    both_stop();
    rejected(gix(&["rebase", "--skip"]).output()?, "(clash again)");
    let skipped = git(&by_git, &["rebase", "--skip"]).output()?;
    assert!(!skipped.status.success(), "{skipped:?}");
    assert_eq!(same(&["ls-files", "-u"]).lines().count(), 3);
    assert_eq!(subjects(same(&log))[..2], ["after", "before"]);
    assert_eq!(success(&mut gix(&["rebase", "--skip"])), rebased);
    success(&mut git(&by_git, &["rebase", "--skip"]));
    assert_eq!(
        subjects(same(&log)),
        ["last", "after", "before", "theirs again"]
    );
    assert_eq!(same(&["rev-parse", "--abbrev-ref", "HEAD"]), "main\n");
    let skipped = std::fs::read_to_string(by_gix.join("pulled-1"))?;
    assert_eq!(skipped, "theirs again\n");
    assert_eq!(success(test.gix(&by_gix).arg("status")), "");
    test.git(&by_gix, &["fsck", "--strict", "--no-dangling"]);
    Ok(())
}
