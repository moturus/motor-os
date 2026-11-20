use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use super::{Result, Server, Test, success};

const IDENTITY: [&str; 4] = [
    "-c",
    "user.name=Test",
    "-c",
    "user.email=test@example.invalid",
];

/// A rebase leaves out a commit whose patch the upstream has. Host Git decides which
/// patches are the same: by the IDs it prints, and by the commits its own rebase skips.
pub fn check(test: &Test) -> Result {
    ids(test)?;
    applied(test)
}

/// Forty lines, with the given lines replaced. Lines are counted from one.
fn numbered(changes: &[(usize, &str)]) -> Vec<u8> {
    let mut text = String::new();
    for number in 1..=40 {
        match changes.iter().find(|(line, _)| *line == number) {
            Some((_, replacement)) => text.push_str(replacement),
            None => text.push_str(&format!("line {number}")),
        }
        text.push('\n');
    }
    text.into_bytes()
}

fn write(directory: &Path, path: &str, data: &[u8]) {
    let path = directory.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
}

fn chmod(directory: &Path, path: &str, mode: u32) {
    fs::set_permissions(directory.join(path), fs::Permissions::from_mode(mode)).unwrap();
}

/// The patch ID that gix computes for a commit is the one `git patch-id --stable` prints
/// for the diff of that commit.
///
/// Three kinds of change are missing here, because the command hashes them differently
/// from the comparison inside Git that a rebase uses: a binary file, a change of mode
/// alone, and an empty file. `applied()` covers them with Git's rebase itself.
fn ids(test: &Test) -> Result {
    let root = test.0.join("patch-ids");
    test.git(&test.0, &["init", "-b", "main", "patch-ids"]);
    let git = |args: &[&str]| test.git(&root, &[&IDENTITY[..], args].concat());
    let commit = |message: &str| {
        git(&["add", "-A"]);
        git(&["commit", "--allow-empty", "-m", message]);
    };
    let put = |path: &str, data: &[u8]| write(&root, path, data);
    let block = |name: &str| format!("fn {name}() {{\n    body();\n}}\n\n");

    put("text", &numbered(&[]));
    put("gone", b"gone\n");
    put("dir/a", b"a\n");
    put("spaces", b"a b\n");
    put("crlf", b"x\r\ny\r\n");
    put("noeol", b"end");
    put("blocks", (block("one") + &block("three")).as_bytes());
    commit("root");
    // Changes six lines apart share a hunk. Seven lines apart they do not.
    let hunks = [
        (5, "five"),
        (12, "twelve"),
        (20, "twenty"),
        (38, "thirty-eight"),
    ];
    put("text", &numbered(&hunks));
    commit("several hunks");
    fs::remove_file(root.join("gone"))?;
    put("new", b"new\n");
    commit("a file less and a file more");
    put("spaces", b"a  b c\n");
    chmod(&root, "spaces", 0o755);
    commit("mode and text");
    put("crlf", b"x\ny\n");
    commit("only whitespace");
    put("noeol", b"end\nmore");
    commit("no newline at the end");
    fs::create_dir(root.join("dir2"))?;
    fs::rename(root.join("dir/a"), root.join("dir2/a"))?;
    commit("a file moved");
    fs::remove_file(root.join("new"))?;
    put("new/inner", b"inner\n");
    commit("a file becomes a directory");
    // The new block could be shown in more than one place. Git moves it down.
    put(
        "blocks",
        (block("one") + &block("two") + &block("three")).as_bytes(),
    );
    commit("a block between two like it");
    std::os::unix::fs::symlink("text", root.join("link"))?;
    commit("a symbolic link");
    fs::remove_file(root.join("link"))?;
    std::os::unix::fs::symlink("dir2/a", root.join("link"))?;
    commit("another target");
    commit("nothing");
    let submodule = |commit: &str| {
        let entry = format!("160000,{},sub", commit.trim());
        git(&["update-index", "--add", "--cacheinfo", &entry]);
    };
    submodule(&git(&["rev-parse", "HEAD~3"]));
    git(&["commit", "-m", "a submodule"]);
    submodule(&git(&["rev-parse", "HEAD~1"]));
    git(&["commit", "-m", "the submodule moves"]);
    git(&["checkout", "-b", "side", "HEAD~4"]);
    put("side", b"side\n");
    git(&["add", "side"]);
    git(&["commit", "-m", "side"]);
    git(&["merge", "--no-ff", "-m", "merge", "main"]);

    let opened = motor_gix::repository::open(&root, &[], false)?;
    let cancellation = motor_gix::cancellation::Cancellation::new();
    let commits = git(&["rev-list", "--all"]);
    assert_eq!(commits.lines().count(), 16);
    for commit in commits.lines() {
        // Git's command works on the text of a diff. Without the indent heuristic that
        // text is the diff that Git itself hashes when it compares commits.
        let script = "git diff-tree --root --full-index --no-indent-heuristic -p \"$1\" \
                      | git patch-id --stable";
        let printed = success(test.command("sh", &root).args(["-c", script, "sh", commit]));
        let expected = printed.split(' ').next().unwrap_or_default().trim();
        let id = gix::ObjectId::from_hex(commit.as_bytes())?;
        let actual = match motor_gix::patch_id::of(&opened.repo, id, &cancellation)? {
            // Git prints nothing for a merge and for a commit that changes nothing.
            Some(id) if !id.is_null() => id.to_string(),
            _ => String::new(),
        };
        let subject = git(&["log", "-1", "--format=%s", commit]);
        assert_eq!(actual, expected, "patch ID of {}", subject.trim());
    }
    Ok(())
}

/// The upstream makes the changes of several commits of the branch, and then undoes them
/// all. Host Git skips the commits whose patch the upstream has, and replays the others.
/// Gix must skip the same commits, and end with the same history.
fn applied(test: &Test) -> Result {
    let server = Server::new(test, "patch-server");
    let update = test.0.join("update");
    let (by_gix, by_git) = (test.0.join("applied-gix"), test.0.join("applied-git"));
    // Both dates are fixed, so the twins have the same commits under the same names.
    let git = |directory: &Path, args: &[&str]| {
        let mut command = test.command("git", directory);
        for date in ["GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE"] {
            command.env(date, "2026-01-02T03:04:05+00:00");
        }
        command.args(["-c", "core.hooksPath=/dev/null", "-c", "core.abbrev=12"]);
        command.args(IDENTITY).args(args);
        command
    };
    // Only the named paths are staged: a clone made by gix holds a plain file where the
    // fixture has a symbolic link, and that must not become part of a commit.
    let commit = |directory: &Path, message: &str, paths: &[&str]| {
        success(&mut git(directory, &[&["add", "-A", "--"], paths].concat()));
        success(&mut git(directory, &["commit", "-m", message]));
    };

    write(&update, "text", &numbered(&[]));
    write(&update, "exe", b"#!/bin/sh\n");
    write(&update, "bin", &[0, 1, 2, 3]);
    write(&update, "gone", b"gone\n");
    write(&update, "moved", b"moved\n");
    // A binary file that has lines. `near` and `far` change one of its lines each.
    let lined = |near: &str, far: &str| format!("\0\na\n{near}\nc\nd\ne\nf\ng\nh\ni\n{far}\nk\n");
    write(&update, "lined", lined("b", "j").as_bytes());
    let base_files = ["text", "exe", "bin", "gone", "moved", "lined"];
    commit(&update, "patch base", &base_files);
    success(&mut git(&update, &["push", "origin", "main"]));
    let base = success(&mut git(&update, &["rev-parse", "HEAD"]));
    success(
        test.gix(&test.0)
            .args(["clone", &server.url("/repo.git"), "applied-gix"]),
    );
    test.git(&test.0, &["clone", "remote.git", "applied-git"]);

    let hunks = [
        (5, "five"),
        (12, "twelve"),
        (20, "twenty"),
        (38, "thirty-eight"),
    ];
    let with = |line: (usize, &'static str)| numbered(&[&hunks[..], &[line]].concat());
    // Each change as the upstream makes it. The first seven are also commits of the branch.
    type Change<'a> = (&'a str, &'a [&'a str], &'a dyn Fn(&Path));
    let upstream: [Change; 12] = [
        ("text", &["text"], &|d| write(d, "text", &numbered(&hunks))),
        ("spaces", &["ws"], &|d| write(d, "ws", b"x=1\n")),
        ("chmod", &["exe"], &|d| chmod(d, "exe", 0o755)),
        ("empty", &["empty"], &|d| write(d, "empty", b"")),
        ("binary", &["bin"], &|d| write(d, "bin", &[0, 9, 9])),
        ("delete", &["gone"], &|d| {
            fs::remove_file(d.join("gone")).unwrap()
        }),
        ("rename", &["moved", "renamed"], &|d| {
            fs::rename(d.join("moved"), d.join("renamed")).unwrap()
        }),
        ("other text", &["text"], &|d| {
            write(d, "text", &with((30, "upstream 30")))
        }),
        ("other mode", &["tool"], &|d| write(d, "tool", b"tool\n")),
        ("other binary", &["bin2"], &|d| write(d, "bin2", &[0, 2])),
        ("binary far", &["lined"], &|d| {
            write(d, "lined", lined("b", "J").as_bytes())
        }),
        ("binary near", &["lined"], &|d| {
            write(d, "lined", lined("B", "J").as_bytes())
        }),
    ];
    // The branch makes them in another order and between other changes. Its `spaces`
    // differs from the upstream's in whitespace only, which a patch ID ignores. Its three
    // `other` commits change the same files as the upstream's, but not in the same way.
    // Its `binary near` changes the same line as the upstream's, but in a binary file
    // that is not the same before: binary files are compared whole, not line by line.
    let branch: [Change; 11] = [
        ("other text", &["text"], &|d| {
            write(d, "text", &numbered(&[(30, "local 30")]))
        }),
        ("text", &["text"], &|d| {
            write(d, "text", &with((30, "local 30")))
        }),
        ("other mode", &["tool"], &|d| {
            write(d, "tool", b"tool\n");
            chmod(d, "tool", 0o755);
        }),
        ("spaces", &["ws"], &|d| write(d, "ws", b"x = 1\n")),
        upstream[2],
        ("other binary", &["bin2"], &|d| write(d, "bin2", &[0, 1])),
        upstream[3],
        upstream[4],
        upstream[5],
        upstream[6],
        ("binary near", &["lined"], &|d| {
            write(d, "lined", lined("B", "j").as_bytes())
        }),
    ];
    for (message, paths, change) in upstream {
        change(&update);
        commit(&update, message, paths);
    }
    let added = ["ws", "empty", "renamed", "tool", "bin2"];
    success(&mut git(
        &update,
        &[&["rm", "-q", "--"], &added[..]].concat(),
    ));
    success(&mut git(&update, &["checkout", base.trim(), "--", "."]));
    commit(&update, "undo", &["."]);
    let tree = |revision: &str| {
        let tree = format!("{}^{{tree}}", revision.trim());
        success(&mut git(&update, &["rev-parse", &tree]))
    };
    assert_eq!(tree("HEAD"), tree(&base), "the upstream is as it was");
    success(&mut git(&update, &["push", "origin", "main"]));
    for clone in [&by_gix, &by_git] {
        for (message, paths, change) in branch {
            change(clone);
            commit(clone, message, paths);
        }
    }

    let mut pull = test.gix(&by_gix);
    pull.args(IDENTITY).args(["-c", "core.abbrev=12"]);
    let by_gix_said = success(pull.args(["pull", "--rebase"]));
    let by_git_said = git(&by_git, &["pull", "--rebase"]).output()?;
    assert!(by_git_said.status.success(), "{by_git_said:?}");
    // What each left out, in its own words: the name of each commit follows these.
    let skipped = |said: &str| -> Vec<String> {
        let name = |line: &str| -> Option<String> {
            let rest = line.strip_prefix("warning: skipped previously applied commit ")?;
            Some(rest.split(' ').next()?.to_owned())
        };
        said.lines().filter_map(name).collect()
    };
    let ours = skipped(&by_gix_said);
    assert_eq!(ours, skipped(&String::from_utf8(by_git_said.stderr)?));
    assert_eq!(ours.len(), 7, "{by_gix_said}");
    assert!(!by_gix_said.contains("dropping"), "{by_gix_said}");

    let log = |clone: &Path| success(&mut git(clone, &["log", "--format=%an|%ad|%s|%T"]));
    let history = log(&by_gix);
    assert_eq!(history, log(&by_git));
    let subjects: Vec<_> = history
        .lines()
        .take(5)
        .map(|line| line.split('|').nth(2).unwrap())
        .collect();
    let replayed = ["binary near", "other binary", "other mode", "other text"];
    assert_eq!(subjects, [&replayed[..], &["undo"]].concat());
    assert_eq!(success(test.gix(&by_gix).arg("status")), "");
    test.git(&by_gix, &["fsck", "--strict", "--no-dangling"]);
    Ok(())
}
