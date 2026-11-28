use std::{fs, path::PathBuf};

use gix::bstr::ByteSlice;

use super::{Client, Result};

fn repository() -> (Client, PathBuf) {
    let client = Client::new();
    let root = client.0.join("repository");
    client.ok(&client.0, &["init", root.to_str().unwrap()]);
    (client, root)
}

#[test]
fn diff_tracks_both_states_of_an_intent_to_add_file() -> Result {
    use gix::index::entry::{Flags, Mode};

    let (client, root) = repository();
    let repo = gix::open(&root)?;
    let mut index = gix::index::State::new(repo.object_hash());
    index.dangerously_push_entry(
        Default::default(),
        repo.write_blob([])?.detach(),
        Flags::EXTENDED | Flags::INTENT_TO_ADD,
        Mode::FILE,
        b"new".as_bstr(),
    );
    gix::index::File::from_state(index, repo.index_path()).write(Default::default())?;

    fs::write(root.join("new"), "new\n")?;
    assert_eq!(client.ok(&root, &["diff", "--staged"]), "");
    let patch = client.ok(&root, &["diff"]);
    assert_eq!(
        patch,
        "diff --git a/new b/new\nnew file mode 100644\nindex 0000000..3e75765\n\
         --- /dev/null\n+++ b/new\n@@ -0,0 +1 @@\n+new\n"
    );
    fs::write(client.0.join("intent.patch"), patch)?;
    let index_bytes = fs::read(repo.index_path())?;
    client.ok(&root, &["apply", "--check", "-R", "../intent.patch"]);
    assert_eq!(fs::read(root.join("new"))?, b"new\n");
    fs::remove_file(root.join("new"))?;
    assert!(!root.join("new").exists());
    assert_eq!(client.ok(&root, &["diff", "--staged"]), "");
    assert_eq!(
        client.ok(&root, &["diff"]),
        "diff --git a/new b/new\ndeleted file mode 100644\nindex e69de29..0000000\n"
    );
    fs::write(
        client.0.join("unrelated.patch"),
        "--- /dev/null\n+++ b/other\n@@ -0,0 +1 @@\n+unrelated\n",
    )?;
    client.ok(&root, &["apply", "--check", "../unrelated.patch"]);
    assert!(!root.join("other").exists());
    assert_eq!(fs::read(repo.index_path())?, index_bytes);
    for option in ["--index", "--cached"] {
        client.error(
            &root,
            &["apply", "--check", option, "../intent.patch"],
            "intent-to-add",
        );
    }
    Ok(())
}

#[test]
fn diff_skips_absent_sparse_files_and_reports_materialized_ones() -> Result {
    use gix::index::entry::{Flags, Mode};

    let (client, root) = repository();
    let repo = gix::open(&root)?;
    let mut index = gix::index::State::new(repo.object_hash());
    index.dangerously_push_entry(
        Default::default(),
        repo.write_blob(b"tracked\n")?.detach(),
        Flags::EXTENDED | Flags::SKIP_WORKTREE,
        Mode::FILE,
        b"omitted".as_bstr(),
    );
    gix::index::File::from_state(index, repo.index_path()).write(Default::default())?;
    let sparse = ["-c", "core.sparseCheckout=true", "diff", "omitted"];
    assert_eq!(client.ok(&root, &["diff"]), "");
    assert_eq!(client.ok(&root, &sparse), "");
    assert!(
        client
            .ok(&root, &["diff", "--staged"])
            .contains("+tracked\n")
    );

    fs::write(root.join("omitted"), "materialized\n")?;
    fs::write(root.join(".gitattributes"), "omitted filter=custom\n")?;
    assert_eq!(
        client.ok(
            &root,
            &["-c", "filter.custom.required=true", "diff", "omitted"]
        ),
        ""
    );
    assert!(
        client
            .ok(&root, &sparse)
            .contains("-tracked\n+materialized\n")
    );
    Ok(())
}

#[test]
fn indexed_copy_checks_a_missing_source() -> Result {
    let (client, root) = repository();
    fs::write(root.join("source"), "original\n")?;
    client.ok(&root, &["add", "source"]);
    fs::remove_file(root.join("source"))?;
    let copy = "diff --git a/source b/dest\ncopy from source\ncopy to dest\n\
                --- a/source\n+++ b/dest\n@@ -1 +1 @@\n-original\n+edited copy\n";
    let patch = client.0.join("copy.patch");
    fs::write(&patch, copy)?;
    client.error(&root, &["apply", "../copy.patch"], "--check");
    client.ok(&root, &["apply", "--index", "--check", "../copy.patch"]);
    assert!(!root.join("source").exists() && !root.join("dest").exists());
    let deletion = "diff --git a/source b/source\ndeleted file mode 100644\n\
                    --- a/source\n+++ /dev/null\n@@ -1 +0,0 @@\n-original\n";
    fs::write(
        &patch,
        format!("{copy}{}", deletion.replace("-original", "-wrong")),
    )?;
    client.error(
        &root,
        &["apply", "--index", "--check", "../copy.patch"],
        "patch does not apply",
    );
    assert!(!root.join("source").exists() && !root.join("dest").exists());
    Ok(())
}

#[test]
fn crlf_patch_checks_match_the_worktree_encoding_and_line_endings() -> Result {
    let (client, root) = repository();
    fs::write(
        root.join(".gitattributes"),
        "note text eol=crlf ident working-tree-encoding=ISO-8859-1\n",
    )?;
    let note = root.join("note");
    let old = b"$Id: original $\r\ncaf\xe9 old\r\n";
    fs::write(&note, old)?;
    let plain = root.join("plain");
    fs::write(&plain, b"keep\nold\r\n")?;
    client.ok(&root, &["add", "-A"]);
    let index = fs::read(root.join(".git/index"))?;
    fs::write(
        client.0.join("crlf.patch"),
        "--- a/note\n+++ b/note\n@@ -1,2 +1,2 @@\n $Id$\r\n-café old\r\n+café new\r\n\
         --- a/plain\n+++ b/plain\n@@ -1,2 +1,2 @@\n keep\n-old\r\n+new\r\n",
    )?;

    for mode in ["--index", "--cached"] {
        client.error(
            &root,
            &["apply", "--check", mode, "../crlf.patch"],
            "patch does not apply",
        );
    }
    client.ok(&root, &["apply", "--check", "../crlf.patch"]);
    assert_eq!(fs::read(&note)?, old);
    assert_eq!(fs::read(root.join(".git/index"))?, index);

    fs::write(&note, b"$Id$\ncaf\xe9 old\n")?;
    client.error(
        &root,
        &["apply", "--check", "../crlf.patch"],
        "patch does not apply",
    );
    Ok(())
}

#[test]
fn incoming_attributes_are_checked_before_writing_files() -> Result {
    let (client, root) = repository();
    let dir = root.join("sub");
    fs::create_dir(&dir)?;
    fs::write(dir.join("note.dat"), "old\n")?;
    client.ok(&root, &["add", "-A"]);
    let index = fs::read(root.join(".git/index"))?;
    fs::write(
        client.0.join("attrs.patch"),
        concat!(
            "diff --git a/.gitattributes b/.gitattributes\nnew file mode 100644\n",
            "--- /dev/null\n+++ b/.gitattributes\n@@ -0,0 +1 @@\n+*.dat filter=convert\n",
            "diff --git a/sub/note.dat b/sub/note.dat\n--- a/sub/note.dat\n+++ b/sub/note.dat\n",
            "@@ -1 +1 @@\n-old\n+new\n",
        ),
    )?;
    let apply = |options: &[&str]| {
        client
            .command(&root)
            .args(["-c", "filter.convert.required=true", "apply"])
            .args(options)
            .arg("../attrs.patch")
            .output()
            .unwrap()
    };
    for options in [&["--check"][..], &["--index", "--check"]] {
        super::assert_error(
            &apply(options),
            "path 'sub/note.dat' uses unsupported filter 'convert'",
        );
        assert!(!root.join(".gitattributes").exists());
        assert_eq!(fs::read_to_string(dir.join("note.dat"))?, "old\n");
        assert_eq!(fs::read(root.join(".git/index"))?, index);
    }
    assert!(apply(&["--cached", "--check"]).status.success());
    // A closer rule in the worktree overrides the incoming root rule.
    fs::write(dir.join(".gitattributes"), "*.dat -filter\n")?;
    assert!(apply(&["--index", "--check"]).status.success());
    Ok(())
}
