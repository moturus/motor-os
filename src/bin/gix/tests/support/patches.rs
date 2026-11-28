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
    client.ok(&root, &["apply", "-R", "../intent.patch"]);
    assert!(!root.join("new").exists());
    assert_eq!(client.ok(&root, &["diff", "--staged"]), "");
    assert_eq!(
        client.ok(&root, &["diff"]),
        "diff --git a/new b/new\ndeleted file mode 100644\nindex e69de29..0000000\n"
    );
    client.ok(&root, &["apply", "../intent.patch"]);
    assert_eq!(fs::read(root.join("new"))?, b"new\n");

    fs::write(
        client.0.join("unrelated.patch"),
        "--- /dev/null\n+++ b/other\n@@ -0,0 +1 @@\n+unrelated\n",
    )?;
    client.ok(&root, &["apply", "--check", "../unrelated.patch"]);
    client.ok(&root, &["apply", "../unrelated.patch"]);
    assert_eq!(fs::read(root.join("other"))?, b"unrelated\n");
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
fn indexed_copy_restores_the_missing_source_after_the_patch_checks() -> Result {
    let (client, root) = repository();
    fs::write(root.join("source"), "original\n")?;
    client.ok(&root, &["add", "source"]);
    fs::remove_file(root.join("source"))?;
    let copy = "diff --git a/source b/dest\ncopy from source\ncopy to dest\n\
                --- a/source\n+++ b/dest\n@@ -1 +1 @@\n-original\n+edited copy\n";
    let patch = client.0.join("copy.patch");
    fs::write(&patch, copy)?;
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
        &["apply", "--index", "../copy.patch"],
        "patch does not apply",
    );
    assert!(!root.join("source").exists() && !root.join("dest").exists());

    fs::write(&patch, copy)?;
    client.ok(&root, &["apply", "--cached", "../copy.patch"]);
    assert!(!root.join("source").exists() && !root.join("dest").exists());
    client.ok(&root, &["unstage", "dest"]);
    client.ok(&root, &["apply", "--index", "../copy.patch"]);
    assert_eq!(fs::read(root.join("source"))?, b"original\n");
    assert_eq!(fs::read(root.join("dest"))?, b"edited copy\n");
    assert_eq!(client.ok(&root, &["diff"]), "");

    client.ok(&root, &["unstage", "dest"]);
    fs::remove_file(root.join("dest"))?;
    fs::remove_file(root.join("source"))?;
    fs::write(patch, format!("{copy}{deletion}"))?;
    client.ok(&root, &["apply", "--index", "../copy.patch"]);
    assert!(!root.join("source").exists());
    assert_eq!(fs::read(root.join("dest"))?, b"edited copy\n");
    assert_eq!(client.ok(&root, &["diff"]), "");
    Ok(())
}

#[test]
fn crlf_worktree_patch_keeps_encoding_and_ident_conversions() -> Result {
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
    client.ok(&root, &["apply", "../crlf.patch"]);
    // Decode the worktree as Latin-1 and compare every byte of the line endings
    // and the ident expansion with the ordinary gix checkout filter.
    let worktree =
        || -> Result<String> { Ok(fs::read(&note)?.into_iter().map(char::from).collect()) };
    let expanded = |word: &str| -> Result<String> {
        let mut out = Vec::new();
        gix::filter::plumbing::ident::apply(
            format!("$Id$\r\ncafé {word}\r\n").as_bytes(),
            gix::hash::Kind::Sha1,
            &mut out,
        )?;
        Ok(String::from_utf8(out)?)
    };
    assert_eq!(worktree()?, expanded("new")?);
    assert_eq!(fs::read(&plain)?, b"keep\nnew\r\n");
    client.ok(&root, &["apply", "-R", "../crlf.patch"]);
    assert_eq!(worktree()?, expanded("old")?);
    assert_eq!(fs::read(&plain)?, b"keep\nold\r\n");
    assert_eq!(client.ok(&root, &["diff"]), "");
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
fn rename_swap_preserves_both_blobs_and_modes() -> Result {
    let (client, root) = repository();
    fs::write(root.join("one"), "first\n")?;
    fs::write(root.join("two"), "second\n")?;
    client.ok(&root, &["add", "-A"]);
    fs::write(
        client.0.join("mode.patch"),
        "diff --git a/two b/two\nold mode 100644\nnew mode 100755\n",
    )?;
    client.ok(&root, &["apply", "--index", "../mode.patch"]);
    let index = || -> Result<_> {
        let repo = gix::open(&root)?;
        let index = repo.index_or_empty()?;
        Ok(index
            .entries()
            .iter()
            .map(|e| (e.id, e.mode))
            .collect::<Vec<_>>())
    };
    let before = index()?;
    assert_eq!(before.len(), 2);
    assert_ne!(before[0].1, before[1].1);
    fs::write(
        client.0.join("swap.patch"),
        concat!(
            "diff --git a/two b/one\nsimilarity index 100%\nrename from two\nrename to one\n",
            "diff --git a/one b/two\nsimilarity index 100%\nrename from one\nrename to two\n",
        ),
    )?;
    for reverse in [false, true] {
        let mut args = vec!["apply", "--index", "../swap.patch"];
        if reverse {
            args.push("-R");
        }
        client.ok(&root, &args);
        let (one, two) = if reverse { (0, 1) } else { (1, 0) };
        assert_eq!(index()?, [before[one], before[two]]);
        let data = ["first\n", "second\n"];
        assert_eq!(fs::read_to_string(root.join("one"))?, data[one]);
        assert_eq!(fs::read_to_string(root.join("two"))?, data[two]);
    }
    Ok(())
}

#[test]
fn reverse_selects_the_destination_in_the_invocation_directory() -> Result {
    let (client, root) = repository();
    let sub = root.join("sub");
    fs::create_dir(&sub)?;
    fs::write(root.join("from"), "contents\n")?;
    client.ok(&root, &["add", "-A"]);
    fs::write(
        client.0.join("rename.patch"),
        concat!(
            "diff --git a/from b/sub/to\nsimilarity index 100%\n",
            "rename from from\nrename to sub/to\n",
        ),
    )?;
    client.ok(&sub, &["apply", "--index", "../../rename.patch"]);
    client.ok(&sub, &["apply", "--index", "-R", "../../rename.patch"]);
    assert!(!root.join("from").exists());
    assert_eq!(fs::read_to_string(sub.join("to"))?, "contents\n");
    client.ok(&root, &["apply", "--index", "-R", "../rename.patch"]);
    assert_eq!(fs::read_to_string(root.join("from"))?, "contents\n");
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
    for options in [&[][..], &["--check"], &["--index"], &["--index", "--check"]] {
        super::assert_error(
            &apply(options),
            "path 'sub/note.dat' uses unsupported filter 'convert'",
        );
        assert!(!root.join(".gitattributes").exists());
        assert_eq!(fs::read_to_string(dir.join("note.dat"))?, "old\n");
        assert_eq!(fs::read(root.join(".git/index"))?, index);
    }
    assert!(apply(&["--cached"]).status.success());
    assert!(!root.join(".gitattributes").exists());
    assert_eq!(fs::read_to_string(dir.join("note.dat"))?, "old\n");
    assert!(apply(&["--cached", "-R"]).status.success());

    // A closer rule in the worktree overrides the incoming root rule.
    fs::write(dir.join(".gitattributes"), "*.dat -filter\n")?;
    assert!(apply(&["--index"]).status.success());
    assert_eq!(fs::read_to_string(dir.join("note.dat"))?, "new\n");
    assert_eq!(
        fs::read_to_string(root.join(".gitattributes"))?,
        "*.dat filter=convert\n"
    );
    Ok(())
}

#[test]
fn deleted_attributes_and_missing_worktree_attributes_use_the_resulting_rules() -> Result {
    let (client, root) = repository();
    let nested = root.join("sub/.gitattributes");
    fs::create_dir(root.join("sub"))?;
    for path in [root.join(".gitattributes"), nested.clone()] {
        fs::write(path, "*.dat filter=convert\n")?;
    }
    client.ok(&root, &["add", "-A"]);
    fs::remove_file(&nested)?;
    fs::write(
        client.0.join("attrs.patch"),
        concat!(
            "diff --git a/.gitattributes b/.gitattributes\ndeleted file mode 100644\n",
            "--- a/.gitattributes\n+++ /dev/null\n@@ -1 +0,0 @@\n-*.dat filter=convert\n",
            "diff --git a/sub/new.dat b/sub/new.dat\nnew file mode 100644\n",
            "--- /dev/null\n+++ b/sub/new.dat\n@@ -0,0 +1 @@\n+new\n",
        ),
    )?;
    let args = [
        "-c",
        "filter.convert.required=true",
        "apply",
        "--index",
        "../attrs.patch",
    ];
    // With the nested file missing, its rule still comes from the index.
    super::assert_error(
        &client.command(&root).args(args).arg("--check").output()?,
        "path 'sub/new.dat' uses unsupported filter 'convert'",
    );
    assert!(root.join(".gitattributes").exists());
    assert!(!root.join("sub/new.dat").exists());

    // An empty nested file takes precedence over its indexed version.
    fs::write(&nested, [])?;
    client.ok(&root, &args);
    assert!(!root.join(".gitattributes").exists());
    assert_eq!(fs::read(root.join("sub/new.dat"))?, b"new\n");
    assert!(fs::read(nested)?.is_empty());
    Ok(())
}

#[test]
fn binary_hunks_span_multiple_buffers_and_validate_unused_directions() -> Result {
    // Git's binary patch for a new file of 16 KiB of zero bytes.
    const PATCH: &str = concat!(
        "diff --git a/block b/block\nnew file mode 100644\n",
        "index 0000000000000000000000000000000000000000..294f4016d05bdd696670c4840f1f36a71f9239de\n",
        "GIT binary patch\nliteral 16384\n",
        "zcmeIuF#!Mo0K%a4Pi+hzh(KY$fB^#r3>YwAz<>b*1`HT5V8DO@0|pEjFkrxd0RsjM\n",
        "q7%*VKfB^#r3>YwAz<>b*1`HT5V8DO@0|pEjFkrxd0RsjMyaxtA00031\n\n",
        "literal 0\nHcmV?d00001\n\n",
    );
    let (client, root) = repository();
    let patch = client.0.join("block.patch");
    let block = root.join("block");
    fs::write(&patch, PATCH)?;
    client.ok(&root, &["apply", "--index", "--check", "../block.patch"]);
    assert!(!block.exists());
    client.ok(&root, &["apply", "--index", "../block.patch"]);
    assert_eq!(fs::read(&block)?, vec![0; 16384]);
    client.ok(&root, &["apply", "--index", "-R", "../block.patch"]);
    assert!(!block.exists());

    let sub = root.join("sub");
    fs::create_dir(&sub)?;
    for (header, wrong) in [
        ("literal 16384", "literal 16383"),
        ("literal 0", "literal 1"),
    ] {
        fs::write(&patch, PATCH.replace(header, wrong))?;
        // The result is already in the object database. From sub/ the whole file is skipped.
        for dir in [&root, &sub] {
            client.error(
                dir,
                &["apply", "--check", patch.to_str().unwrap()],
                "corrupt binary patch",
            );
        }
        assert!(!block.exists());
    }
    Ok(())
}

#[test]
fn the_index_is_written_once_after_the_last_patch_file() -> Result {
    let (client, root) = repository();
    fs::write(root.join("one"), "first\n")?;
    fs::write(root.join("two"), "second\n")?;
    client.ok(&root, &["add", "-A"]);
    let patch = |name: &str, file: &str, old: &str, new: &str| {
        let text = format!(
            "diff --git a/{file} b/{file}\n--- a/{file}\n+++ b/{file}\n@@ -1 +1 @@\n-{old}\n+{new}\n"
        );
        fs::write(client.0.join(name), text).unwrap();
        format!("../{name}")
    };
    let first = patch("first.patch", "one", "first", "FIRST");
    let then = patch("then.patch", "one", "FIRST", "first again");
    let other = patch("other.patch", "two", "not there", "SECOND");
    let index = fs::read(root.join(".git/index"))?;
    let is_unchanged = || {
        assert_eq!(fs::read(root.join(".git/index")).unwrap(), index);
        assert!(!root.join(".git/index.lock").exists());
    };
    let staged = |path: &str| -> Result<String> {
        let repo = gix::open(&root)?;
        let index = repo.index_or_empty()?;
        let entry = index.entry_by_path(path.into()).ok_or("not staged")?;
        Ok(String::from_utf8(repo.find_blob(entry.id)?.data.clone())?)
    };

    // The second patch file does not apply. As in Git, the file that the first one
    // changed stays changed, and the index stays as it was.
    let fails = ["apply", "--index", &first, &other];
    client.error(&root, &fails, "patch failed: two:1");
    is_unchanged();
    assert_eq!(fs::read_to_string(root.join("one"))?, "FIRST\n");
    assert_eq!(fs::read_to_string(root.join("two"))?, "second\n");
    fs::write(root.join("one"), "first\n")?;
    // A patch file is checked against what the patch files before it leave.
    let twice = ["apply", "--cached", &first, &first];
    client.error(&root, &twice, "patch failed: one:1");
    is_unchanged();
    let missing = ["apply", "--cached", &first, "../missing.patch"];
    client.error(&root, &missing, "can't open patch '../missing.patch'");
    is_unchanged();

    client.ok(&root, &["apply", "--index", &first, &then]);
    assert_eq!(fs::read_to_string(root.join("one"))?, "first again\n");
    assert_eq!(staged("one")?, "first again\n");
    assert_eq!(client.ok(&root, &["diff"]), "");
    client.ok(&root, &["apply", "--cached", "-R", &then, &first]);
    assert_eq!(staged("one")?, "first\n");
    assert_eq!(fs::read_to_string(root.join("one"))?, "first again\n");
    assert!(!root.join(".git/index.lock").exists());
    Ok(())
}

#[test]
fn a_file_that_is_created_and_deleted_again_does_not_replace_what_is_there() -> Result {
    let (client, root) = repository();
    fs::write(root.join("a"), "one\ntwo\n")?;
    client.ok(&root, &["add", "-A"]);
    let index = fs::read(root.join(".git/index"))?;
    // The third patch deletes the file of the second one, not what is at `x` already.
    fs::write(
        client.0.join("again.patch"),
        concat!(
            "diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1,2 +1,2 @@\n one\n-two\n+TWO\n",
            "diff --git a/x b/x\nnew file mode 100644\n--- /dev/null\n+++ b/x\n@@ -0,0 +1 @@\n+x\n",
            "diff --git a/x b/x\ndeleted file mode 100644\n--- a/x\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n",
        ),
    )?;
    let is_refused = |place: &str, options: &[&str]| {
        let args = [&["apply"], options, &["../again.patch"]].concat();
        client.error(&root, &args, &format!("x: already exists in {place}"));
        assert_eq!(fs::read_to_string(root.join("a")).unwrap(), "one\ntwo\n");
    };

    // A directory with a file in it is in the way, and then a file.
    fs::create_dir(root.join("x"))?;
    fs::write(root.join("x/kept"), "mine\n")?;
    for options in [&[][..], &["--check"], &["--index"]] {
        is_refused("working directory", options);
    }
    assert_eq!(fs::read_to_string(root.join("x/kept"))?, "mine\n");
    fs::remove_dir_all(root.join("x"))?;
    fs::write(root.join("x"), "mine\n")?;
    for options in [&[][..], &["--check"], &["--index"]] {
        is_refused("working directory", options);
    }
    assert_eq!(fs::read(root.join(".git/index"))?, index);
    client.ok(&root, &["add", "x"]);
    is_refused("index", &["--cached"]);
    assert_eq!(fs::read_to_string(root.join("x"))?, "mine\n");

    // With nothing there, the two patches leave nothing there.
    client.ok(&root, &["unstage", "x"]);
    fs::remove_file(root.join("x"))?;
    client.ok(&root, &["apply", "--index", "../again.patch"]);
    assert!(!root.join("x").exists());
    assert_eq!(fs::read_to_string(root.join("a"))?, "one\nTWO\n");
    Ok(())
}
