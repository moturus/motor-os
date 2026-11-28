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
    fs::remove_file(root.join("new"))?;
    assert!(!root.join("new").exists());
    assert_eq!(client.ok(&root, &["diff", "--staged"]), "");
    assert_eq!(
        client.ok(&root, &["diff"]),
        "diff --git a/new b/new\ndeleted file mode 100644\nindex e69de29..0000000\n"
    );
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
