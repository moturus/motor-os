use super::Result;
use std::{fs, io::Write, path::Path};

pub fn check_push_pack(output: &Path) -> Result {
    let directory = output.join("push-pack");
    let repository = directory.join("source");
    fs::create_dir(&directory)?;
    let cancellation = motor_gix::cancellation::Cancellation::new();
    motor_gix::init::run(
        &repository,
        &["init.defaultBranch=main"],
        false,
        &cancellation,
    )?;
    let opened = motor_gix::repository::open(
        &repository,
        &["user.name=Native Test", "user.email=native@example.com"],
        false,
    )?;
    let repo = &opened.repo;
    let unchanged = repo.write_blob(b"unchanged\n")?.detach();
    let base = repo.write_blob(b"base\n")?.detach();
    let one = repo.write_blob(b"one\n")?.detach();
    let two = repo.write_blob(b"two\n")?.detach();
    let resolution = repo.write_blob(b"resolved\n")?.detach();
    let write_tree = |entries: &[(&str, gix::ObjectId)]| -> Result<gix::ObjectId> {
        Ok(repo
            .write_object(gix::objs::Tree {
                entries: entries
                    .iter()
                    .map(|(name, id)| gix::objs::tree::Entry {
                        mode: gix::objs::tree::EntryKind::Blob.into(),
                        filename: (*name).into(),
                        oid: *id,
                    })
                    .collect(),
            })?
            .detach())
    };
    let tree0 = write_tree(&[("conflict", base), ("unchanged", unchanged)])?;
    let tree1 = write_tree(&[
        ("conflict", one),
        ("side-one", one),
        ("unchanged", unchanged),
    ])?;
    let tree2 = write_tree(&[
        ("conflict", two),
        ("side-two", two),
        ("unchanged", unchanged),
    ])?;
    let merge_tree = write_tree(&[
        ("conflict", resolution),
        ("side-one", one),
        ("side-two", two),
        ("unchanged", unchanged),
    ])?;
    let c0 = repo
        .new_commit("baseline", tree0, std::iter::empty::<gix::ObjectId>())?
        .id;
    let c1 = repo.new_commit("side one", tree1, [c0])?.id;
    let c2 = repo.new_commit("side two", tree2, [c0])?.id;
    let merge = repo.new_commit("merge", merge_tree, [c1, c2])?.id;
    repo.reference(
        "refs/heads/main",
        merge,
        gix::refs::transaction::PreviousValue::MustNotExist,
        "push pack fixture",
    )?;

    use motor_gix::push_policy::Spec;
    for source in ["HEAD".to_owned(), "main".to_owned(), merge.to_string()] {
        let spec = Spec::parse(&format!("{source}:refs/heads/main"), None)?;
        assert_eq!(spec.resolve(repo, &cancellation)?, merge);
        assert!(!spec.validate_update(repo, merge, Some(c0), &cancellation)?);
    }
    // Like `git push origin main`, infer `refs/heads/main` for both sides.
    let short = Spec::parse("main", None)?;
    assert_eq!(short.destination.to_string(), "refs/heads/main");
    assert_eq!(short.resolve(repo, &cancellation)?, merge);
    assert!(!short.validate_update(repo, merge, Some(c0), &cancellation)?);
    let branch = Spec::parse("HEAD:refs/heads/main", None)?;
    assert!(branch.validate_update(repo, merge, Some(merge), &cancellation)?);
    assert!(
        branch
            .validate_update(repo, c0, Some(merge), &cancellation)
            .is_err()
    );
    let missing = gix::ObjectId::from_bytes_or_panic(&[1; 20]);
    assert!(
        branch
            .validate_update(repo, merge, Some(missing), &cancellation)
            .is_err()
    );
    let lease = format!("refs/heads/main:{c0}");
    let leased = Spec::parse("HEAD:refs/heads/main", Some(&lease))?;
    assert!(
        leased
            .validate_update(repo, merge, Some(merge), &cancellation)
            .is_err()
    );
    assert!(!leased.validate_update(repo, merge, Some(c0), &cancellation)?);
    let tag = Spec::parse(&format!("{base}:refs/tags/blob"), None)?;
    assert_eq!(tag.resolve(repo, &cancellation)?, base);
    assert!(!tag.validate_update(repo, base, None, &cancellation)?);
    assert!(
        tag.validate_update(repo, base, Some(unchanged), &cancellation)
            .is_err()
    );
    assert!(
        Spec::parse(&format!("{base}:refs/heads/main"), None)?
            .resolve(repo, &cancellation)
            .is_err()
    );
    assert!(
        Spec::parse("HEAD^:refs/heads/main", None)?
            .resolve(repo, &cancellation)
            .is_err()
    );

    let assert_ids = |selection: &motor_gix::push_objects::Selection,
                      expected: &[gix::ObjectId]| {
        let mut actual = selection.ids().to_vec();
        let mut expected = expected.to_vec();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected);
    };
    let initial = motor_gix::push_objects::select(repo, c0, &[], &cancellation)?;
    assert_ids(&initial, &[c0, tree0, base, unchanged]);
    let incremental = motor_gix::push_objects::select(repo, merge, &[c0], &cancellation)?;
    assert_ids(
        &incremental,
        &[
            c1, c2, merge, tree1, tree2, merge_tree, one, two, resolution,
        ],
    );
    assert!(!incremental.ids().contains(&unchanged));

    let emit = |selection: &motor_gix::push_objects::Selection, name: &str| -> Result {
        let pack = motor_gix::push_pack::write(repo, selection, &directory, &cancellation)?;
        assert_eq!(pack.object_count() as usize, selection.ids().len());
        let (mut reader, length) = pack.into_reader()?;
        let mut target = fs::File::create(directory.join(name))?;
        assert_eq!(std::io::copy(&mut reader, &mut target)?, length);
        target.flush()?;
        Ok(())
    };
    emit(&initial, "initial.pack")?;
    emit(&incremental, "incremental.pack")?;
    fs::write(directory.join("C0"), format!("{c0}\n"))?;
    fs::write(directory.join("M"), format!("{merge}\n"))?;
    Ok(())
}
