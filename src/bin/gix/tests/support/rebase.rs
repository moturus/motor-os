use std::path::Path;

use gix::{
    ObjectId,
    bstr::ByteSlice,
    index::entry::{Flags, Mode},
    prelude::ObjectIdExt,
};
use motor_gix::replay::{self, Range};

use super::Result;

// Histories are written as objects only. Every commit has the same time, which is the
// hardest case for telling the commits of a branch from those of its upstream.
struct History<'a> {
    repo: &'a gix::Repository,
    cancellation: motor_gix::cancellation::Cancellation,
}

impl History<'_> {
    fn tree(&self, entries: &[(&str, &[u8])]) -> Result<ObjectId> {
        let mut state = gix::index::State::new(self.repo.object_hash());
        for (path, data) in entries {
            state.dangerously_push_entry(
                Default::default(),
                self.repo.write_blob(*data)?.detach(),
                Flags::empty(),
                Mode::FILE,
                path.as_bytes().as_bstr(),
            );
        }
        state.sort_entries();
        motor_gix::tree_index::write(self.repo, &state, &self.cancellation)
    }

    fn commit(&self, message: &str, tree: ObjectId, parents: &[ObjectId]) -> Result<ObjectId> {
        self.commit_at(1_700_000_000, message, tree, parents)
    }

    fn commit_at(
        &self,
        seconds: u32,
        message: &str,
        tree: ObjectId,
        parents: &[ObjectId],
    ) -> Result<ObjectId> {
        let time = format!("{seconds} +0000");
        let signature = |name: &'static str| gix::actor::SignatureRef {
            name: name.into(),
            email: "fixture@example.com".into(),
            time: &time,
        };
        // The author differs from the committer, so a replay that mixes them up is caught.
        let commit = self.repo.new_commit_as(
            signature("Fixture Committer"),
            signature("Fixture Author"),
            message,
            tree,
            parents.iter().copied(),
        )?;
        Ok(commit.id)
    }

    /// The message, author, committer, tree and parents of a commit.
    fn read(&self, id: ObjectId) -> Result<(String, String, String, ObjectId, Vec<ObjectId>)> {
        let commit = self.repo.find_commit(id)?;
        let decoded = commit.decode()?;
        Ok((
            decoded.message.to_string(),
            decoded.author()?.name.to_string(),
            decoded.committer()?.name.to_string(),
            decoded.tree(),
            decoded.parents().collect(),
        ))
    }
}

pub fn check_replay(output: &Path) -> Result {
    let repository = output.join("replay-repository");
    let cancellation = motor_gix::cancellation::Cancellation::new();
    motor_gix::init::run(
        &repository,
        &["init.defaultBranch=main"],
        false,
        &cancellation,
    )?;
    let identities = ["user.name=Replayer", "user.email=replayer@example.com"];
    let opened = motor_gix::repository::open(&repository, &identities, false)?;
    let repo = &opened.repo;
    let history = History {
        repo,
        cancellation: motor_gix::cancellation::Cancellation::new(),
    };
    let (tree, commit) = (
        |entries: &[(&str, &[u8])]| history.tree(entries),
        |message: &str, tree, parents: &[ObjectId]| history.commit(message, tree, parents),
    );

    // The upstream: root - base - u1 - u.
    let root = commit("root", tree(&[("r", b"r\n")])?, &[])?;
    let lines = b"1\n2\n3\n";
    let base_tree = tree(&[("a", lines), ("r", b"r\n")])?;
    let base = commit("base", base_tree, &[root])?;
    let upstream_lines = b"1\n2\n3\nU\n";
    let upstream_files: [(&str, &[u8]); 4] = [
        ("a", upstream_lines),
        ("bin", &[0, b'u']),
        ("r", b"r\n"),
        ("same", b"s\n"),
    ];
    let u1 = commit("u1", tree(&upstream_files)?, &[base])?;
    let mut files = upstream_files.to_vec();
    files.push(("c", b"c\n"));
    let upstream_tree = tree(&files)?;
    let u = commit("u", upstream_tree, &[u1])?;

    // The branch: base - l1 - l2 - l3 - m - l4, where m also merges s1, a child of root.
    let l1_tree = tree(&[("a", lines), ("d", b"d\n"), ("r", b"r\n")])?;
    let l1 = commit("l1", l1_tree, &[base])?;
    let l2_files: [(&str, &[u8]); 4] =
        [("a", lines), ("d", b"d\n"), ("r", b"r\n"), ("same", b"s\n")];
    let l2 = commit("l2 adds what u1 added", tree(&l2_files)?, &[l1])?;
    let l3 = commit("\n\nl3 is empty\n\nbody\n", tree(&l2_files)?, &[l2])?;
    let s1 = commit("s1", tree(&[("e", b"e\n"), ("r", b"r\n")])?, &[root])?;
    let mut merged = l2_files.to_vec();
    merged.push(("e", b"e\n"));
    let m = commit("m", tree(&merged)?, &[l3, s1])?;
    merged[0] = ("a", b"one\n2\n3\n");
    let l4 = commit("l4", tree(&merged)?, &[m])?;

    let todo = |range: &Range| replay::todo(repo, range, &cancellation);
    let range = Range {
        original: l4,
        onto: u,
        base,
    };
    assert_eq!(
        replay::todo(repo, &range, &cancellation)?,
        [l1, l2, l3, s1, l4],
        "the order is that of git rev-list --topo-order --reverse --no-merges"
    );
    for (original, expected) in [(base, vec![]), (u, vec![]), (l1, vec![l1])] {
        let range = Range { original, ..range };
        assert_eq!(replay::todo(repo, &range, &cancellation)?, expected);
    }
    check_todo_boundary(&history, base_tree)?;

    let replayed = replay::run(&opened, &todo(&range)?, u, &cancellation)?;
    assert!(replayed.stopped.is_none());
    assert_eq!(replayed.dropped, [l2], "u1 has the change of l2");
    let mut files = files.clone();
    files[0] = ("a", b"one\n2\n3\nU\n");
    files.extend([("d", b"d\n".as_slice()), ("e", b"e\n")]);
    let mut expected_tree = tree(&files)?;
    let mut id = replayed.tip;
    // Newest first. The empty commit l3 is kept, and its replayed form is empty too.
    for (message, undone) in [
        ("l4", Some(("a", upstream_lines.as_slice()))),
        ("s1", None),
        ("\n\nl3 is empty\n\nbody\n", None),
        ("l1", None),
    ] {
        let (actual, author, committer, tree_id, parents) = history.read(id)?;
        assert_eq!(actual, message);
        assert_eq!(author, "Fixture Author");
        assert_eq!(committer, "Replayer");
        assert_eq!(tree_id, expected_tree, "tree of replayed {message:?}");
        let [parent] = parents[..] else {
            return Err(format!("replayed {message:?} has parents {parents:?}").into());
        };
        id = parent;
        match (message, undone) {
            (_, Some(file)) => files[0] = file,
            ("s1", _) => files.retain(|(path, _)| *path != "e"),
            ("l1", _) => files.retain(|(path, _)| *path != "d"),
            _ => {}
        }
        expected_tree = tree(&files)?;
    }
    assert_eq!(id, u, "the replayed commits follow the upstream");
    assert_eq!(expected_tree, upstream_tree);

    // A conflict in the second of three commits, then the rest as `rebase --skip` runs it.
    let x1_tree = tree(&[("a", lines), ("f", b"f\n"), ("r", b"r\n")])?;
    let x1 = commit("x1", x1_tree, &[base])?;
    let mine = b"1\n2\n3\nMINE\n";
    let x2_tree = tree(&[("a", mine), ("f", b"f\n"), ("r", b"r\n")])?;
    let x2 = commit("x2 conflicts", x2_tree, &[x1])?;
    let x3_tree = tree(&[("a", mine), ("f", b"f\n"), ("g", b"g\n"), ("r", b"r\n")])?;
    let x3 = commit("x3", x3_tree, &[x2])?;
    let range = Range {
        original: x3,
        onto: u,
        base,
    };
    let replayed = replay::run(&opened, &todo(&range)?, u, &cancellation)?;
    let stopped = replayed.stopped.ok_or("the conflict did not stop")?;
    assert_eq!(stopped.commit, x2);
    assert_eq!(history.read(replayed.tip)?.0, "x1");
    let (marked_tree, conflicts) = stopped.shown.ok_or("the text conflict is not shown")?;
    assert_eq!(conflicts.len(), 1);
    let marked = repo
        .find_tree(marked_tree)?
        .lookup_entry_by_path("a")?
        .ok_or("the conflicted file is missing")?;
    assert_eq!(
        repo.find_blob(marked.object_id())?.data.as_bstr(),
        format!(
            "1\n2\n3\n<<<<<<< HEAD\nU\n=======\nMINE\n>>>>>>> {} (x2 conflicts)\n",
            x2.attach(repo).shorten_or_id()
        )
    );
    let rest = replay::run(&opened, &todo(&range)?[2..], replayed.tip, &cancellation)?;
    assert!(rest.stopped.is_none() && rest.dropped.is_empty());
    let (message, .., parents) = history.read(rest.tip)?;
    assert_eq!(
        (message.as_str(), &parents[..]),
        ("x3", &[replayed.tip][..])
    );

    // Gix cannot show a conflict in a binary file, so it reports the commit only.
    let binary: [(&str, &[u8]); 3] = [("a", lines), ("bin", &[0, b'y']), ("r", b"r\n")];
    let y1 = commit("y1", tree(&binary)?, &[base])?;
    let range = Range {
        original: y1,
        onto: u,
        base,
    };
    let replayed = replay::run(&opened, &todo(&range)?, u, &cancellation)?;
    let stopped = replayed.stopped.ok_or("the binary conflict did not stop")?;
    assert_eq!((replayed.tip, stopped.commit), (u, y1));
    assert!(stopped.shown.is_none());

    let anonymous =
        motor_gix::repository::open(&repository, &["user.name=", "user.email="], false)?;
    let error = replay::run(&anonymous, &todo(&range)?, u, &cancellation)
        .expect_err("a replay without an identity was accepted");
    assert!(error.to_string().contains("author identity"), "{error}");

    // Replaying wrote objects only: the branch is unborn and there is no index.
    let head = motor_gix::head_ref::capture(repo)?;
    assert_eq!(
        (head.reference.as_ref().map(|name| name.as_bstr()), head.id),
        (Some("refs/heads/main".into()), None)
    );
    assert!(!repo.index_path().try_exists()?);
    assert_eq!(repo.references()?.all()?.count(), 0);
    Ok(())
}

// The upstream has commits that the given base does not lead to. They must not be replayed,
// in whatever order the walk reaches them.
fn check_todo_boundary(history: &History<'_>, tree: ObjectId) -> Result {
    let commit = |seconds, message: &str, parents: &[ObjectId]| {
        history.commit_at(seconds, message, tree, parents)
    };
    // The upstream: r0 - r - x - h - u. Of the equally old x and h, the walk takes x first.
    let r0 = commit(5, "r0", &[])?;
    let r = commit(10, "r", &[r0])?;
    let x = commit(50, "x", &[r])?;
    let mut candidates = (0..64).map(|n| commit(50, &format!("h{n}"), &[x]));
    let h = candidates
        .find(|h| h.as_ref().map_or(true, |h| *h < x))
        .ok_or("no commit sorts before x")??;
    let u = commit(100, "u", &[h])?;
    let todo = |original, base| {
        let range = Range {
            original,
            onto: u,
            base,
        };
        replay::todo(history.repo, &range, &history.cancellation)
    };

    // The walk visits x as a commit of the branch and has nothing else of the branch
    // left. It must go on until h shows that x is upstream.
    let a = commit(90, "a", &[x])?;
    assert_eq!(todo(a, r)?, [a]);

    // Here x is visited before h again, and r is waiting. Then x must be visited a second
    // time, so that r turns out to be upstream as well.
    let p = commit(55, "p", &[r])?;
    let merge = commit(90, "merge", &[x, p])?;
    let b = commit(95, "b", &[merge])?;
    assert_eq!(todo(b, r0)?, [p, b]);
    Ok(())
}

fn id(digit: char) -> ObjectId {
    ObjectId::from_hex(digit.to_string().repeat(40).as_bytes()).unwrap()
}

/// The record of a rebase: how it is written, which records are refused, and what the
/// mutation guard, `status` and `branch` make of it.
pub fn check_rebase_record(output: &Path) -> Result {
    use motor_gix::{
        mutation::Guard,
        operation::{self, Kind, Original, Rebase, Record, State, Step},
    };

    let repository = output.join("rebase-record-repository");
    let cancellation = motor_gix::cancellation::Cancellation::new();
    motor_gix::init::run(
        &repository,
        &["init.defaultBranch=main"],
        false,
        &cancellation,
    )?;
    let identities = ["user.name=Replayer", "user.email=replayer@example.com"];
    let mut opened = motor_gix::repository::open(&repository, &identities, false)?;
    std::fs::write(repository.join("file"), b"content\n")?;
    motor_gix::add::run(&opened, true, &[], &cancellation)?;
    motor_gix::commit::run(&opened, "first", &cancellation)?;
    let first = opened.repo.head_id()?.detach();
    let tree = opened.repo.head_tree()?.id().detach();
    let second = opened.repo.new_commit("second", tree, [first])?.id;
    let third = opened.repo.new_commit("third", tree, [second])?.id;
    let main: gix::refs::FullName = "refs/heads/main".try_into()?;
    let path = opened
        .repo
        .git_dir()
        .join(motor_gix::mutation::OPERATION_FILE);

    // Records of the other kinds are written exactly as before.
    let merge = Record {
        state: State::Incomplete,
        kind: Kind::Merge,
        original: Original {
            reference: Some(main.clone()),
            id: Some(id('1')),
        },
        target_ref: main.clone(),
        target_commit: id('2'),
        result_tree: id('3'),
        intended_commit: None,
    };
    let guard = Guard::acquire(&opened.repo)?;
    guard.create_operation(&merge)?;
    assert_eq!(
        std::fs::read_to_string(&path)?,
        format!(
            "version=1\nstate=incomplete\nkind=merge\noriginal-ref=refs/heads/main\n\
             original-id={}\ntarget-ref=refs/heads/main\ntarget-commit={}\nresult-tree={}\n\
             intended-commit=-\n",
            id('1'),
            id('2'),
            id('3')
        )
    );
    let mut paused_merge = merge.clone();
    paused_merge.state = State::Paused;
    assert!(guard.replace_operation(&merge, &paused_merge).is_err());
    guard.remove_operation(&merge)?;

    // A rebase from its first step to a stop, through a resolution, to an abort.
    let rebase = Rebase {
        original: first,
        onto: second,
        base: first,
        next: Some(third),
        step: Some(Step::Pause),
    };
    let detached = |commit| Original {
        reference: None,
        id: Some(commit),
    };
    let start = Record {
        state: State::Incomplete,
        kind: Kind::Rebase(rebase),
        original: Original {
            reference: Some(main.clone()),
            id: Some(first),
        },
        target_ref: main.clone(),
        target_commit: second,
        result_tree: tree,
        intended_commit: None,
    };
    let stable = |state, next| Record {
        state,
        kind: Kind::Rebase(Rebase {
            next,
            step: None,
            ..rebase
        }),
        original: detached(second),
        ..start.clone()
    };
    let paused = stable(State::Paused, Some(third));
    let ready = stable(State::Ready, Some(third));
    let showing = Record {
        state: State::Incomplete,
        kind: Kind::Rebase(rebase),
        ..paused.clone()
    };
    let publishing = Record {
        state: State::Publishing,
        intended_commit: Some(third),
        ..ready.clone()
    };
    let finished = Record {
        original: detached(third),
        target_commit: third,
        ..stable(State::Paused, None)
    };
    let aborting = Record {
        state: State::Incomplete,
        kind: Kind::Rebase(Rebase {
            next: None,
            step: Some(Step::Abort),
            ..rebase
        }),
        target_commit: first,
        ..finished.clone()
    };
    guard.create_operation(&start)?;
    assert_eq!(
        std::fs::read_to_string(&path)?,
        format!(
            "version=2\nstate=incomplete\nkind=rebase\noriginal-ref=refs/heads/main\n\
             original-id={first}\ntarget-ref=refs/heads/main\ntarget-commit={second}\n\
             result-tree={tree}\nintended-commit=-\nrebase-original={first}\n\
             rebase-onto={second}\nrebase-base={first}\nrebase-next={third}\n\
             rebase-step=pause\n"
        )
    );
    let steps = [
        &start,
        &paused,
        &showing,
        &ready,
        &publishing,
        &ready,
        &publishing,
        &finished,
        &aborting,
    ];
    for pair in steps.windows(2) {
        guard.replace_operation(pair[0], pair[1])?;
        assert_eq!(operation::read(&path)?.as_ref(), Some(pair[1]));
    }

    // Records that no rebase can be in, and changes that no rebase makes.
    let with = |record: &Record, change: &dyn Fn(&mut Record, &mut Rebase)| {
        let mut record = record.clone();
        let Kind::Rebase(mut rebase) = record.kind else {
            unreachable!("a rebase record");
        };
        change(&mut record, &mut rebase);
        record.kind = Kind::Rebase(rebase);
        record
    };
    let attached = Original {
        reference: Some(main.clone()),
        id: Some(second),
    };
    for (invalid, why) in [
        (
            with(&paused, &|_, rebase| rebase.step = Some(Step::Pause)),
            "a step while paused",
        ),
        (
            with(&showing, &|_, rebase| rebase.step = None),
            "no step while incomplete",
        ),
        (
            with(&ready, &|_, rebase| rebase.next = None),
            "stopped at no commit",
        ),
        (
            with(&paused, &|record, _| record.original = attached.clone()),
            "paused on a branch",
        ),
        (
            with(&paused, &|record, _| record.original = detached(first)),
            "paused at another commit",
        ),
        (
            with(&ready, &|record, _| record.intended_commit = Some(third)),
            "a commit to publish while ready",
        ),
        (
            with(&start, &|record, _| record.original.id = Some(second)),
            "a first step from another commit",
        ),
    ] {
        assert!(
            guard.replace_operation(&aborting, &invalid).is_err(),
            "{why}"
        );
    }
    assert_eq!(operation::read(&path)?, Some(aborting.clone()));

    // The version and the kind must agree, and a rebase record has all its fields.
    let good = std::fs::read_to_string(&path)?;
    for (damaged, why) in [
        (good.replace("version=2", "version=1"), "version 1"),
        (good.replace("version=2", "version=3"), "version 3"),
        (
            good.replace("kind=rebase", "kind=merge"),
            "a merge in version 2",
        ),
        (
            good.replace("rebase-step=abort", "rebase-step=finish"),
            "step",
        ),
        (good.replace("rebase-step=abort\n", ""), "a missing field"),
        (format!("{good}rebase-more=-\n"), "a trailing field"),
        (
            good.replace(&format!("rebase-onto={second}"), "rebase-onto=-"),
            "no upstream",
        ),
    ] {
        std::fs::write(&path, damaged)?;
        assert!(operation::read(&path).is_err(), "{why}");
    }
    std::fs::write(&path, &good)?;
    guard.replace_operation(&aborting, &paused)?;
    let other_upstream = with(&paused, &|_, rebase| rebase.onto = third);
    for (to, why) in [
        (&ready, "paused to ready"),
        (&other_upstream, "another upstream"),
        (&merge, "a rebase to a merge"),
    ] {
        assert!(guard.replace_operation(&paused, to).is_err(), "{why}");
    }
    for pair in [&paused, &showing, &ready, &publishing].windows(2) {
        guard.replace_operation(pair[0], pair[1])?;
    }
    assert!(
        guard.replace_operation(&publishing, &showing).is_err(),
        "publishing to incomplete"
    );
    guard.replace_operation(&publishing, &ready)?;
    guard.replace_operation(&ready, &paused)?;
    drop(guard);

    // Only the rebase commands may go on while a rebase is stopped.
    let message = |error: Box<dyn std::error::Error + Send + Sync>| error.to_string();
    let in_progress = "a rebase is in progress; run 'gix rebase --continue'";
    for error in [
        Guard::acquire(&opened.repo).err(),
        Guard::acquire_for_ready_mutation(&opened.repo).err(),
        Guard::acquire_for_recovery(&opened.repo).err(),
    ] {
        let error = message(error.ok_or("a stopped rebase admitted another command")?);
        assert!(error.contains(in_progress), "{error}");
    }
    let (guard, record) = Guard::acquire_rebase(&opened.repo)?;
    assert_eq!(record, paused);
    guard.replace_operation(&paused, &showing)?;
    drop(guard);
    let error = message(Guard::acquire(&opened.repo).err().ok_or("admitted")?);
    assert!(
        error.contains("unfinished gix rebase incomplete"),
        "{error}"
    );
    let (guard, record) = Guard::acquire_for_recovery(&opened.repo)?;
    assert_eq!(record, showing);
    guard.replace_operation(&showing, &ready)?;
    drop(guard);
    let (guard, record) = Guard::acquire_for_ready_mutation(&opened.repo)?;
    assert_eq!(record, Some(ready.clone()));
    drop(guard);

    // HEAD leaves the branch, moves on, and the branch follows at the end.
    let attached_first = motor_gix::head_ref::capture(&opened.repo)?;
    let error = motor_gix::head_ref::detach(
        &mut opened.repo,
        &detached(first),
        second,
        b"wrong".as_bstr(),
        &cancellation,
    )
    .expect_err("HEAD was detached from a state it is not in");
    assert!(error.to_string().contains("HEAD changed"), "{error}");
    let at_second = motor_gix::head_ref::detach(
        &mut opened.repo,
        &attached_first,
        second,
        b"rebase (pick): second".as_bstr(),
        &cancellation,
    )?;
    assert_eq!(at_second, detached(second));
    let mut listed = Vec::new();
    motor_gix::branches::list(&opened.repo, Default::default(), &mut listed, &cancellation)?;
    assert_eq!(listed.as_bstr(), "* (no branch, rebasing main)\n  main\n");
    let mut status = Vec::new();
    motor_gix::status::collect(&opened, &cancellation)?.write_to(&mut status, &cancellation)?;
    assert_eq!(status.as_bstr(), "operation rebase ready\n");
    let error = motor_gix::head_ref::move_branch(
        &mut opened.repo,
        &main,
        second,
        third,
        b"wrong".as_bstr(),
        &cancellation,
    )
    .expect_err("a branch moved from a commit it is not at");
    assert!(error.to_string().contains("changed"), "{error}");
    let at_third = motor_gix::head_ref::detach(
        &mut opened.repo,
        &at_second,
        third,
        b"rebase (continue): third".as_bstr(),
        &cancellation,
    )?;
    motor_gix::head_ref::move_branch(
        &mut opened.repo,
        &main,
        first,
        third,
        b"rebase (finish): refs/heads/main onto".as_bstr(),
        &cancellation,
    )?;
    let finished_head = motor_gix::head_ref::attach(
        &mut opened.repo,
        &at_third,
        &main,
        third,
        b"rebase (finish): returning to refs/heads/main".as_bstr(),
        &cancellation,
    )?;
    assert_eq!(finished_head.reference.as_ref(), Some(&main));
    let error = motor_gix::head_ref::move_branch(
        &mut opened.repo,
        &main,
        third,
        second,
        b"wrong".as_bstr(),
        &cancellation,
    )
    .expect_err("the branch of HEAD moved");
    assert!(error.to_string().contains("HEAD is attached"), "{error}");

    let logs = opened.repo.git_dir().join("logs");
    let null = ObjectId::null(gix::hash::Kind::Sha1);
    let lines = |name: &str| -> Result<Vec<String>> {
        let log = std::fs::read_to_string(logs.join(name))?;
        let line = |line: &str| -> Option<String> {
            let (ids, message) = line.split_once('\t')?;
            let mut ids = ids.split(' ');
            Some(format!("{} {} {message}", ids.next()?, ids.next()?))
        };
        Ok(log.lines().skip(1).filter_map(line).collect())
    };
    assert_eq!(
        lines("HEAD")?,
        [
            format!("{null} {second} rebase (pick): second"),
            format!("{second} {third} rebase (continue): third"),
            format!("{third} {third} rebase (finish): returning to refs/heads/main"),
        ]
    );
    assert_eq!(
        lines("refs/heads/main")?,
        [format!(
            "{first} {third} rebase (finish): refs/heads/main onto"
        )]
    );

    let (guard, record) = Guard::acquire_rebase(&opened.repo)?;
    guard.remove_operation(&record)?;
    drop(guard);
    let error = message(
        Guard::acquire_rebase(&opened.repo)
            .err()
            .ok_or("admitted")?,
    );
    assert!(error.contains("no rebase is in progress"), "{error}");
    Ok(())
}

/// A branch `topic` with five commits. The second and the fourth conflict with the one
/// commit that `main` has more.
#[cfg(feature = "native-test-support")]
struct Conflicting {
    root: std::path::PathBuf,
    opened: motor_gix::repository::OpenedRepository,
    cancellation: motor_gix::cancellation::Cancellation,
    /// The tip of `topic` before the rebase.
    original: ObjectId,
}

#[cfg(feature = "native-test-support")]
impl Conflicting {
    fn new(output: &Path, name: &str) -> Result<Self> {
        let root = output.join(name);
        let cancellation = motor_gix::cancellation::Cancellation::new();
        motor_gix::init::run(&root, &["init.defaultBranch=main"], false, &cancellation)?;
        let identities = ["user.name=Replayer", "user.email=replayer@example.com"];
        let mut opened = motor_gix::repository::open(&root, &identities, false)?;
        let commit = |opened: &motor_gix::repository::OpenedRepository,
                      message: &str,
                      files: &[(&str, &str)]|
         -> Result {
            for (path, text) in files {
                std::fs::write(root.join(path), text)?;
            }
            motor_gix::add::run(opened, true, &[], &cancellation)?;
            motor_gix::commit::run(opened, message, &cancellation)
        };
        commit(
            &opened,
            "base",
            &[("a", "1\n2\n3\n"), ("b", "b\n"), ("keep", "k\n")],
        )?;
        opened.repo.reference(
            "refs/heads/topic",
            opened.repo.head_id()?.detach(),
            gix::refs::transaction::PreviousValue::MustNotExist,
            "fixture",
        )?;
        let theirs = [("a", "1\n2\n3\nTHEIRS\n"), ("b", "THEIRS\n"), ("up", "u\n")];
        commit(&opened, "theirs", &theirs)?;
        motor_gix::switch::run(&mut opened, "topic", &cancellation)?;
        commit(&opened, "t1", &[("t1", "t1\n")])?;
        commit(&opened, "mine", &[("a", "1\n2\n3\nMINE\n")])?;
        commit(&opened, "t3", &[("t3", "t3\n")])?;
        commit(&opened, "mine-b", &[("b", "MINE\n")])?;
        commit(&opened, "t5", &[("t5", "t5\n")])?;
        let original = opened.repo.head_id()?.detach();
        Ok(Conflicting {
            root,
            opened,
            cancellation,
            original,
        })
    }

    /// `gix pull --rebase . main`, which must stop at the commit `mine`.
    fn pull(&mut self) -> String {
        let request = motor_gix::pull::Request {
            remote: Some("."),
            branch: Some("main"),
            ff_only: false,
            rebase: true,
            no_rebase: false,
        };
        let policy = motor_gix::network::Policy::new(&[], &self.cancellation).unwrap();
        let error = motor_gix::pull::run(
            &mut self.opened,
            request,
            &policy,
            std::io::sink(),
            &self.cancellation,
        )
        .expect_err("the conflicting commit was applied");
        error.to_string()
    }

    fn status(&self) -> Result<String> {
        let mut status = Vec::new();
        motor_gix::status::collect(&self.opened, &self.cancellation)?
            .write_to(&mut status, &self.cancellation)?;
        Ok(String::from_utf8(status)?)
    }

    fn file(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(self.root.join(path)).ok()
    }

    /// `gix rebase --continue` or `--skip`: what it printed, or its error.
    fn resume(&self, skip: bool) -> std::result::Result<String, String> {
        let mut out = Vec::new();
        motor_gix::rebase::resume(&self.opened, skip, &mut out, &self.cancellation)
            .map_err(|error| error.to_string())?;
        Ok(String::from_utf8(out).unwrap())
    }

    /// Write `text` to the conflicted file `path` and stage it.
    fn resolve(&self, path: &str, text: &str) -> Result {
        std::fs::write(self.root.join(path), text)?;
        motor_gix::add::run(&self.opened, true, &[], &self.cancellation)
    }

    /// The subjects on the first-parent line of HEAD, newest first, without `base`.
    fn subjects(&self) -> Result<String> {
        let mut subjects = Vec::new();
        let mut commit = self.opened.repo.head_commit()?;
        loop {
            let parent = commit.parent_ids().next().map(gix::Id::detach);
            let Some(parent) = parent else {
                return Ok(subjects.join(" "));
            };
            subjects.push(commit.message_raw()?.to_string());
            commit = self.opened.repo.find_commit(parent)?;
        }
    }

    fn head(&self) -> Result<(Option<String>, String)> {
        let head = motor_gix::head_ref::capture(&self.opened.repo)?;
        let commit = self.opened.repo.head_commit()?.message_raw()?.to_string();
        Ok((
            head.reference.map(|name| name.as_bstr().to_string()),
            commit,
        ))
    }

    /// Require the rebase to be paused at the replayed `t1`, with the files of that commit.
    fn require_paused(&self) -> Result {
        use motor_gix::operation::State;

        let path = self.opened.repo.git_dir().join("gix-operation");
        let record = motor_gix::operation::read(&path)?.ok_or("the rebase has no record")?;
        assert_eq!(record.state, State::Paused);
        let head = motor_gix::head_ref::capture(&self.opened.repo)?;
        assert_eq!(
            (head.reference, head.id),
            (None, Some(record.target_commit))
        );
        let commit = self.opened.repo.find_commit(record.target_commit)?;
        assert_eq!(commit.message_raw()?, "t1");
        assert_eq!(self.status()?, "operation rebase paused\n");
        assert_eq!(self.file("a").as_deref(), Some("1\n2\n3\nTHEIRS\n"));
        assert_eq!(self.file("up").as_deref(), Some("u\n"));
        assert_eq!(self.file("t1").as_deref(), Some("t1\n"));
        Ok(())
    }

    /// Require the rebase to have ended with the branch at a commit named `tip`.
    fn require_finished(&self, tip: &str) -> Result {
        assert_eq!(self.head()?, (Some("refs/heads/topic".into()), tip.into()));
        assert!(!self.opened.repo.git_dir().join("gix-operation").exists());
        assert_eq!(self.status()?, "");
        Ok(())
    }

    /// Require the branch to be as it was before the rebase, with nothing left of it.
    fn require_aborted(&self) -> Result {
        let head = motor_gix::head_ref::capture(&self.opened.repo)?;
        assert_eq!(
            (head.reference.as_ref().map(|name| name.as_bstr()), head.id),
            (Some("refs/heads/topic".into()), Some(self.original))
        );
        assert!(!self.opened.repo.git_dir().join("gix-operation").exists());
        assert_eq!(self.status()?, "");
        assert_eq!(self.file("a").as_deref(), Some("1\n2\n3\nMINE\n"));
        assert_eq!(self.file("up"), None);
        assert_eq!(self.file("t1").as_deref(), Some("t1\n"));
        Ok(())
    }
}

/// Interrupt each step of a stopping rebase, then repair it with `recover` or `abort`.
#[cfg(feature = "native-test-support")]
pub fn check_rebase_recovery(output: &Path) -> Result {
    use motor_gix::test_support::{Failure, fail_once};

    let incomplete = "a step of the rebase is incomplete";

    // The stop fails while it writes files, before HEAD moves. Recovery goes forward.
    let mut fixture = Conflicting::new(output, "rebase-recovery-files")?;
    let armed = fail_once(Failure::AfterFirstInstallRemoval)?;
    let error = fixture.pull();
    drop(armed);
    assert!(error.contains(incomplete), "{error}");
    assert_eq!(fixture.opened.repo.head_id()?, fixture.original);
    assert_eq!(
        fixture.status()?.lines().next(),
        Some("operation rebase incomplete")
    );
    let recovered = motor_gix::recover::run(&fixture.opened, &fixture.cancellation)?;
    assert!(recovered.starts_with("the rebase is paused"), "{recovered}");
    fixture.require_paused()?;
    let error = motor_gix::recover::run(&fixture.opened, &fixture.cancellation)
        .expect_err("a paused rebase was recovered again");
    assert!(
        error.to_string().contains("a rebase is in progress"),
        "{error}"
    );
    motor_gix::rebase::abort(&fixture.opened, &fixture.cancellation)?;
    fixture.require_aborted()?;

    // The stop fails after HEAD has moved. Then the abort fails while it writes files.
    let mut fixture = Conflicting::new(output, "rebase-recovery-head")?;
    let armed = fail_once(Failure::BeforeRebaseStopped)?;
    let error = fixture.pull();
    drop(armed);
    assert!(error.contains(incomplete), "{error}");
    assert_ne!(fixture.opened.repo.head_id()?, fixture.original);
    assert!(
        fixture
            .file("a")
            .is_some_and(|text| text.contains("<<<<<<< HEAD"))
    );
    motor_gix::recover::run(&fixture.opened, &fixture.cancellation)?;
    fixture.require_paused()?;
    let armed = fail_once(Failure::AfterFirstInstallRemoval)?;
    let error = motor_gix::rebase::abort(&fixture.opened, &fixture.cancellation)
        .expect_err("the abort ignored the injected failure");
    drop(armed);
    assert!(error.to_string().contains(incomplete), "{error}");
    let recovered = motor_gix::recover::run(&fixture.opened, &fixture.cancellation)?;
    assert_eq!(recovered, "finished the abort of the rebase");
    fixture.require_aborted()?;

    // The abort of a stopped rebase fails before HEAD returns. A second abort finishes it.
    let mut fixture = Conflicting::new(output, "rebase-recovery-abort")?;
    let error = fixture.pull();
    assert!(
        error.contains("could not apply") && error.contains("(mine)"),
        "{error}"
    );
    assert_eq!(fixture.status()?, "operation rebase ready\nUU a\n");
    let armed = fail_once(Failure::BeforeRebaseAborted)?;
    let error = motor_gix::rebase::abort(&fixture.opened, &fixture.cancellation)
        .expect_err("the abort ignored the injected failure");
    drop(armed);
    assert!(error.to_string().contains(incomplete), "{error}");
    assert_ne!(fixture.opened.repo.head_id()?, fixture.original);
    assert_eq!(fixture.file("a").as_deref(), Some("1\n2\n3\nMINE\n"));
    motor_gix::rebase::abort(&fixture.opened, &fixture.cancellation)?;
    fixture.require_aborted()?;

    // An interrupted first step can be aborted at once, without `recover`.
    let mut fixture = Conflicting::new(output, "rebase-recovery-direct")?;
    let armed = fail_once(Failure::AfterFirstInstallRemoval)?;
    fixture.pull();
    drop(armed);
    motor_gix::rebase::abort(&fixture.opened, &fixture.cancellation)?;
    fixture.require_aborted()?;
    let error = motor_gix::rebase::abort(&fixture.opened, &fixture.cancellation)
        .expect_err("a rebase was aborted twice");
    assert!(
        error.to_string().contains("no rebase is in progress"),
        "{error}"
    );
    Ok(())
}

/// Interrupt `rebase --continue` and `--skip` at each point, then finish the rebase.
#[cfg(feature = "native-test-support")]
pub fn check_rebase_resume(output: &Path) -> Result {
    use motor_gix::test_support::{Failure, fail_once};

    let rebased = "Successfully rebased and updated refs/heads/topic.\n";
    let unpublished = "the resolution commit may not be published";

    // The resolution commit is made, but HEAD does not move to it. Then it does, but the
    // record does not follow. Each time, `--continue` goes on from where things are.
    let mut fixture = Conflicting::new(output, "rebase-resume-continue")?;
    fixture.pull();
    fixture.resolve("a", "1\n2\n3\nBOTH\n")?;
    let armed = fail_once(Failure::BeforeResolutionPublished)?;
    let error = fixture
        .resume(false)
        .expect_err("the injected failure was ignored");
    drop(armed);
    assert!(error.contains(unpublished), "{error}");
    assert_eq!(fixture.head()?, (None, "t1".into()));
    assert_eq!(fixture.status()?, "operation rebase publishing\nM  a\n");
    let error = fixture
        .resume(false)
        .expect_err("the second conflict was not found");
    assert!(
        error.contains("could not apply") && error.contains("(mine-b)"),
        "{error}"
    );
    assert_eq!(fixture.subjects()?, "t3 mine t1 theirs");
    assert_eq!(fixture.status()?, "operation rebase ready\nUU b\n");
    fixture.resolve("b", "BOTH\n")?;
    let armed = fail_once(Failure::AfterResolutionPublished)?;
    let error = fixture
        .resume(false)
        .expect_err("the injected failure was ignored");
    drop(armed);
    assert!(error.contains(unpublished), "{error}");
    assert_eq!(fixture.head()?, (None, "mine-b".into()));
    assert_eq!(fixture.resume(false)?, rebased);
    fixture.require_finished("t5")?;
    assert_eq!(fixture.subjects()?, "t5 mine-b t3 mine t1 theirs");
    assert_eq!(fixture.file("a").as_deref(), Some("1\n2\n3\nBOTH\n"));
    assert_eq!(fixture.file("b").as_deref(), Some("BOTH\n"));
    let replayed = fixture.opened.repo.head_commit()?;
    assert_eq!(replayed.committer()?.name, "Replayer");

    // Both conflicting commits are skipped. The finish is interrupted after the branch
    // has moved, and `--continue` attaches HEAD.
    let mut fixture = Conflicting::new(output, "rebase-resume-skip")?;
    fixture.pull();
    let error = fixture
        .resume(true)
        .expect_err("the second conflict was not found");
    assert!(error.contains("(mine-b)"), "{error}");
    assert_eq!(fixture.subjects()?, "t3 t1 theirs");
    assert_eq!(fixture.file("a").as_deref(), Some("1\n2\n3\nTHEIRS\n"));
    let armed = fail_once(Failure::BeforeRebaseFinished)?;
    let error = fixture
        .resume(true)
        .expect_err("the injected failure was ignored");
    drop(armed);
    assert!(
        error.contains("before HEAD returned to the branch"),
        "{error}"
    );
    assert_eq!(fixture.head()?, (None, "t5".into()));
    assert_eq!(fixture.status()?, "operation rebase paused\n");
    let error = fixture
        .resume(true)
        .expect_err("a commit was skipped at the end");
    assert!(error.contains("no commit is left to skip"), "{error}");
    assert_eq!(fixture.resume(false)?, rebased);
    fixture.require_finished("t5")?;
    assert_eq!(fixture.subjects()?, "t5 t3 t1 theirs");
    assert_eq!(fixture.file("b").as_deref(), Some("THEIRS\n"));

    // A skip is interrupted while it writes files. `recover` pauses the rebase at the
    // next conflicting commit, which `--continue` then shows.
    let mut fixture = Conflicting::new(output, "rebase-resume-recover")?;
    fixture.pull();
    let armed = fail_once(Failure::AfterFirstInstallRemoval)?;
    let error = fixture
        .resume(true)
        .expect_err("the injected failure was ignored");
    drop(armed);
    assert!(
        error.contains("a step of the rebase is incomplete"),
        "{error}"
    );
    let error = fixture
        .resume(false)
        .expect_err("an interrupted rebase went on");
    assert!(
        error.contains("a step of the rebase was interrupted"),
        "{error}"
    );
    motor_gix::recover::run(&fixture.opened, &fixture.cancellation)?;
    assert_eq!(fixture.head()?, (None, "t3".into()));
    assert_eq!(fixture.status()?, "operation rebase paused\n");
    let error = fixture
        .resume(false)
        .expect_err("the second conflict was not found");
    assert!(error.contains("(mine-b)"), "{error}");
    assert_eq!(fixture.status()?, "operation rebase ready\nUU b\n");

    // An abort also works while a resolution commit is half published.
    fixture.resolve("b", "BOTH\n")?;
    let armed = fail_once(Failure::BeforeResolutionPublished)?;
    fixture
        .resume(false)
        .expect_err("the injected failure was ignored");
    drop(armed);
    motor_gix::rebase::abort(&fixture.opened, &fixture.cancellation)?;
    fixture.require_aborted()
}
