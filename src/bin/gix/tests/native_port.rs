use std::{fs, path::PathBuf, sync::atomic::AtomicBool};

use gix::{
    bstr::ByteSlice,
    index::{File, State, entry::Mode},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() -> Result {
    let mut args = std::env::args_os().skip(1);
    let fixture = PathBuf::from(args.next().ok_or("fixture path required")?);
    let output = PathBuf::from(args.next().ok_or("output path required")?);
    fs::create_dir(&output)?;
    let worktree = output.join("worktree");
    fs::create_dir(&worktree)?;

    let repo = gix::open::Options::isolated()
        .config_overrides([
            "core.symlinks=false",
            "core.checkStat=minimal",
            "core.trustctime=false",
        ])
        .open(fixture)?
        .to_thread_local();
    let hash = gix::hash::Kind::Sha1;
    let input = File::at(repo.index_path(), hash, false, Default::default())?;
    assert_eq!(
        input.entries().len(),
        3,
        "read a real Git index with its checksum"
    );
    input.verify_entries()?;

    let packed = gix::refs::packed::Buffer::open(repo.git_dir().join("packed-refs"), 0, hash)?;
    assert_eq!(
        packed.iter()?.count(),
        1,
        "force the packed-ref large-file path"
    );
    let graph = gix::commitgraph::File::at(repo.git_dir().join("objects/info/commit-graph"))
        .map_err(|err| err.into_error())?;
    assert_eq!(graph.num_commits(), 2);
    graph.verify_checksum().map_err(|err| err.into_error())?;

    let capabilities = gix::fs::Capabilities::probe_dir(&worktree);
    assert!(
        capabilities.executable_bit,
        "native probe must observe executable bits"
    );
    let tree = repo.head_tree_id()?.detach();
    let state = State::from_tree(&tree, &repo.objects, Default::default())?;
    let mut index = File::from_state(state, output.join("written.index"));
    let objects = repo.objects.clone().into_arc()?;
    let interrupt = AtomicBool::new(false);
    let discard = gix::features::progress::Discard;

    for (round, mode) in [Mode::FILE_EXECUTABLE, Mode::FILE, Mode::FILE_EXECUTABLE]
        .into_iter()
        .enumerate()
    {
        let entry = index
            .entry_mut_by_path_and_stage(
                b"editable".as_bstr(),
                gix::index::entry::Stage::Unconflicted,
            )
            .ok_or("fixture entry missing")?;
        entry.mode = mode;
        entry.stat = Default::default();

        let mut options =
            repo.checkout_options(gix::worktree::stack::state::attributes::Source::IdMapping)?;
        options.fs = capabilities;
        options.fs.symlink = false;
        options.thread_limit = Some(1);
        options.destination_is_initially_empty = round == 0;
        options.overwrite_existing = round != 0;
        let outcome = gix::worktree::state::checkout(
            &mut index,
            &worktree,
            objects.clone(),
            &discard,
            &discard,
            &interrupt,
            options,
        )?;
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert!(outcome.collisions.is_empty(), "{:?}", outcome.collisions);
        assert_eq!(fs::read(worktree.join("editable"))?, b"other\n");
        assert_eq!(fs::read(worktree.join("caf\u{e9}"))?, b"utf8\n");
        assert_eq!(fs::read(worktree.join("link"))?, b"editable");
        assert!(fs::symlink_metadata(worktree.join("link"))?.is_file());

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(worktree.join("editable"))?;
        let metadata = gix::index::fs::Metadata::from_file(&file)?;
        assert_eq!(metadata.is_executable(), mode == Mode::FILE_EXECUTABLE);
        assert_eq!(metadata.modified(), Some(file.metadata()?.modified()?));
        #[cfg(target_os = "motor")]
        {
            use std::os::fd::AsRawFd;

            let attributes = moto_rt::fs::get_file_attr(file.as_raw_fd()).map_err(|err| {
                let code: moto_rt::ErrorCode = err.into();
                std::io::Error::from_raw_os_error(code.into())
            })?;
            let expected = moto_rt::fs::PERM_READ
                | moto_rt::fs::PERM_WRITE
                | if mode == Mode::FILE_EXECUTABLE {
                    moto_rt::fs::PERM_EXEC
                } else {
                    0
                };
            assert_eq!(
                attributes.perm, expected,
                "exact editable native permissions"
            );
        }
    }

    index.write(gix::index::write::Options {
        extensions: gix::index::write::Extensions::None,
        skip_hash: false,
    })?;
    let reopened = File::at(
        output.join("written.index"),
        hash,
        false,
        Default::default(),
    )?;
    assert_eq!(reopened.entries().len(), 3);
    println!("gix native port fixture PASS");
    Ok(())
}
