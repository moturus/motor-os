use std::{fs, io::BufReader, path::Path, sync::atomic::AtomicBool};

use gix::{
    ObjectId,
    bstr::ByteSlice,
    index::entry::{Flags, Mode},
};

use super::Result;

// Build the packed repository on the machine running the test. This exercises
// the same on-disk inputs on Linux and Motor without Git or an uploaded tree.
pub fn create(directory: &Path) -> Result {
    let cancellation = motor_gix::cancellation::Cancellation::new();
    motor_gix::init::run(
        directory,
        &["init.defaultBranch=main"],
        false,
        &cancellation,
    )?;
    let opened = motor_gix::repository::open(
        directory,
        &["user.name=Native Test", "user.email=native@example.test"],
        false,
    )?;
    let repo = &opened.repo;
    let mut index = gix::index::State::new(repo.object_hash());
    for (name, bytes, mode) in [
        ("editable", b"first\n".as_slice(), Mode::FILE_EXECUTABLE),
        ("caf\u{e9}", b"utf8\n".as_slice(), Mode::FILE),
        ("link", b"editable".as_slice(), Mode::SYMLINK),
    ] {
        index.dangerously_push_entry(
            Default::default(),
            repo.write_blob(bytes)?.detach(),
            Flags::empty(),
            mode,
            name.as_bytes().as_bstr(),
        );
    }
    index.sort_entries();
    let first_tree = motor_gix::tree_index::write(repo, &index, &cancellation)?;
    let first = repo
        .new_commit("initial", first_tree, std::iter::empty::<ObjectId>())?
        .id;
    index
        .entry_mut_by_path_and_stage(
            b"editable".as_bstr(),
            gix::index::entry::Stage::Unconflicted,
        )
        .unwrap()
        .id = repo.write_blob(b"other\n")?.detach();
    index.dangerously_push_entry(
        Default::default(),
        first,
        Flags::empty(),
        Mode::COMMIT,
        b"nested".as_bstr(),
    );
    index.sort_entries();
    let second_tree = motor_gix::tree_index::write(repo, &index, &cancellation)?;
    let second = repo.new_commit("second", second_tree, [first])?.id;
    fs::write(
        repo.git_dir().join("packed-refs"),
        format!("# pack-refs with: peeled fully-peeled sorted\n{second} refs/heads/main\n"),
    )?;
    motor_gix::mutation::Guard::acquire(repo)?.publish_fresh_index(index)?;
    fs::remove_file(
        repo.git_dir()
            .join(motor_gix::mutation::OPERATION_LOCK_FILE),
    )?;

    let graphs = repo.git_dir().join("objects/info/commit-graphs");
    fs::create_dir_all(&graphs)?;
    let base = graph(
        &graphs,
        first,
        first_tree,
        repo.find_commit(first)?.time()?.seconds as u64,
        None,
    )?;
    let tip = graph(
        &graphs,
        second,
        second_tree,
        repo.find_commit(second)?.time()?.seconds as u64,
        Some(base),
    )?;
    fs::write(
        graphs.join("commit-graph-chain"),
        format!("{base}\n{tip}\n"),
    )?;

    let selected = motor_gix::push_objects::select(repo, second, &[], &cancellation)?;
    let pack = motor_gix::push_pack::write(repo, &selected, directory, &cancellation)?;
    let (reader, _) = pack.into_reader()?;
    gix::odb::pack::Bundle::write_to_directory(
        &mut BufReader::new(reader),
        Some(&repo.git_dir().join("objects/pack")),
        &mut gix::progress::Discard,
        &AtomicBool::new(false),
        Some(repo.objects.clone()),
        gix::odb::pack::bundle::write::Options {
            thread_limit: Some(1),
            alloc_limit_bytes: Some(16 * 1024 * 1024),
            ..Default::default()
        },
    )?;
    // Force later reads through the pack and index instead of loose objects.
    for entry in fs::read_dir(repo.git_dir().join("objects"))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.len() == 2 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

// A split commit-graph contains a header, chunk offsets, one commit and a
// SHA-1 trailer. The second file refers to position zero in its base graph.
fn graph(
    directory: &Path,
    commit: ObjectId,
    tree: ObjectId,
    time: u64,
    base: Option<ObjectId>,
) -> Result<ObjectId> {
    let mut fan = Vec::new();
    for byte in 0..256 {
        fan.extend_from_slice(&u32::from(byte >= usize::from(commit.as_slice()[0])).to_be_bytes());
    }
    let mut record = tree.as_slice().to_vec();
    record.extend_from_slice(&(if base.is_some() { 0_u32 } else { 0x7000_0000 }).to_be_bytes());
    record.extend_from_slice(&0x7000_0000_u32.to_be_bytes());
    let generation = if base.is_some() { 2_u64 } else { 1 };
    record.extend_from_slice(&((generation << 34) | time).to_be_bytes());
    let mut chunks = vec![
        (*b"OIDF", fan),
        (*b"OIDL", commit.as_slice().to_vec()),
        (*b"CDAT", record),
    ];
    if let Some(base) = base {
        chunks.push((*b"BASE", base.as_slice().to_vec()));
    }
    let mut bytes = b"CGPH".to_vec();
    bytes.extend_from_slice(&[1, 1, chunks.len() as u8, u8::from(base.is_some())]);
    let mut offset = 8 + (chunks.len() + 1) * 12;
    for (id, data) in &chunks {
        bytes.extend_from_slice(id);
        bytes.extend_from_slice(&(offset as u64).to_be_bytes());
        offset += data.len();
    }
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&(offset as u64).to_be_bytes());
    for (_, data) in chunks {
        bytes.extend(data);
    }
    let mut hasher = gix::hash::hasher(gix::hash::Kind::Sha1);
    hasher.update(&bytes);
    let checksum = hasher.try_finalize()?;
    bytes.extend_from_slice(checksum.as_slice());
    fs::write(directory.join(format!("graph-{checksum}.graph")), bytes)?;
    Ok(checksum)
}
