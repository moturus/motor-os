use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::AtomicBool,
};

use gix::{
    bstr::ByteSlice,
    index::{
        File,
        entry::{Flags, Mode, Stage},
    },
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() -> Result {
    let mut args = std::env::args_os().skip(1);
    let first = args.next().ok_or("fixture path required")?;
    if first == OsStr::new("--capture-child") {
        return capture_child(&args.next().ok_or("capture action required")?);
    }
    if first == OsStr::new("--mutation-child") {
        let repository = PathBuf::from(args.next().ok_or("mutation repository required")?);
        let expectation = args.next().ok_or("mutation expectation required")?;
        return mutation_child(&repository, &expectation);
    }
    let fixture = PathBuf::from(first);
    let output = PathBuf::from(args.next().ok_or("output path required")?);

    let url = motor_gix::https_url::HttpsUrl::parse("https://EXAMPLE.com:443/repo.git?q=1")?;
    assert_eq!(url.as_str(), "https://example.com/repo.git?q=1");
    assert_eq!(
        url.same_origin_redirect("https://example.COM:443/else?q=2")?
            .as_str(),
        "https://example.com/else?q=2"
    );
    let ipv6 = motor_gix::https_url::HttpsUrl::parse("https://[2001:0db8::1]:8443?q")?;
    assert_eq!(ipv6.as_str(), "https://[2001:db8::1]:8443/?q");
    let ipv4 = motor_gix::https_url::HttpsUrl::parse("https://127.0.0.1:444/repo")?;
    assert_eq!(ipv4.as_str(), "https://127.0.0.1:444/repo");
    for invalid in [
        "http://example.com/",
        "HTTPS://example.com/",
        "https://user@example.com/",
        "https://example.com/white space",
        "https://café.example/",
        "https://example.com/#fragment",
        "https://example.com\\@other/",
        "https://example.com:0/",
        "https://2001:db8::1/",
        "https://127.1/",
        "https://exa_mple.com/",
    ] {
        assert!(
            motor_gix::https_url::HttpsUrl::parse(invalid).is_err(),
            "{invalid}"
        );
    }
    for redirect in [
        "https://other.example/repo.git",
        "https://example.com:8443/repo.git",
    ] {
        assert!(url.same_origin_redirect(redirect).is_err(), "{redirect}");
    }

    fs::create_dir(&output)?;
    check_init(&output)?;
    #[cfg(target_os = "motor")]
    check_loose_ref_limit(&output)?;
    check_capture(&output)?;
    check_mutation(&output)?;
    let worktree = output.join("worktree");
    fs::create_dir(&worktree)?;

    check_refs(&fixture)?;
    let opened = motor_gix::repository::open(&fixture, &[], false)?;
    let repo = &opened.repo;
    let hash = gix::hash::Kind::Sha1;
    let input = File::at(repo.index_path(), hash, false, Default::default())?;
    assert_eq!(
        input.entries().len(),
        4,
        "read a real Git index with its checksum"
    );
    input.verify_entries()?;

    let packed = gix::refs::packed::Buffer::open(repo.git_dir().join("packed-refs"), 0, hash)?;
    assert_eq!(
        packed.iter()?.count(),
        1,
        "force the packed-ref large-file path"
    );
    let graph = gix::commitgraph::Graph::from_info_dir(&repo.git_dir().join("objects/info"))
        .map_err(|err| err.into_error())?;
    assert_eq!(graph.num_commits(), 2);
    graph
        .verify_integrity(|_| Ok::<_, std::io::Error>(()))
        .map_err(|err| err.into_error())?;

    check_pack_validation(repo, &output)?;

    let capabilities = gix::fs::Capabilities::probe_dir(&worktree);
    assert!(
        capabilities.executable_bit,
        "native probe must observe executable bits"
    );
    for path in ["editable", "caf\u{e9}", "link"] {
        let path = fixture.join(path);
        if path.try_exists()? {
            fs::remove_file(path)?;
        }
    }
    let state =
        motor_gix::checkout::initial(&opened, &motor_gix::cancellation::Cancellation::new())?;
    assert_eq!(fs::read(fixture.join("editable"))?, b"other\n");
    assert_eq!(fs::read(fixture.join("caf\u{e9}"))?, b"utf8\n");
    assert_eq!(fs::read(fixture.join("link"))?, b"editable");
    assert!(fs::symlink_metadata(fixture.join("link"))?.is_file());
    let cancellation = motor_gix::cancellation::Cancellation::new();
    let mut converter = motor_gix::stage_blob::Converter::new(repo, &state)?;
    let editable = converter
        .stage(
            b"editable".as_bstr(),
            Some(Mode::FILE_EXECUTABLE),
            &cancellation,
        )?
        .ok_or("checked-out editable file is missing")?;
    assert_eq!(editable.mode, Mode::FILE_EXECUTABLE);
    assert_eq!(editable.stat.size, 6);
    assert_eq!(repo.find_blob(editable.id)?.data, b"other\n");
    let link = converter
        .stage(b"link".as_bstr(), Some(Mode::SYMLINK), &cancellation)?
        .ok_or("checked-out link text is missing")?;
    assert_eq!(link.mode, Mode::SYMLINK);
    assert_eq!(link.stat.size, 8);
    assert_eq!(repo.find_blob(link.id)?.data, b"editable");
    check_add(&output, &fixture.join("editable"), repo.head_id()?.detach())?;
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
    assert_eq!(reopened.entries().len(), 4);

    fs::write(
        fixture.join(".git/info/attributes"),
        "editable filter=blocked\n",
    )?;
    let command_sentinel = output.join("external-command-ran");
    let command = format!("touch {}", command_sentinel.display());
    let overrides = [
        format!("filter.blocked.clean={command}"),
        "filter.blocked.required=true".into(),
        format!("diff.external={command}"),
        format!("diff.blocked.command={command}"),
        format!("diff.blocked.textconv={command}"),
        format!("merge.blocked.driver={command}"),
        "merge.text.name=".into(),
        "merge.default=blocked".into(),
        format!("core.askPass={command}"),
        format!("core.sshCommand={command}"),
        format!("gitoxide.ssh.commandWithoutShellFallback={command}"),
        format!("credential.helper={command}"),
    ];
    let overrides = overrides.iter().map(String::as_str).collect::<Vec<_>>();
    let opened = motor_gix::repository::open(&fixture, &overrides, false)?;
    let cancellation = motor_gix::cancellation::Cancellation::new();
    cancellation.cancel();
    let cancelled = motor_gix::status::collect(&opened, &cancellation)
        .err()
        .ok_or("cancelled status succeeded")?;
    assert!(motor_gix::cancellation::was_cancelled(cancelled.as_ref()));
    let cancelled_again = motor_gix::status::collect(&opened, &cancellation)
        .err()
        .ok_or("repeated cancelled status succeeded")?;
    assert!(motor_gix::cancellation::was_cancelled(
        cancelled_again.as_ref()
    ));
    assert!(
        opened
            .command_policy
            .external_filters
            .contains(b"blocked".as_bstr())
    );
    assert!(
        opened
            .command_policy
            .required_filters
            .contains(b"blocked".as_bstr())
    );
    assert!(
        opened
            .command_policy
            .external_merge_drivers
            .contains(b"blocked".as_bstr())
    );
    assert_eq!(
        opened
            .command_policy
            .default_merge_driver
            .as_ref()
            .map(|name| name.as_bstr()),
        Some(b"blocked".as_bstr())
    );
    let sanitized = opened.repo.config_snapshot();
    for key in [
        "core.askPass",
        "core.sshCommand",
        "gitoxide.ssh.commandWithoutShellFallback",
        "credential.helper",
        "diff.external",
        "merge.default",
    ] {
        assert!(
            sanitized.raw_value(key).is_err(),
            "{key} remains configured"
        );
    }

    let filter_options = gix::filter::Pipeline::options(&opened.repo)?;
    let filter = filter_options
        .drivers
        .iter()
        .find(|driver| driver.name == "blocked")
        .ok_or("sanitized filter evidence missing")?;
    assert!(filter.required);
    assert!(filter.clean.is_none() && filter.smudge.is_none() && filter.process.is_none());

    let diff = opened.repo.diff_resource_cache_for_tree_diff()?;
    let diff_driver = diff
        .filter
        .drivers()
        .iter()
        .find(|driver| driver.name == "blocked")
        .ok_or("sanitized diff driver missing")?;
    assert!(diff_driver.command.is_none() && diff_driver.binary_to_text_command.is_none());
    assert!(
        !opened
            .command_policy
            .external_merge_drivers
            .contains(b"text".as_bstr())
    );
    let merge = opened.repo.merge_resource_cache(Default::default())?;
    assert!(merge.drivers().is_empty());
    assert!(opened.repo.ssh_connect_options()?.command.is_none());

    let (mut pipeline, index) = opened.repo.filter_pipeline(None)?;
    let mut converted =
        pipeline.convert_to_git(b"unchanged\n".as_slice(), "editable".as_ref(), &index)?;
    let mut actual = Vec::new();
    converted.read_to_end(&mut actual)?;
    assert_eq!(actual, b"unchanged\n");
    assert!(
        !command_sentinel.exists(),
        "sanitized library consumer ran an external command"
    );

    println!("gix native port fixture PASS");
    Ok(())
}

#[cfg(target_os = "motor")]
fn check_loose_ref_limit(output: &Path) -> Result {
    use gix::refs::file::{find, iter::loose_then_packed};

    let directory = output.join("loose-ref-limit");
    fs::create_dir_all(directory.join("refs/heads"))?;
    let store = gix::refs::file::Store::at(directory.clone(), gix::hash::Kind::Sha1);
    let name = "refs/heads/bounded";
    let id = gix::hash::ObjectId::null(gix::hash::Kind::Sha1);
    let mut file = fs::File::create(directory.join(name))?;
    writeln!(file, "{id}")?;
    file.set_len(8 * 1024 * 1024)?;

    assert_eq!(store.find(name)?.target.into_id(), id);
    let platform = store.iter()?;
    let mut refs = platform.all()?;
    assert_eq!(
        refs.next().ok_or("bounded ref missing")??.target.into_id(),
        id
    );
    assert!(refs.next().is_none());

    let tag_name = "refs/tags/bounded";
    fs::create_dir_all(directory.join("refs/tags"))?;
    writeln!(fs::File::create(directory.join(tag_name))?, "{id}")?;
    for (prefix, expected) in [("refs/heads/", name), ("refs/tags/", tag_name)] {
        let mut refs = platform.prefixed(prefix.as_bytes().as_bstr().try_into()?)?;
        assert_eq!(
            refs.next().ok_or("prefixed ref missing")??.name.as_bstr(),
            expected
        );
        assert!(refs.next().is_none());
    }

    file.set_len(8 * 1024 * 1024 + 1)?;
    let lookup = store.try_find(name).expect_err("lookup must enforce 8 MiB");
    assert!(matches!(
        lookup,
        find::Error::ReadFileContents { source, .. }
            if source.kind() == std::io::ErrorKind::InvalidData
                && source.to_string() == "bounded input exceeds the byte limit"
    ));
    let listing = platform
        .all()?
        .next()
        .ok_or("oversized ref missing from listing")?
        .expect_err("listing must enforce 8 MiB");
    assert!(matches!(
        listing,
        loose_then_packed::Error::ReadFileContents { source, .. }
            if source.kind() == std::io::ErrorKind::InvalidData
                && source.to_string() == "bounded input exceeds the byte limit"
    ));
    drop(file);
    fs::remove_dir_all(directory)?;
    Ok(())
}

fn check_init(output: &Path) -> Result {
    let cancellation = motor_gix::cancellation::Cancellation::new();

    let default = output.join("init-default");
    motor_gix::init::run(&default, &["init.defaultBranch=main"], false, &cancellation)?;
    assert_eq!(
        fs::read(default.join(".git/HEAD"))?,
        b"ref: refs/heads/main\n"
    );
    let repo = gix::open(&default)?;
    assert_eq!(repo.object_hash(), gix::hash::Kind::Sha1);
    assert_eq!(repo.workdir(), Some(default.as_path()));

    let existing = output.join("init-existing");
    fs::create_dir(&existing)?;
    fs::write(existing.join("sentinel"), b"preserve\n")?;
    motor_gix::init::run(
        &existing,
        &["init.defaultBranch=topic"],
        false,
        &cancellation,
    )?;
    assert_eq!(fs::read(existing.join("sentinel"))?, b"preserve\n");
    assert_eq!(
        fs::read(existing.join(".git/HEAD"))?,
        b"ref: refs/heads/topic\n"
    );

    let head_before = fs::read(existing.join(".git/HEAD"))?;
    let config_before = fs::read(existing.join(".git/config"))?;
    assert!(
        motor_gix::init::run(&existing, &[], false, &cancellation).is_err(),
        "reinitialization must be refused"
    );
    assert_eq!(fs::read(existing.join(".git/HEAD"))?, head_before);
    assert_eq!(fs::read(existing.join(".git/config"))?, config_before);
    assert_eq!(fs::read(existing.join("sentinel"))?, b"preserve\n");

    let invalid = output.join("init-invalid");
    let error = motor_gix::init::run(&invalid, &["init.defaultBranch=HEAD"], false, &cancellation)
        .err()
        .ok_or("an invalid default branch was accepted")?;
    assert!(error.to_string().contains("invalid init.defaultBranch"));
    assert!(!invalid.try_exists()?);

    let cancelled = output.join("init-cancelled");
    let cancellation = motor_gix::cancellation::Cancellation::new();
    cancellation.cancel();
    let error = motor_gix::init::run(&cancelled, &[], false, &cancellation)
        .err()
        .ok_or("cancelled init succeeded")?;
    assert!(motor_gix::cancellation::was_cancelled(error.as_ref()));
    assert!(!cancelled.try_exists()?);
    Ok(())
}

fn check_refs(repository: &Path) -> Result {
    use motor_gix::refs::Kind;

    let cancellation = motor_gix::cancellation::Cancellation::new();
    let mut opened = motor_gix::repository::open(repository, &[], false)?;
    let operation_lock = opened
        .repo
        .git_dir()
        .join(motor_gix::mutation::OPERATION_LOCK_FILE);
    let index_path = opened.repo.index_path();
    let index_before = fs::read(&index_path)?;
    let earlier = opened.repo.rev_parse_single(b"HEAD^".as_bstr())?.detach();
    let head = opened.repo.head_id()?.detach();

    let mut branches = Vec::new();
    motor_gix::refs::list(&opened.repo, Kind::Branch, &mut branches, &cancellation)?;
    assert_eq!(branches, b"main\n");
    let mut tags = Vec::new();
    motor_gix::refs::list(&opened.repo, Kind::Tag, &mut tags, &cancellation)?;
    assert!(tags.is_empty());
    assert!(
        !operation_lock.try_exists()?,
        "listing references created the operation lock"
    );

    for invalid in ["HEAD", "-leading"] {
        assert!(
            motor_gix::refs::create(&mut opened, Kind::Branch, invalid, None, &cancellation)
                .is_err(),
            "accepted invalid branch name {invalid}"
        );
    }

    motor_gix::refs::create(
        &mut opened,
        Kind::Branch,
        "earlier",
        Some("HEAD^"),
        &cancellation,
    )?;
    motor_gix::refs::create(&mut opened, Kind::Tag, "at-head", None, &cancellation)?;
    assert_eq!(
        opened.repo.find_reference("refs/heads/earlier")?.id(),
        earlier
    );
    assert_eq!(opened.repo.find_reference("refs/tags/at-head")?.id(), head);

    branches.clear();
    motor_gix::refs::list(&opened.repo, Kind::Branch, &mut branches, &cancellation)?;
    assert_eq!(branches, b"earlier\nmain\n");
    tags.clear();
    motor_gix::refs::list(&opened.repo, Kind::Tag, &mut tags, &cancellation)?;
    assert_eq!(tags, b"at-head\n");

    assert!(
        motor_gix::refs::create(
            &mut opened,
            Kind::Branch,
            "earlier",
            Some("HEAD"),
            &cancellation,
        )
        .is_err(),
        "duplicate branch creation succeeded"
    );
    assert_eq!(
        opened.repo.find_reference("refs/heads/earlier")?.id(),
        earlier,
        "duplicate creation changed the existing target"
    );
    assert!(
        motor_gix::refs::create(
            &mut opened,
            Kind::Branch,
            "tree-target",
            Some("HEAD^{tree}"),
            &cancellation,
        )
        .is_err(),
        "a branch accepted a non-commit target"
    );
    assert!(
        opened
            .repo
            .try_find_reference("refs/heads/tree-target")?
            .is_none()
    );
    assert_eq!(fs::read(index_path)?, index_before);
    assert!(!opened.repo.git_dir().join("index.lock").try_exists()?);
    Ok(())
}

fn check_add(output: &Path, executable_source: &Path, gitlink_id: gix::ObjectId) -> Result {
    let repository = output.join("add-repository");
    let cancellation = motor_gix::cancellation::Cancellation::new();
    motor_gix::init::run(&repository, &[], false, &cancellation)?;
    let opened = motor_gix::repository::open(&repository, &[], false)?;
    let repo = &opened.repo;

    for (path, data) in [
        ("modified", b"old\n".as_slice()),
        ("deleted", b"delete\n"),
        ("ignored-tracked", b"old ignored\n"),
        ("file-parent", b"old parent\n"),
        ("directory/old", b"old child\n"),
        ("link-preserved", b"old-target"),
    ] {
        let path = repository.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, data)?;
    }
    fs::copy(executable_source, repository.join("executable"))?;
    let executable = OpenOptions::new()
        .read(true)
        .open(repository.join("executable"))?;
    #[cfg(target_os = "motor")]
    {
        use std::os::fd::AsRawFd;

        // Motor copies RWX files as RX; this fixture needs an editable executable.
        moto_rt::fs::set_file_perm(
            executable.as_raw_fd(),
            moto_rt::fs::PERM_READ | moto_rt::fs::PERM_WRITE | moto_rt::fs::PERM_EXEC,
        )
        .map_err(|error| format!("cannot make executable fixture writable: {error:?}"))?;
    }
    assert!(gix::index::fs::Metadata::from_file(&executable)?.is_executable());

    motor_gix::add::run(&opened, true, &[], &cancellation)?;
    let conflict_ids = [
        repo.write_blob(b"base\n")?.detach(),
        repo.write_blob(b"ours\n")?.detach(),
        repo.write_blob(b"theirs\n")?.detach(),
    ];
    let mut guard = motor_gix::mutation::Guard::acquire(repo)?;
    guard.publish_edited_index(|index| {
        index
            .entry_mut_by_path_and_stage(b"link-preserved".as_bstr(), Stage::Unconflicted)
            .ok_or("staged link seed missing")?
            .mode = Mode::SYMLINK;
        for (stage, id) in [Stage::Base, Stage::Ours, Stage::Theirs]
            .into_iter()
            .zip(conflict_ids)
        {
            index.dangerously_push_entry(
                Default::default(),
                id,
                Flags::from_stage(stage),
                Mode::FILE,
                b"conflict".as_bstr(),
            );
        }
        for path in ["gitlink", "missing-gitlink", "blocked-parent/nested"] {
            index.dangerously_push_entry(
                Default::default(),
                gitlink_id,
                Flags::empty(),
                Mode::COMMIT,
                path.as_bytes().as_bstr(),
            );
        }
        Ok(())
    })?;
    drop(guard);

    fs::write(repository.join("modified"), b"new\n")?;
    fs::remove_file(repository.join("deleted"))?;
    fs::write(repository.join("ignored-tracked"), b"new ignored\n")?;
    fs::write(repository.join("added"), b"added\n")?;
    fs::write(repository.join("conflict"), b"resolved\n")?;
    fs::write(repository.join("link-preserved"), b"new-target")?;
    fs::write(repository.join("executable"), b"new executable\n")?;
    fs::write(
        repository.join(".gitignore"),
        b"ignored-new\nignored-tracked\n",
    )?;
    fs::write(repository.join("ignored-new"), b"ignored\n")?;

    fs::remove_file(repository.join("file-parent"))?;
    fs::create_dir(repository.join("file-parent"))?;
    fs::write(repository.join("file-parent/child"), b"child\n")?;
    fs::remove_file(repository.join("directory/old"))?;
    fs::remove_dir(repository.join("directory"))?;
    fs::write(repository.join("directory"), b"now a file\n")?;

    fs::create_dir(repository.join("gitlink"))?;
    fs::write(
        repository.join("gitlink/untracked-child"),
        b"must not stage\n",
    )?;
    fs::write(repository.join("blocked-parent"), b"replacement\n")?;

    motor_gix::add::run(
        &opened,
        false,
        &["file-parent/child".into(), "directory/old".into()],
        &cancellation,
    )?;
    let partial = repo.open_index()?;
    for absent in ["file-parent", "directory/old", "directory"] {
        assert!(partial.entry_range(absent.as_bytes().as_bstr()).is_none());
    }
    assert!(
        partial
            .entry_range(b"file-parent/child".as_bstr())
            .is_some()
    );
    expect_add_rejected(
        &opened,
        &[".".into(), "ignored-new".into()],
        "explicit path 'ignored-new' is ignored",
    )?;

    expect_add_rejected(
        &opened,
        &["ignored-new".into()],
        "explicit path 'ignored-new' is ignored",
    )?;
    let oversized = fs::File::create(repository.join("oversized"))?;
    oversized.set_len(16 * 1024 * 1024 + 1)?;
    drop(oversized);
    expect_add_rejected(
        &opened,
        &["oversized".into()],
        "cannot stage 'oversized': the worktree file exceeds the 16 MiB limit",
    )?;
    fs::remove_file(repository.join("oversized"))?;
    expect_add_rejected(
        &opened,
        &["blocked-parent".into()],
        "cannot stage 'blocked-parent': an indexed descendant is a gitlink",
    )?;
    fs::remove_file(repository.join("blocked-parent"))?;
    fs::create_dir(repository.join("blocked-parent"))?;

    fs::write(
        repository.join(".git/info/attributes"),
        b"modified filter=blocked\n",
    )?;
    let filtered = motor_gix::repository::open(
        &repository,
        &[
            "filter.blocked.clean=must-not-run",
            "filter.blocked.required=true",
        ],
        false,
    )?;
    expect_add_rejected(
        &filtered,
        &["modified".into()],
        "path 'modified' uses unsupported filter 'blocked'",
    )?;
    drop(filtered);
    fs::remove_file(repository.join(".git/info/attributes"))?;

    motor_gix::add::run(&opened, false, &[".".into()], &cancellation)?;
    let index = File::at(
        repo.index_path(),
        repo.object_hash(),
        false,
        Default::default(),
    )?;
    assert_eq!(index.entries().len(), 12);
    for absent in [
        "deleted",
        "ignored-new",
        "file-parent",
        "directory/old",
        "gitlink/untracked-child",
    ] {
        assert!(
            index.entry_range(absent.as_bytes().as_bstr()).is_none(),
            "{absent}"
        );
    }
    for (path, mode, data) in [
        ("modified", Mode::FILE, b"new\n".as_slice()),
        ("added", Mode::FILE, b"added\n"),
        ("ignored-tracked", Mode::FILE, b"new ignored\n"),
        ("conflict", Mode::FILE, b"resolved\n"),
        ("file-parent/child", Mode::FILE, b"child\n"),
        ("directory", Mode::FILE, b"now a file\n"),
        ("link-preserved", Mode::SYMLINK, b"new-target"),
        ("executable", Mode::FILE_EXECUTABLE, b"new executable\n"),
    ] {
        assert_index_blob(repo, &index, path, mode, data)?;
    }
    for path in ["gitlink", "missing-gitlink", "blocked-parent/nested"] {
        let entry = index
            .entry_by_path(path.as_bytes().as_bstr())
            .ok_or("preserved gitlink missing")?;
        assert_eq!((entry.mode, entry.id), (Mode::COMMIT, gitlink_id), "{path}");
    }
    assert!(index.entry_by_path(b".gitignore".as_bstr()).is_some());
    assert!(!repo.git_dir().join("index.lock").exists());
    Ok(())
}

fn expect_add_rejected(
    opened: &motor_gix::repository::OpenedRepository,
    paths: &[String],
    expected: &str,
) -> Result {
    let index_path = opened.repo.index_path();
    let before = fs::read(&index_path)?;
    let error = motor_gix::add::run(
        opened,
        false,
        paths,
        &motor_gix::cancellation::Cancellation::new(),
    )
    .expect_err("add unexpectedly succeeded");
    assert!(error.to_string().contains(expected), "{error}");
    assert_eq!(
        fs::read(&index_path)?,
        before,
        "rejected add changed the index"
    );
    assert!(!opened.repo.git_dir().join("index.lock").exists());
    Ok(())
}

fn assert_index_blob(
    repo: &gix::Repository,
    index: &gix::index::State,
    path: &str,
    mode: Mode,
    data: &[u8],
) -> Result {
    let entry = index
        .entry_by_path_and_stage(path.as_bytes().as_bstr(), Stage::Unconflicted)
        .ok_or("expected staged entry missing")?;
    assert_eq!(entry.mode, mode, "{path}");
    assert_eq!(repo.find_blob(entry.id)?.data, data, "{path}");
    assert_eq!(
        index.entry_range(path.as_bytes().as_bstr()).unwrap().len(),
        1
    );
    Ok(())
}

fn check_mutation(output: &Path) -> Result {
    let repository = output.join("mutation-repository");
    drop(gix::init(&repository)?);
    let alternate = output.join("mutation-alternate");
    fs::create_dir_all(alternate.join("pack"))?;
    fs::create_dir_all(repository.join(".git/objects/info"))?;
    fs::write(
        repository.join(".git/objects/info/alternates"),
        format!("{}\n", alternate.canonicalize()?.display()),
    )?;
    let opened = motor_gix::repository::open(&repository, &[], false)?;
    let git_dir = opened.repo.git_dir();

    let mut guard = motor_gix::mutation::Guard::acquire(&opened.repo)?;
    assert!(guard.index().entries().is_empty());
    run_mutation_child(&repository, "blocked")?;
    guard.publish_fresh_index(gix::index::State::new(gix::hash::Kind::Sha1))?;
    run_mutation_child(&repository, "blocked")?;
    drop(guard);
    run_mutation_child(&repository, "acquire")?;
    let lock = fs::metadata(git_dir.join(motor_gix::mutation::OPERATION_LOCK_FILE))?;
    assert!(lock.is_file() && lock.len() == 0);
    assert!(!git_dir.join("index.lock").exists());

    let mut guard = motor_gix::mutation::Guard::acquire(&opened.repo)?;
    let index_backup = git_dir.join("index.backup");
    fs::rename(opened.repo.index_path(), &index_backup)?;
    fs::create_dir(opened.repo.index_path())?;
    let obstruction = opened.repo.index_path().join("keep");
    fs::write(&obstruction, b"preserved")?;
    let publication_error = guard
        .publish_fresh_index(gix::index::State::new(gix::hash::Kind::Sha1))
        .expect_err("a nonempty directory must obstruct index publication");
    assert_eq!(fs::read(&obstruction)?, b"preserved");
    assert!(!git_dir.join("index.lock").exists());
    run_mutation_child(&repository, "blocked")?;
    drop(publication_error);
    fs::remove_file(obstruction)?;
    fs::remove_dir(opened.repo.index_path())?;
    fs::rename(index_backup, opened.repo.index_path())?;
    drop(guard);

    fs::write(git_dir.join("index.lock"), b"foreign")?;
    assert!(motor_gix::mutation::Guard::acquire(&opened.repo).is_err());
    assert_eq!(fs::read(git_dir.join("index.lock"))?, b"foreign");
    fs::remove_file(git_dir.join("index.lock"))?;

    for (name, expected) in [
        (motor_gix::mutation::OPERATION_FILE, "unfinished gix state"),
        ("MERGE_HEAD", "unsupported operation state"),
    ] {
        let marker = git_dir.join(name);
        fs::write(&marker, [])?;
        expect_guard_rejected(&opened.repo, expected)?;
        fs::remove_file(marker)?;
    }
    let promisor = alternate.join("pack/fixture.promisor");
    fs::write(&promisor, [])?;
    expect_guard_rejected(&opened.repo, "promisor packs")?;
    fs::remove_file(promisor)?;
    fs::write(
        git_dir.join("shallow"),
        b"0000000000000000000000000000000000000000\n",
    )?;
    expect_guard_rejected(&opened.repo, "shallow repositories")?;
    fs::remove_file(git_dir.join("shallow"))?;

    check_edited_index_publication(&opened)?;

    let mut state = gix::index::State::new(gix::hash::Kind::Sha1);
    state.dangerously_push_entry(
        Default::default(),
        gix::ObjectId::null(gix::hash::Kind::Sha1),
        gix::index::entry::Flags::EXTENDED | gix::index::entry::Flags::INTENT_TO_ADD,
        Mode::FILE,
        b"intent".as_bstr(),
    );
    let mut index = File::from_state(state, opened.repo.index_path());
    index.write(gix::index::write::Options {
        extensions: gix::index::write::Extensions::None,
        skip_hash: false,
    })?;
    expect_guard_rejected(&opened.repo, "intent-to-add")
}

fn check_edited_index_publication(opened: &motor_gix::repository::OpenedRepository) -> Result {
    let repo = &opened.repo;
    let worktree = repo.workdir().ok_or("mutation worktree missing")?;
    let retained_path = worktree.join("portable-retained");
    #[cfg(not(target_os = "motor"))]
    let controlled = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
    #[cfg(not(target_os = "motor"))]
    write_at(&retained_path, b"old\n", controlled)?;
    #[cfg(target_os = "motor")]
    fs::write(&retained_path, b"old\n")?;
    let retained_id = repo.write_blob(b"old\n")?.detach();

    let mut state = gix::index::State::new(gix::hash::Kind::Sha1);
    state.dangerously_push_entry(
        index_stat(&retained_path)?,
        retained_id,
        gix::index::entry::Flags::empty(),
        Mode::FILE,
        b"portable-retained".as_bstr(),
    );
    let mut index = File::from_state(state, repo.index_path());
    index.write(gix::index::write::Options {
        extensions: gix::index::write::Extensions::None,
        skip_hash: false,
    })?;
    #[cfg(not(target_os = "motor"))]
    {
        OpenOptions::new()
            .write(true)
            .open(repo.index_path())?
            .set_times(fs::FileTimes::new().set_modified(controlled))?;
        // Exact same-size, same-second worktree edit with unchanged cached stat.
        write_at(&retained_path, b"new\n", controlled)?;
    }

    let added_path = worktree.join("portable-added");
    fs::write(&added_path, b"added\n")?;
    let added_id = repo.write_blob(b"added\n")?.detach();
    let added_stat = index_stat(&added_path)?;
    let mut guard = motor_gix::mutation::Guard::acquire(repo)?;
    let original_retained = guard
        .index()
        .entry_by_path(b"portable-retained".as_bstr())
        .ok_or("original retained entry missing")?;
    let (retained_stage, retained_flags) = (original_retained.stage(), original_retained.flags);
    #[cfg(not(target_os = "motor"))]
    assert_eq!(guard.index().timestamp().unix_seconds(), 1_700_000_000);
    let checksum = guard.publish_edited_index(|index| {
        index.dangerously_push_entry(
            added_stat,
            added_id,
            gix::index::entry::Flags::empty(),
            Mode::FILE,
            b"portable-added".as_bstr(),
        );
        Ok(())
    })?;
    assert!(!repo.git_dir().join("index.lock").exists());
    run_mutation_child(worktree, "blocked")?;

    let reopened = File::at(
        repo.index_path(),
        repo.object_hash(),
        false,
        Default::default(),
    )?;
    assert_eq!(reopened.checksum(), Some(checksum));
    assert_eq!(reopened.entries().len(), 2);
    assert_eq!(
        reopened.entries()[0].path(&reopened),
        b"portable-added".as_bstr()
    );
    assert_eq!(
        reopened.entries()[1].path(&reopened),
        b"portable-retained".as_bstr()
    );
    let retained = reopened
        .entry_by_path(b"portable-retained".as_bstr())
        .ok_or("retained entry missing")?;
    assert_eq!((retained.id, retained.mode), (retained_id, Mode::FILE));
    assert_eq!(
        (retained.stage(), retained.flags),
        (retained_stage, retained_flags)
    );
    let added = reopened
        .entry_by_path(b"portable-added".as_bstr())
        .ok_or("added entry missing")?;
    assert_eq!((added.id, added.mode), (added_id, Mode::FILE));

    #[cfg(not(target_os = "motor"))]
    {
        assert!(reopened.timestamp().unix_seconds() > 1_700_000_000);
        assert_eq!(
            retained.stat.size, 0,
            "racy retained entry was not invalidated"
        );
        let reopened_repo = motor_gix::repository::open(worktree, &[], false)?;
        let report = motor_gix::status::collect(
            &reopened_repo,
            &motor_gix::cancellation::Cancellation::new(),
        )?;
        let mut output = Vec::new();
        report.write_to(&mut output, &motor_gix::cancellation::Cancellation::new())?;
        assert_eq!(output, b"A  portable-added\nAM portable-retained\n");
    }
    drop(guard);
    run_mutation_child(worktree, "acquire")
}

#[cfg(not(target_os = "motor"))]
fn write_at(path: &Path, contents: &[u8], modified: std::time::SystemTime) -> Result {
    fs::write(path, contents)?;
    OpenOptions::new()
        .write(true)
        .open(path)?
        .set_times(fs::FileTimes::new().set_modified(modified))?;
    Ok(())
}

fn index_stat(path: &Path) -> Result<gix::index::entry::Stat> {
    let file = OpenOptions::new().read(true).open(path)?;
    let metadata = gix::index::fs::Metadata::from_file(&file)?;
    Ok(gix::index::entry::Stat::from_fs(&metadata)?)
}

fn run_mutation_child(repository: &Path, expectation: &str) -> Result {
    let status = Command::new(std::env::current_exe()?)
        .args([
            OsStr::new("--mutation-child"),
            repository.as_os_str(),
            OsStr::new(expectation),
        ])
        .status()?;
    if !status.success() {
        return Err(format!("mutation child failed for {expectation}: {status}").into());
    }
    Ok(())
}

fn mutation_child(repository: &Path, expectation: &OsStr) -> Result {
    let opened = motor_gix::repository::open(repository, &[], false)?;
    let result = motor_gix::mutation::Guard::acquire(&opened.repo);
    match expectation.to_str() {
        Some("acquire") if result.is_ok() => Ok(()),
        Some("blocked")
            if result.as_ref().is_err_and(|error| {
                error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
            }) =>
        {
            Ok(())
        }
        _ => {
            let result = result
                .err()
                .map_or_else(|| "guard acquired".to_owned(), |error| error.to_string());
            Err(format!("unexpected mutation result for {expectation:?}: {result}").into())
        }
    }
}

fn expect_guard_rejected(repo: &gix::Repository, expected: &str) -> Result {
    let error = motor_gix::mutation::Guard::acquire(repo)
        .err()
        .ok_or_else(|| format!("mutation guard accepted {expected}"))?;
    assert!(error.to_string().contains(expected), "{error}");
    Ok(())
}

fn check_pack_validation(repo: &gix::Repository, output: &std::path::Path) -> Result {
    use gix::odb::pack::{self, data::Version};

    let roundtrip = output.join("pack-roundtrip");
    fs::create_dir(&roundtrip)?;
    let mut packs = 0;
    for entry in fs::read_dir(repo.objects.store_ref().path().join("pack"))? {
        let path = entry?.path();
        if path.extension() != Some(OsStr::new("pack")) {
            continue;
        }
        packs += 1;
        let source = pack::data::File::at(&path, gix::hash::Kind::Sha1)?;
        let outcome = pack::Bundle::write_to_directory(
            &mut std::io::BufReader::new(fs::File::open(&path)?),
            Some(&roundtrip),
            &mut gix::progress::Discard,
            &AtomicBool::new(false),
            Some(repo.objects.clone()),
            pack::bundle::write::Options {
                thread_limit: Some(1),
                alloc_limit_bytes: Some(16 * 1024 * 1024),
                ..Default::default()
            },
        )?;
        assert_eq!(outcome.index.num_objects, source.num_objects());
        assert!(outcome.index.num_objects > 0);
    }
    assert_eq!(packs, 1, "fixture has one real pack to rewrite and index");

    let directory = output.join("pack-validation");
    fs::create_dir(&directory)?;
    for (version, corrupt_checksum, accepted) in [
        (Version::V3, false, false),
        (Version::V2, true, false),
        (Version::V2, false, true),
    ] {
        let mut data = pack::data::header::encode(version, 0).to_vec();
        let mut hasher = gix::hash::hasher(gix::hash::Kind::Sha1);
        hasher.update(&data);
        let mut checksum = hasher.try_finalize()?;
        if corrupt_checksum {
            checksum.as_mut_slice()[0] ^= 1;
        }
        data.extend_from_slice(checksum.as_slice());
        let result = pack::Bundle::write_to_directory(
            &mut data.as_slice(),
            Some(&directory),
            &mut gix::progress::Discard,
            &AtomicBool::new(false),
            Some(repo.objects.clone()),
            pack::bundle::write::Options {
                thread_limit: Some(1),
                ..Default::default()
            },
        );
        assert_eq!(
            result.is_ok(),
            accepted,
            "{version:?}, corrupt={corrupt_checksum}: {result:?}"
        );
        if accepted {
            assert_eq!(result?.index.num_objects, 0);
        }
        assert!(
            fs::read_dir(&directory)?.next().is_none(),
            "pack writer left temporary files"
        );
    }
    check_thin_pack(repo, output)?;
    Ok(())
}

fn check_thin_pack(repo: &gix::Repository, output: &Path) -> Result {
    use gix::odb::pack;

    let hash = gix::hash::Kind::Sha1;
    let a = repo.write_blob(b"A")?.detach();
    let b = repo.write_blob(b"B")?.detach();
    let mut data = pack::data::header::encode(pack::data::Version::V2, 2).to_vec();
    // C refers to B, which arrives as a delta from A. Both A and B are also local.
    for (base_id, result) in [(b, b'C'), (a, b'B')] {
        let delta = [1, 1, 1, result];
        pack::data::entry::Header::RefDelta { base_id }.write_to(delta.len() as u64, &mut data)?;
        let mut compressed = gix::zlib::stream::deflate::Write::new(Vec::new(), Default::default());
        compressed.write_all(&delta)?;
        compressed.flush()?;
        data.extend(compressed.into_inner());
    }
    let entries_end = data.len();
    let mut hasher = gix::hash::hasher(hash);
    hasher.update(&data);
    data.extend_from_slice(hasher.try_finalize()?.as_slice());

    let directory = output.join("pack-thin");
    fs::create_dir(&directory)?;
    let outcome = pack::Bundle::write_to_directory(
        &mut data.as_slice(),
        Some(&directory),
        &mut gix::progress::Discard,
        &AtomicBool::new(false),
        Some(repo.objects.clone()),
        pack::bundle::write::Options {
            thread_limit: Some(1),
            alloc_limit_bytes: Some(16 * 1024 * 1024),
            ..Default::default()
        },
    )?;
    assert_eq!(
        outcome.index.num_objects, 3,
        "append A once; B is already incoming"
    );
    let completed = fs::read(
        outcome
            .data_path
            .as_ref()
            .ok_or("thin pack was not written")?,
    )?;
    assert_eq!(&completed[12..entries_end], &data[12..entries_end]);
    let bundle = outcome
        .to_bundle()
        .ok_or("thin pack index was not written")??;
    let mut buffer = Vec::new();
    for expected in [b"A", b"B", b"C"] {
        let id = gix::objs::compute_hash(hash, gix::objs::Kind::Blob, expected)?;
        let object = bundle
            .find(
                &id,
                &mut buffer,
                &mut gix::zlib::Inflate::default(),
                &mut pack::cache::Never,
            )?
            .ok_or("completed thin pack is missing an object")?
            .0;
        assert_eq!(object.kind, gix::objs::Kind::Blob);
        assert_eq!(object.data, expected);
    }
    Ok(())
}

fn capture_child(action: &OsStr) -> Result {
    match action.to_str().ok_or("capture action is not UTF-8")? {
        "echo" => {
            let mut body = Vec::new();
            std::io::stdin().read_to_end(&mut body)?;
            std::io::stdout().write_all(&body)?;
            std::io::stderr().write_all(b"child diagnostic\n")?;
        }
        "stdout-overflow" => {
            std::io::stdout().write_all(b"overflow")?;
            std::io::stdout().flush()?;
            loop {
                std::thread::park();
            }
        }
        "stderr-overflow" => std::io::stderr().write_all(&vec![b'x'; 65 * 1024])?,
        "exit130" => std::process::exit(130),
        _ => return Err("unknown capture action".into()),
    }
    Ok(())
}

fn check_capture(output: &Path) -> Result {
    let executable = std::env::current_exe()?;
    let input_path = output.join("capture-input");
    fs::write(&input_path, b"request body")?;
    let mut input = fs::File::open(input_path)?;
    input.seek(SeekFrom::End(0))?;
    let response = capture_file(&output.join("capture-echo"))?;
    let mut command = Command::new(&executable);
    command.args(["--capture-child", "echo"]);
    let cancellation = motor_gix::cancellation::Cancellation::new();
    let mut captured =
        motor_gix::curl_capture::capture(command, response, Some(input), 12, &cancellation)?;
    let mut body = Vec::new();
    captured.response.read_to_end(&mut body)?;
    assert!(captured.status.success());
    assert_eq!(captured.body_size, 12);
    assert_eq!(body, b"request body");
    assert_eq!(captured.stderr, b"child diagnostic\n");

    for (action, body_limit, expected) in [
        ("stdout-overflow", 4, "response exceeded"),
        ("stderr-overflow", 64, "stderr exceeded"),
        ("exit130", 64, "operation cancelled"),
    ] {
        let mut command = Command::new(&executable);
        command.args(["--capture-child", action]);
        let cancellation = motor_gix::cancellation::Cancellation::new();
        let error = motor_gix::curl_capture::capture(
            command,
            capture_file(&output.join(format!("capture-{action}")))?,
            None,
            body_limit,
            &cancellation,
        )
        .err()
        .ok_or("capture case succeeded unexpectedly")?;
        assert!(error.to_string().contains(expected), "{action}: {error}");
        if action == "exit130" {
            assert!(motor_gix::cancellation::was_cancelled(error.as_ref()));
            assert!(cancellation.check().is_err(), "cancellation was not sticky");
        }
    }
    Ok(())
}

fn capture_file(path: &Path) -> std::io::Result<fs::File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}
