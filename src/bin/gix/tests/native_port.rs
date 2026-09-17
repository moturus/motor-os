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
    check_head_ref(&output)?;
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
    check_diff_input(&output)?;
    check_diff_render()?;
    check_diff_policy(&output)?;
    check_diff_run(&output)?;
    check_restore(&output)?;
    check_executable_attributes(&output)?;
    check_unstage(&output)?;
    check_commit(&output)?;
    check_transition_delta(&output)?;
    check_switch(&output)?;
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

fn check_diff_input(output: &Path) -> Result {
    use motor_gix::diff_input::{Loaded, Loader, Source};

    let repository = output.join("add-repository");
    let attributes = repository.join(".git/info/attributes");
    assert!(!attributes.try_exists()?);
    let modified_before = fs::read(repository.join("modified"))?;
    let link_before = fs::read(repository.join("link-preserved"))?;
    fs::write(&attributes, b"modified text\nlink-preserved text\n")?;
    fs::write(repository.join("modified"), b"new\r\n")?;
    fs::write(repository.join("link-preserved"), b"new\r\ntarget")?;

    let opened = motor_gix::repository::open(&repository, &[], false)?;
    let repo = &opened.repo;
    let index = repo.open_index()?;
    let cancellation = motor_gix::cancellation::Cancellation::new();
    let index_before = fs::read(repo.index_path())?;

    let entry = |path: &str| {
        index
            .entry_by_path(path.as_bytes().as_bstr())
            .map(|entry| (entry.id, entry.mode))
            .ok_or("diff input fixture entry is missing")
    };
    let (modified_id, modified_mode) = entry("modified")?;
    let (link_id, link_mode) = entry("link-preserved")?;
    let (gitlink_id, gitlink_mode) = entry("gitlink")?;
    let (missing_gitlink_id, missing_gitlink_mode) = entry("missing-gitlink")?;
    let mut loader = Loader::new(&opened, &index);

    let pair = loader.load_pair(
        b"gitlink".as_bstr(),
        Source::Object {
            id: gitlink_id,
            mode: gitlink_mode,
        },
        Source::Worktree {
            index_id: gitlink_id,
            index_mode: gitlink_mode,
        },
        &cancellation,
    )?;
    assert_eq!(pair.old, Loaded::Gitlink { id: gitlink_id });
    assert_eq!(pair.new, Loaded::Gitlink { id: gitlink_id });

    let pair = loader.load_pair(
        b"missing-gitlink".as_bstr(),
        Source::Worktree {
            index_id: missing_gitlink_id,
            index_mode: missing_gitlink_mode,
        },
        Source::Missing,
        &cancellation,
    )?;
    assert_eq!(
        pair.old,
        Loaded::Gitlink {
            id: missing_gitlink_id,
        }
    );
    assert_eq!(pair.new, Loaded::Missing);

    let pair = loader.load_pair(
        b"modified".as_bstr(),
        Source::Object {
            id: modified_id,
            mode: modified_mode,
        },
        Source::Worktree {
            index_id: modified_id,
            index_mode: modified_mode,
        },
        &cancellation,
    )?;
    assert_eq!(
        pair,
        motor_gix::diff_input::Pair {
            old: Loaded::Blob {
                mode: Mode::FILE,
                bytes: b"new\n".to_vec(),
            },
            new: Loaded::Blob {
                mode: Mode::FILE,
                bytes: b"new\n".to_vec(),
            },
        }
    );

    let pair = loader.load_pair(
        b"link-preserved".as_bstr(),
        Source::Object {
            id: link_id,
            mode: link_mode,
        },
        Source::Worktree {
            index_id: link_id,
            index_mode: link_mode,
        },
        &cancellation,
    )?;
    assert_eq!(
        pair.new,
        Loaded::Blob {
            mode: Mode::SYMLINK,
            bytes: b"new\r\ntarget".to_vec(),
        }
    );

    fs::write(repository.join("modified"), modified_before)?;
    fs::write(repository.join("link-preserved"), link_before)?;
    fs::remove_file(attributes)?;
    assert_eq!(fs::read(repo.index_path())?, index_before);
    assert!(!repo.git_dir().join("index.lock").try_exists()?);
    Ok(())
}

fn check_diff_render() -> Result {
    use gix::diff::blob::Algorithm;
    use motor_gix::diff_render::{MAX_TEXT_LINES, prepare_text};

    let before = b"zero\none\ntwo\nthree\nold";
    let after = b"zero\none\ntwo\nthree\nnew";
    let expected = b"--- a/sample\n+++ b/sample\n@@ -2,4 +2,4 @@\n one\n two\n three\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n";
    for algorithm in [Algorithm::Myers, Algorithm::Histogram] {
        let cancellation = motor_gix::cancellation::Cancellation::new();
        let mut out = Vec::new();
        prepare_text(b"sample".as_bstr(), before, after, algorithm, &cancellation)?.write_to(
            (b"a/sample", b"b/sample"),
            &cancellation,
            &mut out,
        )?;
        assert_eq!(out, expected, "{algorithm:?}");
    }

    let mut boundary = vec![b'\n'; MAX_TEXT_LINES as usize];
    let cancellation = motor_gix::cancellation::Cancellation::new();
    let prepared = prepare_text(
        b"boundary".as_bstr(),
        &boundary,
        &boundary,
        Algorithm::Histogram,
        &cancellation,
    )?;
    assert!(prepared.is_empty());
    let mut out = Vec::new();
    prepared.write_to((b"a/boundary", b"b/boundary"), &cancellation, &mut out)?;
    assert!(out.is_empty());

    boundary.push(b'\n');
    let error = prepare_text(
        b"odd\npath".as_bstr(),
        b"",
        &boundary,
        Algorithm::Myers,
        &motor_gix::cancellation::Cancellation::new(),
    )
    .err()
    .expect("one line over the text limit was accepted");
    assert!(
        error
            .to_string()
            .contains("odd\\npath': after text exceeds the 262144-line limit"),
        "{error}"
    );

    let error = prepare_text(
        b"sample".as_bstr(),
        before,
        after,
        Algorithm::MyersMinimal,
        &motor_gix::cancellation::Cancellation::new(),
    )
    .err()
    .expect("minimal diff was accepted");
    assert!(
        error.to_string().contains("minimal diff algorithm"),
        "{error}"
    );

    let cancellation = motor_gix::cancellation::Cancellation::new();
    cancellation.cancel();
    let error = prepare_text(
        b"sample".as_bstr(),
        before,
        after,
        Algorithm::Myers,
        &cancellation,
    )
    .err()
    .expect("cancelled text diff was accepted");
    assert!(motor_gix::cancellation::was_cancelled(error.as_ref()));
    Ok(())
}

fn check_diff_run(output: &Path) -> Result {
    use motor_gix::diff_render::MAX_TEXT_LINES;

    let repository = output.join("add-repository");
    let opened = motor_gix::repository::open(&repository, &[], false)?;
    let cancellation = motor_gix::cancellation::Cancellation::new();
    let invoke =
        |opened: &motor_gix::repository::OpenedRepository, staged: bool, paths: &[String]| {
            let mut out = Vec::new();
            let result = motor_gix::diff::run(opened, staged, paths, &cancellation, &mut out);
            (result, out)
        };
    let index_path = opened.repo.index_path();
    let index_before = fs::read(&index_path)?;
    let modified_path = repository.join("modified");
    let modified_before = fs::read(&modified_path)?;
    let selected = ["modified".to_owned()];

    let (result, out) = invoke(&opened, true, &selected);
    result?;
    let staged = String::from_utf8(out)?;
    assert!(staged.contains("--- /dev/null\n+++ b/modified\n") && staged.contains("+new\n"));

    let (result, out) = invoke(&opened, false, &selected);
    result?;
    assert!(out.is_empty());
    assert_eq!(fs::read(&index_path)?, index_before);
    assert_eq!(fs::read(&modified_path)?, modified_before);

    fs::write(&modified_path, b"worktree\n")?;
    let (result, out) = invoke(&opened, false, &selected);
    result?;
    let worktree = String::from_utf8(out)?;
    assert!(
        worktree.contains("--- a/modified\n+++ b/modified\n")
            && worktree.contains("-new\n+worktree\n")
    );
    assert_eq!(fs::read(&index_path)?, index_before);
    assert_eq!(fs::read(&modified_path)?, b"worktree\n");

    let (result, out) = invoke(&opened, false, &["absent".into()]);
    let error = result.expect_err("an unmatched literal path was accepted");
    assert!(
        error.to_string().contains("did not match a tracked path"),
        "{error}"
    );
    assert!(out.is_empty());

    let attributes = opened.repo.git_dir().join("info/attributes");
    fs::write(&attributes, b"modified filter=blocked\n")?;
    let filtered = motor_gix::repository::open(
        &repository,
        &[
            "filter.blocked.clean=must-not-run",
            "filter.blocked.required=true",
        ],
        false,
    )?;
    let (result, out) = invoke(&filtered, false, &selected);
    let error = result.expect_err("a required filter was accepted");
    assert!(
        error.to_string().contains("unsupported filter 'blocked'"),
        "{error}"
    );
    assert!(out.is_empty());
    drop(filtered);
    fs::remove_file(&attributes)?;

    let minimal = motor_gix::repository::open(&repository, &["diff.algorithm=minimal"], false)?;
    let (result, out) = invoke(&minimal, false, &selected);
    let error = result.expect_err("Minimal text diff was accepted");
    assert!(
        error.to_string().contains("minimal diff algorithm"),
        "{error}"
    );
    assert!(out.is_empty(), "Minimal wrote a file preamble");
    drop(minimal);
    assert_eq!(fs::read(&index_path)?, index_before);
    assert_eq!(fs::read(&modified_path)?, b"worktree\n");

    fs::write(&modified_path, vec![b'\n'; MAX_TEXT_LINES as usize + 1])?;
    let (result, out) = invoke(&opened, false, &selected);
    let error = result.expect_err("the text line limit was not enforced");
    assert!(error.to_string().contains("262144-line limit"), "{error}");
    assert!(out.is_empty(), "the line-limit error wrote a file preamble");
    fs::write(&modified_path, b"worktree\n")?;
    assert_eq!(fs::read(&index_path)?, index_before);

    {
        let mut guard = motor_gix::mutation::Guard::acquire(&opened.repo)?;
        guard.publish_edited_index(|index| {
            index
                .entry_mut_by_path_and_stage(b"modified".as_bstr(), Stage::Unconflicted)
                .ok_or("modified fixture entry is missing")?
                .flags = Flags::from_stage(Stage::Ours);
            Ok(())
        })?;
    }
    let conflicted_index = fs::read(&index_path)?;
    let conflicted = motor_gix::repository::open(&repository, &[], false)?;
    let (result, out) = invoke(&conflicted, false, &["added".into()]);
    result?;
    assert!(
        out.is_empty(),
        "an unselected conflict blocked an unchanged path"
    );
    let (result, out) = invoke(&conflicted, false, &selected);
    let error = result.expect_err("a selected conflict was accepted");
    assert!(
        error.to_string().contains("index entry is conflicted"),
        "{error}"
    );
    assert!(out.is_empty(), "conflict preflight wrote output");
    assert_eq!(fs::read(&index_path)?, conflicted_index);
    assert_eq!(fs::read(&modified_path)?, b"worktree\n");
    drop(conflicted);

    fs::write(&index_path, &index_before)?;
    fs::write(&modified_path, &modified_before)?;
    assert!(!opened.repo.git_dir().join("index.lock").try_exists()?);
    Ok(())
}

fn check_diff_policy(output: &Path) -> Result {
    use gix::diff::blob::Algorithm;
    use motor_gix::{
        diff::render_pair,
        diff_input::{Loaded, Pair},
        diff_policy::{BinaryMode, PathPolicy, Resolver},
    };

    let repository = output.join("add-repository");
    let attributes = repository.join(".git/info/attributes");
    assert!(!attributes.try_exists()?);
    fs::write(
        &attributes,
        b"modified diff\nadded -diff\nignored-tracked diff=named\nexecutable diff=minimal\ndeleted diff=unknown\n",
    )?;
    let opened = motor_gix::repository::open(
        &repository,
        &[
            "diff.algorithm=histogram",
            "diff.named.binary=false",
            "diff.named.algorithm=myers",
            "diff.minimal.binary=false",
            "diff.minimal.algorithm=minimal",
        ],
        false,
    )?;
    let index_path = opened.repo.index_path();
    let index_before = fs::read(&index_path)?;
    let index = opened.repo.open_index()?;
    let cancellation = motor_gix::cancellation::Cancellation::new();
    let mut resolver = Resolver::new(&opened, &index)?;
    let resolve = |resolver: &mut Resolver<'_>, path: &str| {
        resolver.resolve(path.as_bytes().as_bstr(), Mode::FILE, &cancellation)
    };

    assert_eq!(
        resolve(&mut resolver, "unmentioned")?,
        PathPolicy {
            algorithm: Algorithm::Histogram,
            binary: BinaryMode::Auto,
        }
    );
    assert_eq!(resolve(&mut resolver, "modified")?.binary, BinaryMode::Text);
    assert_eq!(resolve(&mut resolver, "added")?.binary, BinaryMode::Binary);
    assert_eq!(
        resolve(&mut resolver, "ignored-tracked")?,
        PathPolicy {
            algorithm: Algorithm::Myers,
            binary: BinaryMode::Text,
        }
    );
    assert_eq!(
        resolve(&mut resolver, "executable")?,
        PathPolicy {
            algorithm: Algorithm::MyersMinimal,
            binary: BinaryMode::Text,
        }
    );
    assert_eq!(
        resolve(&mut resolver, "deleted")?,
        PathPolicy {
            algorithm: Algorithm::Histogram,
            binary: BinaryMode::Auto,
        }
    );
    assert!(BinaryMode::Auto.is_binary(b"text", b"binary\0data"));
    assert!(!BinaryMode::Auto.is_binary(b"text", b"more text"));
    assert!(!BinaryMode::Text.is_binary(b"\0", b"\0"));
    assert!(BinaryMode::Binary.is_binary(b"", b""));
    let render = |path: &str, pair: Pair, resolver: &mut Resolver<'_>| -> Result<Vec<u8>> {
        let mut out = Vec::new();
        render_pair(
            path.as_bytes().as_bstr(),
            pair,
            resolver,
            &cancellation,
            &mut out,
        )?;
        Ok(out)
    };
    assert_eq!(
        render(
            "executable",
            Pair {
                old: Loaded::Blob {
                    mode: Mode::FILE,
                    bytes: b"same\n".to_vec(),
                },
                new: Loaded::Blob {
                    mode: Mode::FILE_EXECUTABLE,
                    bytes: b"same\n".to_vec(),
                },
            },
            &mut resolver,
        )?,
        b"diff --git a/executable b/executable\nold mode 100644\nnew mode 100755\n"
    );
    assert_eq!(
        render(
            "executable",
            Pair {
                old: Loaded::Blob {
                    mode: Mode::SYMLINK,
                    bytes: b"old\n".to_vec(),
                },
                new: Loaded::Blob {
                    mode: Mode::FILE,
                    bytes: b"new\n".to_vec(),
                },
            },
            &mut resolver,
        )?,
        b"diff --git a/executable b/executable\nold mode 120000\nnew mode 100644\n--- a/executable\n+++ b/executable\n@@ -1,1 +1,1 @@\n-old\n+new\n"
    );
    assert_eq!(
        render(
            "added",
            Pair {
                old: Loaded::Missing,
                new: Loaded::Blob {
                    mode: Mode::FILE,
                    bytes: b"binary\0data".to_vec(),
                },
            },
            &mut resolver,
        )?,
        b"diff --git a/added b/added\nnew file mode 100644\nBinary files /dev/null and b/added differ\n"
    );

    let first = gix::ObjectId::from_hex(b"1111111111111111111111111111111111111111")?;
    let second = gix::ObjectId::from_hex(b"2222222222222222222222222222222222222222")?;
    let mut gitlinks = Vec::new();
    for (path, pair) in [
        (
            "changed-submodule",
            Pair {
                old: Loaded::Gitlink { id: first },
                new: Loaded::Gitlink { id: second },
            },
        ),
        (
            "new-submodule",
            Pair {
                old: Loaded::Missing,
                new: Loaded::Gitlink { id: first },
            },
        ),
        (
            "replaced-submodule",
            Pair {
                old: Loaded::Gitlink { id: first },
                new: Loaded::Blob {
                    mode: Mode::FILE,
                    bytes: b"ordinary\n".to_vec(),
                },
            },
        ),
    ] {
        render_pair(
            path.as_bytes().as_bstr(),
            pair,
            &mut resolver,
            &cancellation,
            &mut gitlinks,
        )?;
    }
    assert_eq!(
        String::from_utf8(gitlinks)?,
        concat!(
            "diff --git a/changed-submodule b/changed-submodule\n",
            "Gitlinks a/changed-submodule (1111111111111111111111111111111111111111) and b/changed-submodule (2222222222222222222222222222222222222222) differ\n",
            "diff --git a/new-submodule b/new-submodule\n",
            "new file mode 160000\n",
            "Gitlinks /dev/null (absent) and b/new-submodule (1111111111111111111111111111111111111111) differ\n",
            "diff --git a/replaced-submodule b/replaced-submodule\n",
            "old mode 160000\n",
            "new mode 100644\n",
            "Gitlinks a/replaced-submodule (1111111111111111111111111111111111111111) and b/replaced-submodule (non-gitlink) differ\n",
        )
    );

    drop(resolver);
    drop(index);
    drop(opened);
    fs::remove_file(attributes)?;
    assert_eq!(fs::read(index_path)?, index_before);
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

fn check_executable_attributes(output: &Path) -> Result {
    let repository = output.join("executable-attributes-repository");
    let cancellation = motor_gix::cancellation::Cancellation::new();
    motor_gix::init::run(&repository, &[], false, &cancellation)?;
    fs::write(
        repository.join(".gitattributes"),
        b"payload filter=blocked\n",
    )?;
    fs::write(repository.join("payload"), b"must not be checked out\n")?;
    let overrides = ["user.name=Native Test", "user.email=native@example.com"];
    let opened = motor_gix::repository::open(&repository, &overrides, false)?;
    motor_gix::add::run(&opened, true, &[], &cancellation)?;
    let mut guard = motor_gix::mutation::Guard::acquire(&opened.repo)?;
    guard.publish_edited_index(|index| {
        index
            .entry_mut_by_path_and_stage(b".gitattributes".as_bstr(), Stage::Unconflicted)
            .ok_or("attribute fixture entry is missing")?
            .mode = Mode::FILE_EXECUTABLE;
        Ok(())
    })?;
    drop(guard);
    motor_gix::commit::run(&opened, "executable attributes", &cancellation)?;
    let tree = opened.repo.head_tree()?;
    let attributes = tree
        .lookup_entry_by_path(".gitattributes")?
        .ok_or("committed attribute fixture is missing")?;
    assert_eq!(
        attributes.mode().kind(),
        gix::objs::tree::EntryKind::BlobExecutable
    );

    fs::remove_file(repository.join(".gitattributes"))?;
    fs::remove_file(repository.join("payload"))?;
    let filtered =
        motor_gix::repository::open(&repository, &["filter.blocked.required=true"], false)?;
    let guard = motor_gix::mutation::Guard::acquire(&filtered.repo)?;
    let index_before = fs::read(filtered.repo.index_path())?;
    let error = motor_gix::checkout::initial(&filtered, &cancellation)
        .expect_err("checkout accepted an executable required-filter attribute file");
    assert!(
        error
            .to_string()
            .contains("path 'payload' uses unsupported filter 'blocked'"),
        "{error}"
    );
    assert!(!repository.join(".gitattributes").try_exists()?);
    assert!(!repository.join("payload").try_exists()?);
    assert_eq!(fs::read(filtered.repo.index_path())?, index_before);
    assert!(filtered.repo.git_dir().join("index.lock").try_exists()?);
    drop(guard);
    assert!(!filtered.repo.git_dir().join("index.lock").try_exists()?);
    Ok(())
}

fn check_unstage(output: &Path) -> Result {
    let repository = output.join("unstage-repository");
    let cancellation = motor_gix::cancellation::Cancellation::new();
    motor_gix::init::run(
        &repository,
        &["init.defaultBranch=main"],
        false,
        &cancellation,
    )?;
    fs::create_dir(repository.join("dir"))?;
    fs::write(repository.join("dir/tracked"), b"baseline\n")?;
    fs::write(repository.join("retained"), b"retained\n")?;
    let overrides = ["user.name=Native Test", "user.email=native@example.com"];
    let opened = motor_gix::repository::open(&repository, &overrides, false)?;
    motor_gix::add::run(&opened, true, &[], &cancellation)?;

    let mut guard = motor_gix::mutation::Guard::acquire(&opened.repo)?;
    guard.publish_edited_index(|index| {
        let entry = index
            .entry_mut_by_path_and_stage(
                b"retained".as_bstr(),
                gix::index::entry::Stage::Unconflicted,
            )
            .ok_or("retained fixture entry is missing")?;
        // Seed a non-racy cache; initial staging may have cleared its size.
        entry.stat.size = fs::metadata(repository.join("retained"))?
            .len()
            .try_into()?;
        entry.stat.mtime = gix::index::entry::stat::Time { secs: 1, nsecs: 0 };
        Ok(())
    })?;
    drop(guard);
    let before_unborn = opened.repo.open_index()?;
    let retained = before_unborn
        .entry_by_path(b"retained".as_bstr())
        .ok_or("retained fixture entry is missing")?;
    assert_ne!(retained.stat.size, 0, "retained cache setup lost its size");
    let retained = (retained.stat, retained.id, retained.flags, retained.mode);
    motor_gix::unstage::run(&opened, &["dir".into()], &cancellation)?;
    let index = opened.repo.open_index()?;
    assert!(index.entry_range(b"dir/tracked".as_bstr()).is_none());
    let after = index
        .entry_by_path(b"retained".as_bstr())
        .ok_or("retained fixture entry is missing")?;
    assert_eq!(
        (after.stat, after.id, after.flags, after.mode),
        retained,
        "unstaging an unborn path changed an unselected stat cache"
    );
    assert_eq!(fs::read(repository.join("dir/tracked"))?, b"baseline\n");

    motor_gix::add::run(&opened, false, &["dir".into()], &cancellation)?;
    motor_gix::commit::run(&opened, "baseline", &cancellation)?;
    let baseline = opened
        .repo
        .open_index()?
        .entry_by_path(b"dir/tracked".as_bstr())
        .ok_or("baseline entry is missing")?
        .id;

    fs::remove_file(repository.join("dir/tracked"))?;
    fs::remove_dir(repository.join("dir"))?;
    fs::write(repository.join("dir"), b"replacement\n")?;
    motor_gix::add::run(&opened, false, &["dir".into()], &cancellation)?;
    let index_before_rejection = fs::read(opened.repo.index_path())?;
    let error = motor_gix::unstage::run(&opened, &["dir/tracked".into()], &cancellation)
        .expect_err("an unselected file ancestor must obstruct a HEAD descendant");
    assert!(
        error.to_string().contains("retained index entry 'dir'"),
        "{error}"
    );
    assert_eq!(fs::read(opened.repo.index_path())?, index_before_rejection);

    let index = opened.repo.open_index()?;
    let retained = index
        .entry_by_path(b"retained".as_bstr())
        .ok_or("retained fixture entry is missing")?;
    let retained = (retained.stat, retained.id, retained.flags, retained.mode);
    motor_gix::unstage::run(&opened, &["dir".into()], &cancellation)?;
    let index = opened.repo.open_index()?;
    assert_eq!(
        index
            .entry_by_path(b"dir/tracked".as_bstr())
            .ok_or("HEAD entry was not restored")?
            .id,
        baseline
    );
    let after = index
        .entry_by_path(b"retained".as_bstr())
        .ok_or("retained fixture entry is missing")?;
    assert_eq!((after.stat, after.id, after.flags, after.mode), retained);
    assert_eq!(fs::read(repository.join("dir"))?, b"replacement\n");

    let index_before_rejection = fs::read(opened.repo.index_path())?;
    let error = motor_gix::unstage::run(&opened, &["missing".into()], &cancellation)
        .expect_err("an unmatched literal path must fail");
    assert!(
        error
            .to_string()
            .contains("did not match HEAD or the index"),
        "{error}"
    );
    assert_eq!(fs::read(opened.repo.index_path())?, index_before_rejection);
    assert!(!opened.repo.git_dir().join("index.lock").exists());
    Ok(())
}

struct TransitionFixture {
    opened: motor_gix::repository::OpenedRepository,
    original_commit: gix::ObjectId,
    original_tree: gix::ObjectId,
    target_ref: gix::refs::FullName,
    target_commit: gix::ObjectId,
    target_tree: gix::ObjectId,
}

fn transition_fixture(output: &Path, name: &str) -> Result<TransitionFixture> {
    let repository = output.join(name);
    let cancellation = motor_gix::cancellation::Cancellation::new();
    motor_gix::init::run(
        &repository,
        &["init.defaultBranch=main"],
        false,
        &cancellation,
    )?;
    fs::create_dir_all(repository.join("dir/sub"))?;
    fs::create_dir(repository.join("removed"))?;
    for (path, data) in [
        (".gitignore", b"ignored-parent\ndir/block\n".as_slice()),
        ("a", b"old a\n"),
        ("dir/sub.extra", b"old sibling\n"),
        ("dir/sub/old", b"old child\n"),
        ("keep", b"unchanged\n"),
        ("removed/old", b"removed child\n"),
    ] {
        fs::write(repository.join(path), data)?;
    }
    let overrides = ["user.name=Native Test", "user.email=native@example.com"];
    let opened = motor_gix::repository::open(&repository, &overrides, false)?;
    motor_gix::add::run(&opened, true, &[], &cancellation)?;
    motor_gix::commit::run(&opened, "original", &cancellation)?;
    let repo = &opened.repo;
    let original_commit = repo.head_id()?.detach();
    let original_tree = repo.head_tree()?.id().detach();
    let (mut target, _) = repo.open_index()?.into_parts();
    target.remove_entries(|_, path, _| {
        path == "a" || path.starts_with(b"dir/") || path.starts_with(b"removed/")
    });
    let keep = target
        .entry_mut_by_path_and_stage(b"keep".as_bstr(), Stage::Unconflicted)
        .ok_or("transition fixture keep entry is missing")?;
    keep.id = repo.write_blob(b"target keep\n")?.detach();
    keep.mode = Mode::FILE_EXECUTABLE;
    for (path, data) in [
        ("a/b", b"new child\n".as_slice()),
        ("dir", b"new file\n"),
        ("empty-target", b"new empty replacement\n"),
        ("ignored-parent/leaf", b"ignored parent child\n"),
        ("untracked-parent/leaf", b"untracked parent child\n"),
    ] {
        target.dangerously_push_entry(
            Default::default(),
            repo.write_blob(data)?.detach(),
            Flags::empty(),
            Mode::FILE,
            path.as_bytes().as_bstr(),
        );
    }
    target.sort_entries();
    let target_tree = motor_gix::tree_index::write(repo, &target, &cancellation)?;
    let target_commit = repo
        .new_commit("transition target", target_tree, [original_commit])?
        .id;
    let target_ref: gix::refs::FullName = "refs/heads/transition-target".try_into()?;
    repo.reference(
        target_ref.clone(),
        target_commit,
        gix::refs::transaction::PreviousValue::MustNotExist,
        "transition fixture",
    )?;
    Ok(TransitionFixture {
        opened,
        original_commit,
        original_tree,
        target_ref,
        target_commit,
        target_tree,
    })
}

fn check_transition_delta(output: &Path) -> Result {
    let fixture = transition_fixture(output, "transition-repository")?;
    let repo = &fixture.opened.repo;
    let cancellation = motor_gix::cancellation::Cancellation::new();
    let mut guard = motor_gix::mutation::Guard::acquire(repo)?;
    let locked = guard.index();
    let index_before = fs::read(repo.index_path())?;
    let delta = motor_gix::transition::compute(
        repo,
        locked,
        &fixture.original_tree,
        &fixture.target_tree,
        &cancellation,
    )?;
    assert_eq!(
        delta
            .changes
            .iter()
            .map(|change| (
                change.path.as_bstr(),
                change.original.is_some(),
                change.target.is_some(),
            ))
            .collect::<Vec<_>>(),
        [
            ("a", true, false),
            ("a/b", false, true),
            ("dir", false, true),
            ("dir/sub.extra", true, false),
            ("dir/sub/old", true, false),
            ("empty-target", false, true),
            ("ignored-parent/leaf", false, true),
            ("keep", true, true),
            ("removed/old", true, false),
            ("untracked-parent/leaf", false, true),
        ]
        .map(|(path, old, new)| (path.as_bytes().as_bstr(), old, new))
    );
    assert_eq!(delta.original_index.entries().len(), 6);
    assert_eq!(delta.target_index.entries().len(), 7);
    let workdir = repo.workdir().ok_or("worktree missing")?;
    fs::create_dir(workdir.join("empty-target"))?;
    motor_gix::transition::preflight_collisions(repo, &delta, &cancellation)?;
    for parent in ["untracked-parent", "ignored-parent"] {
        fs::write(workdir.join(parent), b"obstruction\n")?;
        let error = motor_gix::transition::preflight_collisions(repo, &delta, &cancellation)
            .expect_err("an untracked or ignored ancestor was accepted");
        assert!(error.to_string().contains(parent), "{error}");
        fs::remove_file(workdir.join(parent))?;
    }
    fs::write(workdir.join("dir/block"), b"ignored obstruction\n")?;
    let error = motor_gix::transition::preflight_collisions(repo, &delta, &cancellation)
        .expect_err("an ignored descendant was accepted");
    assert!(error.to_string().contains("dir/block"), "{error}");
    fs::remove_file(workdir.join("dir/block"))?;
    fs::create_dir(workdir.join("dir/empty"))?;
    let error = motor_gix::transition::preflight_collisions(repo, &delta, &cancellation)
        .expect_err("an unrelated empty descendant directory was accepted");
    assert!(error.to_string().contains("dir/empty"), "{error}");
    fs::remove_dir(workdir.join("dir/empty"))?;

    fs::create_dir(workdir.join("untracked-parent"))?;
    fs::write(workdir.join("untracked-parent/.git"), b"foreign repository")?;
    let error = motor_gix::transition::preflight_collisions(repo, &delta, &cancellation)
        .expect_err("a nested repository ancestor was accepted");
    assert!(error.to_string().contains("nested repository"), "{error}");
    fs::remove_dir_all(workdir.join("untracked-parent"))?;

    fs::write(workdir.join("removed/.git"), b"foreign repository")?;
    let error = motor_gix::transition::preflight_collisions(repo, &delta, &cancellation)
        .expect_err("a nested repository on a deletion-only path was accepted");
    assert!(error.to_string().contains("removed"), "{error}");
    fs::remove_file(workdir.join("removed/.git"))?;

    let prepared = motor_gix::transition::prepare(
        &fixture.opened,
        locked,
        &fixture.original_tree,
        &fixture.target_tree,
        &cancellation,
    )?;
    assert_eq!(prepared.target_index.entries().len(), 7);
    assert!(
        prepared
            .changes
            .iter()
            .filter(|change| change.original.is_some())
            .all(|change| change.original_stat.is_some())
    );

    let mut filtered_target = prepared.target_index.clone();
    filtered_target.dangerously_push_entry(
        Default::default(),
        repo.write_blob(b".gitignore filter=blocked\n")?.detach(),
        Flags::empty(),
        Mode::FILE,
        b".gitattributes".as_bstr(),
    );
    filtered_target.sort_entries();
    let filtered_target = motor_gix::tree_index::write(repo, &filtered_target, &cancellation)?;
    let filtered = motor_gix::repository::open(workdir, &["filter.blocked.required=true"], false)?;
    let error = motor_gix::transition::prepare(
        &filtered,
        locked,
        &fixture.original_tree,
        &filtered_target,
        &cancellation,
    )
    .expect_err("a target attribute assigning a required external filter was accepted");
    assert!(
        error
            .to_string()
            .contains("path '.gitignore' uses unsupported filter 'blocked'"),
        "{error}"
    );
    assert!(!workdir.join(".gitattributes").try_exists()?);

    let gitignore = workdir.join(".gitignore");
    let original_gitignore = fs::read(&gitignore)?;
    let dirty = b"ignored-parent\ndir/block\n# dirty but unpersisted\n";
    let dirty_id = gix::objs::compute_hash(repo.object_hash(), gix::objs::Kind::Blob, dirty)?;
    assert!(repo.try_find_object(dirty_id)?.is_none());
    fs::write(&gitignore, dirty)?;
    let error = motor_gix::transition::prepare(
        &fixture.opened,
        locked,
        &fixture.original_tree,
        &fixture.target_tree,
        &cancellation,
    )
    .expect_err("a dirty unchanged tracked file was accepted");
    assert!(
        error.to_string().contains(".gitignore' has local changes"),
        "{error}"
    );
    assert!(repo.try_find_object(dirty_id)?.is_none());
    fs::write(gitignore, original_gitignore)?;

    assert!(
        motor_gix::transition::compute(
            repo,
            &delta.target_index,
            &fixture.original_tree,
            &fixture.target_tree,
            &cancellation,
        )
        .is_err(),
        "an index that differs from the original tree was accepted"
    );

    let mut gitlink_target = delta.target_index.clone();
    gitlink_target.dangerously_push_entry(
        Default::default(),
        fixture.original_commit,
        Flags::empty(),
        Mode::COMMIT,
        b"gitlink".as_bstr(),
    );
    gitlink_target.sort_entries();
    let gitlink_tree = motor_gix::tree_index::write(repo, &gitlink_target, &cancellation)?;
    assert!(
        motor_gix::transition::compute(
            repo,
            locked,
            &fixture.original_tree,
            &gitlink_tree,
            &cancellation,
        )
        .is_err(),
        "a changed gitlink was accepted"
    );
    assert_eq!(repo.head_id()?.detach(), fixture.original_commit);
    assert_eq!(fs::read(repo.index_path())?, index_before);
    assert_eq!(fs::read(workdir.join("a"))?, b"old a\n");

    use motor_gix::operation::{Kind, Original, Record, State};
    let original_ref = repo
        .head()?
        .referent_name()
        .ok_or("transition fixture HEAD is detached")?
        .to_owned();
    let record = Record {
        state: State::Incomplete,
        kind: Kind::Switch,
        original: Original {
            reference: Some(original_ref),
            id: Some(fixture.original_commit),
        },
        target_ref: fixture.target_ref.clone(),
        target_commit: fixture.target_commit,
        result_tree: fixture.target_tree,
        intended_commit: None,
    };
    guard.create_operation(&record)?;
    let operation_path = repo.git_dir().join(motor_gix::mutation::OPERATION_FILE);
    let operation_before = fs::read(&operation_path)?;
    let unchanged_path = workdir.join(".gitignore");
    let unchanged_bytes = fs::read(&unchanged_path)?;
    let unchanged_stat = gix::index::entry::Stat::from_fs(
        &gix::index::fs::Metadata::from_path_no_follow(&unchanged_path)?,
    )?;
    fs::create_dir(workdir.join("ignored-parent"))?;
    let sentinel = workdir.join("ignored-parent/unrelated");
    fs::write(&sentinel, b"preserve me\n")?;

    fs::write(workdir.join("removed/old"), b"late stale source expanded\n")?;
    let error =
        motor_gix::transition::install(&fixture.opened, &guard, &record, prepared, &cancellation)
            .expect_err("a source changed after preparation was accepted");
    assert!(error.to_string().contains("removed/old"), "{error}");
    assert_eq!(fs::read(workdir.join("a"))?, b"old a\n");
    assert_eq!(fs::read(repo.index_path())?, index_before);
    assert_eq!(repo.head_id()?.detach(), fixture.original_commit);
    assert_eq!(fs::read(&operation_path)?, operation_before);

    fs::write(workdir.join("removed/old"), b"removed child\n")?;
    let prepared = motor_gix::transition::prepare(
        &fixture.opened,
        guard.index(),
        &fixture.original_tree,
        &fixture.target_tree,
        &cancellation,
    )?;
    let installed =
        motor_gix::transition::install(&fixture.opened, &guard, &record, prepared, &cancellation)?;
    assert_eq!(fs::read(workdir.join("a/b"))?, b"new child\n");
    assert_eq!(fs::read(workdir.join("dir"))?, b"new file\n");
    assert_eq!(
        fs::read(workdir.join("empty-target"))?,
        b"new empty replacement\n"
    );
    assert_eq!(fs::read(workdir.join("keep"))?, b"target keep\n");
    assert!(gix::index::fs::Metadata::from_path_no_follow(&workdir.join("keep"))?.is_executable());
    assert!(!workdir.join("removed/old").try_exists()?);
    assert_eq!(fs::read(&unchanged_path)?, unchanged_bytes);
    assert_eq!(
        gix::index::entry::Stat::from_fs(&gix::index::fs::Metadata::from_path_no_follow(
            &unchanged_path
        )?,)?,
        unchanged_stat
    );
    assert_eq!(fs::read(&sentinel)?, b"preserve me\n");
    assert_eq!(repo.head_id()?.detach(), fixture.original_commit);
    assert_eq!(fs::read(&operation_path)?, operation_before);
    assert_eq!(fs::read(repo.index_path())?, index_before);
    guard.publish_fresh_index(installed)?;
    let published = repo.open_index()?;
    assert_eq!(
        published.entries().len(),
        delta.target_index.entries().len()
    );
    assert!(
        published
            .entries()
            .iter()
            .zip(delta.target_index.entries())
            .all(|(actual, expected)| {
                actual.path(&published) == expected.path(&delta.target_index)
                    && actual.id == expected.id
                    && actual.mode == expected.mode
                    && !actual.flags.contains(Flags::SKIP_WORKTREE)
            })
    );
    assert_eq!(repo.head_id()?.detach(), fixture.original_commit);
    assert_eq!(motor_gix::operation::read(&operation_path)?, Some(record));
    drop(guard);
    assert!(!repo.git_dir().join("index.lock").try_exists()?);
    Ok(())
}

fn check_switch(output: &Path) -> Result {
    use motor_gix::operation::Original;

    let mut fixture = transition_fixture(output, "switch-repository")?;
    let cancellation = motor_gix::cancellation::Cancellation::new();
    let git_dir = fixture.opened.repo.git_dir().to_owned();
    let main = fixture
        .opened
        .repo
        .head()?
        .referent_name()
        .ok_or("switch fixture HEAD is detached")?
        .to_owned();
    let log_root = git_dir.join("logs");
    let main_log = log_root.join(gix::path::from_bstr(main.as_bstr()).as_ref());
    let target_log = log_root.join(gix::path::from_bstr(fixture.target_ref.as_bstr()).as_ref());
    let branch_logs = [fs::read(&main_log)?, fs::read(&target_log)?];
    let head_log = fs::read(log_root.join("HEAD"))?;

    motor_gix::switch::run(&mut fixture.opened, "transition-target", &cancellation)?;
    let repo = &fixture.opened.repo;
    assert_eq!(
        motor_gix::head_ref::capture(repo)?,
        Original {
            reference: Some(fixture.target_ref.clone()),
            id: Some(fixture.target_commit),
        }
    );
    assert_eq!(repo.find_reference(&main)?.id(), fixture.original_commit);
    assert_eq!(
        repo.find_reference(&fixture.target_ref)?.id(),
        fixture.target_commit
    );
    assert_eq!(fs::read(main_log)?, branch_logs[0]);
    assert_eq!(fs::read(target_log)?, branch_logs[1]);
    let changed_log = fs::read(log_root.join("HEAD"))?;
    let appended = &changed_log[head_log.len()..];
    assert!(
        appended.starts_with(
            format!("{} {} ", fixture.original_commit, fixture.target_commit).as_bytes()
        )
    );
    assert!(appended.ends_with(b"\tswitch: transition-target\n"));
    assert_eq!(appended.iter().filter(|byte| **byte == b'\n').count(), 1);

    let index = repo.open_index()?;
    assert_eq!(
        motor_gix::tree_index::write(repo, &index, &cancellation)?,
        fixture.target_tree
    );
    assert_eq!(
        fs::read(repo.workdir().ok_or("switch worktree missing")?.join("a/b"))?,
        b"new child\n"
    );
    assert!(
        !git_dir
            .join(motor_gix::mutation::OPERATION_FILE)
            .try_exists()?
    );
    assert!(!git_dir.join("index.lock").try_exists()?);

    motor_gix::switch::run(&mut fixture.opened, "transition-target", &cancellation)?;
    assert_eq!(fs::read(log_root.join("HEAD"))?, changed_log);
    let operation_path = git_dir.join(motor_gix::mutation::OPERATION_FILE);
    assert!(!operation_path.try_exists()?);

    let head_lock = git_dir.join("HEAD.lock");
    fs::write(&head_lock, b"foreign")?;
    let error = motor_gix::switch::run(&mut fixture.opened, "main", &cancellation)
        .expect_err("a foreign HEAD lock allowed switch publication");
    assert!(
        error.to_string().contains("switch is incomplete"),
        "{error}"
    );
    assert_eq!(fs::read(&head_lock)?, b"foreign");
    assert!(operation_path.try_exists()?);
    assert_eq!(
        motor_gix::head_ref::capture(&fixture.opened.repo)?,
        Original {
            reference: Some(fixture.target_ref),
            id: Some(fixture.target_commit),
        }
    );
    assert_eq!(fs::read(log_root.join("HEAD"))?, changed_log);
    assert!(!git_dir.join("index.lock").try_exists()?);
    Ok(())
}

fn check_commit(output: &Path) -> Result {
    let repository = output.join("commit-repository");
    let cancellation = motor_gix::cancellation::Cancellation::new();
    motor_gix::init::run(
        &repository,
        &["init.defaultBranch=main"],
        false,
        &cancellation,
    )?;
    fs::write(repository.join("first"), b"first\n")?;
    let staged = motor_gix::repository::open(&repository, &[], false)?;
    motor_gix::add::run(&staged, true, &[], &cancellation)?;
    let index_before = fs::read(staged.repo.index_path())?;
    let operation_lock = staged
        .repo
        .git_dir()
        .join(motor_gix::mutation::OPERATION_LOCK_FILE);
    fs::write(&operation_lock, b"identity preflight sentinel")?;

    for (overrides, expected) in [
        (
            ["user.name=", "user.email="],
            "author identity requires a nonempty name and email",
        ),
        (
            ["user.name=Bad<Name", "user.email=native@example.com"],
            "Signature name or email",
        ),
    ] {
        let invalid = motor_gix::repository::open(&repository, &overrides, false)?;
        let error = motor_gix::commit::run(&invalid, "must fail", &cancellation)
            .err()
            .ok_or("invalid identity created a commit")?;
        assert!(error.to_string().contains(expected), "{error}");
        assert!(invalid.repo.head()?.is_unborn());
        assert_eq!(fs::read(invalid.repo.index_path())?, index_before);
        assert_eq!(
            fs::read(&operation_lock)?,
            b"identity preflight sentinel",
            "identity failure reached the mutation guard"
        );
    }
    fs::write(&operation_lock, [])?;

    let overrides = ["user.name=Native Test", "user.email=native@example.com"];
    let opened = motor_gix::repository::open(&repository, &overrides, false)?;
    motor_gix::commit::run(&opened, "initial", &cancellation)?;
    let initial = opened.repo.head_id()?.detach();
    let initial_commit = opened.repo.find_commit(initial)?;
    assert_eq!(initial_commit.parent_ids().count(), 0);
    assert_eq!(initial_commit.message_raw()?, b"initial".as_bstr());
    assert_eq!(initial_commit.author()?.name, b"Native Test".as_bstr());
    assert_eq!(
        initial_commit.committer()?.email,
        b"native@example.com".as_bstr()
    );
    let initial_tree = initial_commit.tree()?;
    let first = initial_tree
        .lookup_entry_by_path("first")?
        .ok_or("initial tree entry is missing")?;
    assert_eq!(opened.repo.find_blob(first.object_id())?.data, b"first\n");
    assert!(
        opened
            .repo
            .head()?
            .referent_name()
            .is_some_and(|name| name.as_bstr() == b"refs/heads/main")
    );
    for path in [".git/logs/HEAD", ".git/logs/refs/heads/main"] {
        assert!(
            fs::read(repository.join(path))?.ends_with(b"\tcommit (initial): initial\n"),
            "{path} has the wrong initial reflog"
        );
    }

    fs::remove_file(repository.join("first"))?;
    fs::write(repository.join("second"), b"second\n")?;
    motor_gix::add::run(&opened, true, &[], &cancellation)?;
    motor_gix::commit::run(&opened, "second", &cancellation)?;
    let second = opened.repo.head_id()?.detach();
    let second_commit = opened.repo.find_commit(second)?;
    assert_eq!(
        second_commit
            .parent_ids()
            .map(|id| id.detach())
            .collect::<Vec<_>>(),
        vec![initial]
    );
    let second_tree = second_commit.tree()?;
    assert!(second_tree.lookup_entry_by_path("first")?.is_none());
    let entry = second_tree
        .lookup_entry_by_path("second")?
        .ok_or("second tree entry is missing")?;
    assert_eq!(opened.repo.find_blob(entry.object_id())?.data, b"second\n");
    for path in [".git/logs/HEAD", ".git/logs/refs/heads/main"] {
        assert!(
            fs::read(repository.join(path))?.ends_with(b"\tcommit: second\n"),
            "{path} has the wrong second reflog"
        );
    }

    assert!(motor_gix::commit::run(&opened, "empty", &cancellation).is_err());
    assert_eq!(opened.repo.head_id()?.detach(), second);

    fs::write(repository.join("third"), b"third\n")?;
    motor_gix::add::run(&opened, false, &["third".into()], &cancellation)?;
    let staged_index = fs::read(opened.repo.index_path())?;
    fs::write(repository.join(".git/HEAD"), format!("{second}\n"))?;
    let detached = motor_gix::repository::open(&repository, &overrides, false)?;
    let error = motor_gix::commit::run(&detached, "detached", &cancellation)
        .err()
        .ok_or("detached HEAD accepted a commit")?;
    assert!(error.to_string().contains("attached to a local branch"));
    assert_eq!(fs::read(detached.repo.index_path())?, staged_index);
    fs::write(repository.join(".git/HEAD"), b"ref: refs/heads/main\n")?;

    let opened = motor_gix::repository::open(&repository, &overrides, false)?;
    let ref_lock = repository.join(".git/refs/heads/main.lock");
    fs::write(&ref_lock, b"foreign")?;
    assert!(motor_gix::commit::run(&opened, "locked", &cancellation).is_err());
    assert_eq!(opened.repo.head_id()?.detach(), second);
    assert_eq!(fs::read(opened.repo.index_path())?, staged_index);
    assert_eq!(fs::read(&ref_lock)?, b"foreign");
    assert!(!repository.join(".git/index.lock").try_exists()?);
    assert!(!repository.join(".git/HEAD.lock").try_exists()?);
    fs::remove_file(ref_lock)?;

    let ids = [
        opened.repo.write_blob(b"base\n")?.detach(),
        opened.repo.write_blob(b"ours\n")?.detach(),
        opened.repo.write_blob(b"theirs\n")?.detach(),
    ];
    let mut guard = motor_gix::mutation::Guard::acquire(&opened.repo)?;
    guard.publish_edited_index(|index| {
        for (stage, id) in [Stage::Base, Stage::Ours, Stage::Theirs]
            .into_iter()
            .zip(ids)
        {
            index.dangerously_push_entry(
                Default::default(),
                id,
                Flags::from_stage(stage),
                Mode::FILE,
                b"conflict".as_bstr(),
            );
        }
        Ok(())
    })?;
    drop(guard);
    let conflicted_index = fs::read(opened.repo.index_path())?;
    let error = motor_gix::commit::run(&opened, "conflict", &cancellation)
        .err()
        .ok_or("unresolved index created a commit")?;
    assert!(error.to_string().contains("is unresolved"), "{error}");
    assert_eq!(opened.repo.head_id()?.detach(), second);
    assert_eq!(fs::read(opened.repo.index_path())?, conflicted_index);
    assert!(!repository.join(".git/index.lock").try_exists()?);
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

    check_operation_record(&opened)?;
    let marker = git_dir.join("MERGE_HEAD");
    fs::write(&marker, [])?;
    expect_guard_rejected(&opened.repo, "unsupported operation state")?;
    fs::remove_file(marker)?;
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

fn check_operation_record(opened: &motor_gix::repository::OpenedRepository) -> Result {
    use motor_gix::operation::{Kind, Original, Record, State};

    let repo = &opened.repo;
    let path = repo.git_dir().join(motor_gix::mutation::OPERATION_FILE);
    let branch = gix::refs::FullName::try_from(b"refs/heads/non-utf8-\xff".as_bstr())?;
    let mut record = Record {
        state: State::Incomplete,
        kind: Kind::Merge,
        original: Original {
            reference: Some(branch.clone()),
            id: Some(gix::ObjectId::from_hex(
                b"1111111111111111111111111111111111111111",
            )?),
        },
        target_ref: branch,
        target_commit: gix::ObjectId::from_hex(b"2222222222222222222222222222222222222222")?,
        result_tree: gix::ObjectId::from_hex(b"3333333333333333333333333333333333333333")?,
        intended_commit: None,
    };
    let guard = motor_gix::mutation::Guard::acquire(repo)?;
    let mut invalid = record.clone();
    invalid.original = Original {
        reference: None,
        id: None,
    };
    assert!(guard.create_operation(&invalid).is_err());
    invalid = record.clone();
    invalid.original.reference = Some(gix::refs::FullName::try_from("refs/heads/other")?);
    assert!(guard.create_operation(&invalid).is_err());
    invalid = record.clone();
    invalid.state = State::Ready;
    assert!(guard.create_operation(&invalid).is_err());
    assert!(!path.exists() && !path.with_extension("lock").exists());
    guard.create_operation(&record)?;
    assert_eq!(motor_gix::operation::read(&path)?, Some(record.clone()));
    assert!(!path.with_extension("lock").exists());

    for (state, intended) in [
        (State::Ready, None),
        (State::Publishing, Some(record.result_tree)),
        (State::Ready, None),
        (State::Incomplete, None),
    ] {
        let mut next = record.clone();
        next.state = state;
        next.intended_commit = intended;
        guard.replace_operation(&record, &next)?;
        assert_eq!(motor_gix::operation::read(&path)?, Some(next.clone()));
        record = next;
    }
    let before = fs::read(&path)?;
    let mut stale = record.clone();
    stale.state = State::Ready;
    let mut publishing = stale.clone();
    publishing.state = State::Publishing;
    publishing.intended_commit = Some(record.result_tree);
    let error = guard
        .replace_operation(&stale, &publishing)
        .expect_err("a stale operation snapshot was accepted");
    assert!(
        error
            .to_string()
            .contains("changed while it was being updated")
    );
    assert_eq!(fs::read(&path)?, before);

    let mut changed = record.clone();
    changed.state = State::Ready;
    changed.target_commit = changed.result_tree;
    assert!(guard.replace_operation(&record, &changed).is_err());
    assert_eq!(motor_gix::operation::read(&path)?, Some(record.clone()));
    guard.remove_operation(&record)?;
    assert!(!path.exists() && !path.with_extension("lock").exists());
    drop(guard);
    fs::write(path.with_extension("lock"), [])?;
    expect_guard_rejected(repo, "stale gix operation update lock")?;
    fs::remove_file(path.with_extension("lock"))?;

    let guard = motor_gix::mutation::Guard::acquire(repo)?;
    guard.create_operation(&record)?;
    drop(guard);
    expect_guard_rejected(repo, "merge incomplete")?;
    let cancellation = motor_gix::cancellation::Cancellation::new();
    let mut output = Vec::new();
    motor_gix::status::collect(opened, &cancellation)?.write_to(&mut output, &cancellation)?;
    assert!(output.starts_with(b"operation merge incomplete\n"));
    fs::write(
        repo.git_dir().join("MERGE_HEAD"),
        record.target_commit.to_string(),
    )?;
    let (guard, observed) = motor_gix::mutation::Guard::acquire_for_recovery(repo)?;
    assert_eq!(observed, record);
    run_mutation_child(
        repo.workdir().ok_or("mutation worktree missing")?,
        "blocked",
    )?;
    guard.remove_operation(&observed)?;
    drop(guard);
    fs::remove_file(repo.git_dir().join("MERGE_HEAD"))?;
    run_mutation_child(
        repo.workdir().ok_or("mutation worktree missing")?,
        "acquire",
    )?;

    let guard = motor_gix::mutation::Guard::acquire(repo)?;
    guard.create_operation(&record)?;
    let mut ready = record.clone();
    ready.state = State::Ready;
    guard.replace_operation(&record, &ready)?;
    drop(guard);
    let error = motor_gix::mutation::Guard::acquire_for_recovery(repo)
        .err()
        .ok_or("recovery admitted a ready merge")?;
    assert!(error.to_string().contains("must be committed or aborted"));
    fs::remove_file(&path)?;

    fs::write(&path, b"version=1\n")?;
    let error = motor_gix::operation::read(&path)
        .err()
        .ok_or("truncated operation record was accepted")?;
    assert!(error.to_string().contains("invalid gix operation record"));
    expect_guard_rejected(repo, "invalid gix operation record")?;
    assert!(motor_gix::status::collect(opened, &cancellation).is_err());
    fs::remove_file(path)?;
    Ok(())
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

fn check_restore(output: &Path) -> Result {
    let repository = output.join("add-repository");
    let opened = motor_gix::repository::open(&repository, &[], false)?;
    let repo = &opened.repo;
    let cancellation = motor_gix::cancellation::Cancellation::new();
    let index_before = fs::read(repo.index_path())?;
    let head_before = fs::read(repo.git_dir().join("HEAD"))?;

    fs::write(repository.join("modified"), b"dirty\n")?;
    fs::remove_file(repository.join("ignored-tracked"))?;
    fs::copy(
        repository.join("executable"),
        repository.join("link-preserved"),
    )?;
    fs::copy(repository.join("modified"), repository.join("executable"))?;
    fs::write(repository.join("added"), b"nonselected\n")?;
    let paths = [
        "modified".into(),
        "ignored-tracked".into(),
        "executable".into(),
        "link-preserved".into(),
        "gitlink".into(),
    ];
    motor_gix::restore::run(&opened, &paths, &cancellation)?;
    for (path, data, executable) in [
        ("modified", b"new\n".as_slice(), false),
        ("ignored-tracked", b"new ignored\n", false),
        ("executable", b"new executable\n", true),
        ("link-preserved", b"new-target", false),
    ] {
        assert_eq!(fs::read(repository.join(path))?, data, "{path}");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(repository.join(path))?;
        assert_eq!(
            gix::index::fs::Metadata::from_file(&file)?.is_executable(),
            executable,
            "{path}"
        );
    }
    assert_eq!(fs::read(repository.join("added"))?, b"nonselected\n");
    assert_eq!(
        fs::read(repository.join("gitlink/untracked-child"))?,
        b"must not stage\n"
    );
    assert_eq!(fs::read(repo.index_path())?, index_before);

    fs::remove_file(repository.join("modified"))?;
    fs::create_dir(repository.join("modified"))?;
    motor_gix::restore::run(&opened, &["modified".into()], &cancellation)?;
    assert_eq!(fs::read(repository.join("modified"))?, b"new\n");

    fs::remove_file(repository.join("ignored-tracked"))?;
    fs::create_dir(repository.join("ignored-tracked"))?;
    fs::write(repository.join("ignored-tracked/keep"), b"preserved\n")?;
    fs::write(repository.join("added"), b"preflight preserved\n")?;
    expect_restore_rejected(
        &opened,
        &["added".into(), "ignored-tracked".into()],
        "worktree directory is not empty",
    )?;
    assert_eq!(
        fs::read(repository.join("added"))?,
        b"preflight preserved\n"
    );
    assert_eq!(
        fs::read(repository.join("ignored-tracked/keep"))?,
        b"preserved\n"
    );

    fs::remove_file(repository.join("file-parent/child"))?;
    fs::remove_dir(repository.join("file-parent"))?;
    fs::write(repository.join("file-parent"), b"obstruction\n")?;
    expect_restore_rejected(
        &opened,
        &["file-parent/child".into()],
        "worktree ancestor is not a directory",
    )?;
    assert_eq!(fs::read(repository.join("file-parent"))?, b"obstruction\n");

    let id = repo.write_blob(b"conflict\n")?.detach();
    let mut guard = motor_gix::mutation::Guard::acquire(repo)?;
    guard.publish_edited_index(|index| {
        let path = b"conflict".as_bstr();
        index.remove_entries(|_, entry_path, _| entry_path == path);
        for stage in [Stage::Base, Stage::Ours, Stage::Theirs] {
            let flags = Flags::from_stage(stage);
            index.dangerously_push_entry(Default::default(), id, flags, Mode::FILE, path);
        }
        Ok(())
    })?;
    drop(guard);
    expect_restore_rejected(&opened, &["conflict".into()], "index entry is conflicted")?;
    fs::write(repo.index_path(), &index_before)?;
    assert_eq!(fs::read(repo.index_path())?, index_before);
    assert_eq!(fs::read(repo.git_dir().join("HEAD"))?, head_before);
    assert!(!repo.git_dir().join("index.lock").try_exists()?);
    Ok(())
}

fn expect_restore_rejected(
    opened: &motor_gix::repository::OpenedRepository,
    paths: &[String],
    expected: &str,
) -> Result {
    let before = fs::read(opened.repo.index_path())?;
    let error =
        motor_gix::restore::run(opened, paths, &motor_gix::cancellation::Cancellation::new())
            .expect_err("restore unexpectedly succeeded");
    assert!(error.to_string().contains(expected), "{error}");
    assert_eq!(fs::read(opened.repo.index_path())?, before);
    assert!(!opened.repo.git_dir().join("index.lock").try_exists()?);
    Ok(())
}

fn check_head_ref(output: &Path) -> Result {
    use motor_gix::operation::Original;

    let repository = output.join("head-ref-repository");
    let cancellation = motor_gix::cancellation::Cancellation::new();
    motor_gix::init::run(
        &repository,
        &["init.defaultBranch=main"],
        false,
        &cancellation,
    )?;
    let mut opened = motor_gix::repository::open(
        &repository,
        &["user.name=Native Test", "user.email=native@example.com"],
        false,
    )?;
    let main: gix::refs::FullName = "refs/heads/main".try_into()?;
    let unborn = Original {
        reference: Some(main.clone()),
        id: None,
    };
    assert_eq!(motor_gix::head_ref::capture(&opened.repo)?, unborn);
    motor_gix::head_ref::require(&opened.repo, &unborn)?;

    fs::write(repository.join("tracked"), b"content\n")?;
    motor_gix::add::run(&opened, true, &[], &cancellation)?;
    motor_gix::commit::run(&opened, "head fixture", &cancellation)?;
    let commit = opened.repo.head_id()?.detach();
    let attached = Original {
        reference: Some(main.clone()),
        id: Some(commit),
    };
    assert_eq!(motor_gix::head_ref::capture(&opened.repo)?, attached);
    assert_eq!(
        motor_gix::head_ref::existing_local_branch(&opened.repo, "main")?,
        (main.clone(), commit)
    );

    let head_path = opened.repo.git_dir().join("HEAD");
    fs::write(&head_path, format!("{commit}\n"))?;
    let detached = Original {
        reference: None,
        id: Some(commit),
    };
    assert_eq!(motor_gix::head_ref::capture(&opened.repo)?, detached);
    assert!(motor_gix::head_ref::require(&opened.repo, &attached).is_err());

    let tree = opened.repo.find_commit(commit)?.tree_id()?.detach();
    fs::write(&head_path, format!("{tree}\n"))?;
    assert!(
        motor_gix::head_ref::capture(&opened.repo).is_err(),
        "a detached non-commit HEAD was accepted"
    );
    fs::write(&head_path, b"ref: refs/heads/main\n")?;
    motor_gix::head_ref::require(&opened.repo, &attached)?;

    fs::write(
        opened.repo.git_dir().join("refs/heads/symbolic"),
        b"ref: refs/heads/main\n",
    )?;
    assert!(
        motor_gix::head_ref::existing_local_branch(&opened.repo, "symbolic").is_err(),
        "a symbolic local branch was followed"
    );
    fs::write(&head_path, b"ref: refs/tags/not-a-branch\n")?;
    assert!(
        motor_gix::head_ref::capture(&opened.repo).is_err(),
        "HEAD attached outside the local-branch namespace was accepted"
    );
    fs::write(&head_path, b"ref: refs/heads/main\n")?;

    let target_commit = opened.repo.new_commit("head target", tree, [commit])?.id;
    for name in ["other", "same"] {
        opened.repo.reference(
            format!("refs/heads/{name}"),
            target_commit,
            gix::refs::transaction::PreviousValue::MustNotExist,
            "head fixture",
        )?;
    }
    let (other_ref, _) = motor_gix::head_ref::existing_local_branch(&opened.repo, "other")?;
    let (same_ref, _) = motor_gix::head_ref::existing_local_branch(&opened.repo, "same")?;
    let log_root = opened.repo.git_dir().join("logs");
    let branch_logs = [
        fs::read(log_root.join("refs/heads/main"))?,
        fs::read(log_root.join("refs/heads/other"))?,
        fs::read(log_root.join("refs/heads/same"))?,
    ];
    let mut head_log = fs::read(log_root.join("HEAD"))?;

    let guard = motor_gix::mutation::Guard::acquire(&opened.repo)?;
    run_mutation_child(&repository, "blocked")?;
    let actual = motor_gix::head_ref::attach(
        &mut opened.repo,
        &attached,
        &other_ref,
        target_commit,
        b"switch: other".as_bstr(),
        &cancellation,
    )?;
    let on_other = Original {
        reference: Some(other_ref.clone()),
        id: Some(target_commit),
    };
    assert_eq!(actual, on_other);
    assert_eq!(opened.repo.find_reference(&main)?.id(), commit);
    assert_eq!(opened.repo.find_reference(&other_ref)?.id(), target_commit);
    assert_eq!(opened.repo.find_reference(&same_ref)?.id(), target_commit);
    assert_eq!(fs::read(log_root.join("refs/heads/main"))?, branch_logs[0]);
    assert_eq!(fs::read(log_root.join("refs/heads/other"))?, branch_logs[1]);
    assert_eq!(fs::read(log_root.join("refs/heads/same"))?, branch_logs[2]);
    let changed_log = fs::read(log_root.join("HEAD"))?;
    let appended = &changed_log[head_log.len()..];
    assert!(appended.starts_with(format!("{commit} {target_commit} ").as_bytes()));
    assert!(appended.ends_with(b"\tswitch: other\n"));
    assert_eq!(appended.iter().filter(|byte| **byte == b'\n').count(), 1);
    head_log = changed_log;

    let error = motor_gix::head_ref::attach(
        &mut opened.repo,
        &attached,
        &same_ref,
        target_commit,
        b"stale".as_bstr(),
        &cancellation,
    )
    .expect_err("a stale expected HEAD was accepted");
    assert!(error.to_string().contains("HEAD changed"), "{error}");
    let error = motor_gix::head_ref::attach(
        &mut opened.repo,
        &on_other,
        &same_ref,
        commit,
        b"moved".as_bstr(),
        &cancellation,
    )
    .expect_err("a moved destination branch was accepted");
    assert!(error.to_string().contains("local branch"), "{error}");
    assert_eq!(fs::read(log_root.join("HEAD"))?, head_log);

    let on_same = motor_gix::head_ref::attach(
        &mut opened.repo,
        &on_other,
        &same_ref,
        target_commit,
        b"switch: same".as_bstr(),
        &cancellation,
    )?;
    assert_eq!(
        on_same,
        Original {
            reference: Some(same_ref),
            id: Some(target_commit),
        }
    );
    let equal_log = fs::read(log_root.join("HEAD"))?;
    let appended = &equal_log[head_log.len()..];
    assert!(appended.starts_with(format!("{target_commit} {target_commit} ").as_bytes()));
    assert!(appended.ends_with(b"\tswitch: same\n"));
    assert_eq!(appended.iter().filter(|byte| **byte == b'\n').count(), 1);
    assert_eq!(fs::read(log_root.join("refs/heads/main"))?, branch_logs[0]);
    assert_eq!(fs::read(log_root.join("refs/heads/other"))?, branch_logs[1]);
    assert_eq!(fs::read(log_root.join("refs/heads/same"))?, branch_logs[2]);
    run_mutation_child(&repository, "blocked")?;
    drop(guard);
    run_mutation_child(&repository, "acquire")?;
    Ok(())
}
