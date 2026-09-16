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
    index::{File, entry::Mode},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() -> Result {
    let mut args = std::env::args_os().skip(1);
    let first = args.next().ok_or("fixture path required")?;
    if first == OsStr::new("--capture-child") {
        return capture_child(&args.next().ok_or("capture action required")?);
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
    check_capture(&output)?;
    let worktree = output.join("worktree");
    fs::create_dir(&worktree)?;

    let repo = gix::open::Options::isolated()
        .config_overrides([
            "core.symlinks=false",
            "core.checkStat=minimal",
            "core.trustctime=false",
        ])
        .open(&fixture)?
        .to_thread_local();
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

    check_pack_validation(&repo, &output)?;

    let capabilities = gix::fs::Capabilities::probe_dir(&worktree);
    assert!(
        capabilities.executable_bit,
        "native probe must observe executable bits"
    );
    let tree = repo.head_tree_id()?.detach();
    let state = motor_gix::tree_index::build(
        &repo,
        &tree,
        &worktree,
        &motor_gix::cancellation::Cancellation::new(),
    )?;
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
