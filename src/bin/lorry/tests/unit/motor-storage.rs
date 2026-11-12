#[test]
fn motor_cache_roots_are_disjoint_from_repositories_in_both_roles() {
    let mut config = Config::default();
    for role in [Role::None, Role::Interactive] {
        let root = role.cache_directory();
        for repository in [root.clone(), root.join("vendor")] {
            config.repositories.local = Some(repository);
            let error = validate_storage_layout(&config, &BTreeMap::new()).unwrap_err();
            assert!(error.render().contains("overlap"));
        }
    }
    config.repositories.local = Some(PathBuf::from("/none/tmp/lorry-test-vendor"));
    validate_storage_layout(&config, &BTreeMap::new()).unwrap();
}

#[test]
fn motor_rejects_cache_directory_overrides() {
    let path = Path::new("/none/cfg/lorry.toml");
    let document = Document::parse(
        path,
        "test",
        "[cache]\ndirectory = \"/none/custom-cache\"\n".into(),
    )
    .unwrap();
    let error = merge_cache(path, &document, &mut Config::default())
        .unwrap_err()
        .render();
    assert!(
        error.contains("cache.directory` is not supported on Motor"),
        "{error}"
    );
    assert!(error.contains("/none/cfg/lorry.toml:2"), "{error}");
}

#[test]
fn motor_cargo_home_shares_defaults_and_preserves_overrides() {
    let temp = TempDir::new();
    let root = temp.0.join("workspace");
    fs::create_dir_all(root.join(".cargo")).unwrap();
    let load = |environment: &BTreeMap<String, String>| {
        let mut config = Config::default();
        load_cargo_layers(&root, &root, environment, &mut config, |name| {
            environment.get(name).map(OsString::from)
        })
        .unwrap();
        config
    };
    assert_eq!(
        default_cargo_home(None).unwrap(),
        Path::new("/user/cfg/cargo")
    );
    let mut environment = BTreeMap::from([
        (
            "HOME".into(),
            temp.0.join("unused-home").display().to_string(),
        ),
        ("CARGO_HOME".into(), String::new()),
    ]);
    let config = load(&environment);
    for name in [
        "CFLAGS_x86_64_unknown_motor",
        "CXXFLAGS_x86_64_unknown_motor",
    ] {
        assert_eq!(config.environment[name], "--target=x86_64-unknown-motor");
    }
    assert_eq!(config.environment["CXXSTDLIB_x86_64_unknown_motor"], "c++");
    assert!(config.cargo_trust.is_empty());

    environment.insert("CXXSTDLIB_x86_64_unknown_motor".into(), String::new());
    assert_eq!(
        load(&environment).environment["CXXSTDLIB_x86_64_unknown_motor"],
        ""
    );
    environment.remove("CXXSTDLIB_x86_64_unknown_motor");
    let local = root.join(".cargo/config.toml");
    fs::write(
        &local,
        "[env]\nCXXSTDLIB_x86_64_unknown_motor = \"workspace\"\n",
    )
    .unwrap();
    let config = load(&environment);
    assert_eq!(
        config.environment["CXXSTDLIB_x86_64_unknown_motor"],
        "workspace"
    );
    assert_eq!(config.cargo_trust.len(), 1);
    assert_eq!(config.cargo_trust[0].file, local);
    fs::remove_file(local).unwrap();

    let home = temp.0.join("explicit-cargo-home");
    fs::create_dir(&home).unwrap();
    fs::write(
        home.join("config.toml"),
        "[env]\nCUSTOM_CARGO_HOME = \"selected\"\n",
    )
    .unwrap();
    environment.insert("CARGO_HOME".into(), home.display().to_string());
    let config = load(&environment);
    assert_eq!(config.environment.len(), 1);
    assert_eq!(config.environment["CUSTOM_CARGO_HOME"], "selected");
    assert!(config.cargo_trust.is_empty());
}
