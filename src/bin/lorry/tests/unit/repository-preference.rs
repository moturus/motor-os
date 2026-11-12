#[test]
fn role_source_preference_keeps_local_first_and_falls_back() {
    let root = TempDir::new("preference");
    let local = root.0.join("local");
    let user = root.0.join("user");
    let none = root.0.join("none");
    for path in [&local, &user, &none] {
        repository(path);
    }
    let (checksum, _) = registry_object(&user, b"same archive");
    let mut config = configurations(Some(&local), Some(&none));
    config.user = Some(user);
    let selected = |config: &Repositories| {
        RepositorySet::open(config, crate::source_tree::DEFAULT_LIMITS, 1024)
            .unwrap()
            .lookup_registry(&checksum)
            .unwrap()
            .unwrap()
            .layer
    };
    assert_eq!(selected(&config), Layer::User);
    registry_object(&none, b"same archive");
    assert_eq!(selected(&config), Layer::None);
    config.prefer_user_vendored_sources = true;
    assert_eq!(selected(&config), Layer::User);
    registry_object(&local, b"same archive");
    assert_eq!(selected(&config), Layer::Local);
    config.prefer_user_vendored_sources = false;
    assert_eq!(selected(&config), Layer::Local);
}
