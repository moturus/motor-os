#[test]
fn reads_fallback_without_mutating_it_and_prefers_the_writable_cache() {
    let fixture = Fixture::new();
    let fallback = BuildCache::for_test(&fixture.0.join("user"));
    let mut cache = BuildCache::for_test(&fixture.0.join("none"));
    cache.read_only_units = Some(fallback.units.clone());
    let key = CacheKey([27; 32]);
    let built = output(&fixture.0.join("built"), b"fallback");
    fallback
        .store(
            key,
            &built,
            None,
            None,
            (b"", b""),
            &Tracked::new(),
            &test_owner(),
        )
        .unwrap();
    let before = Tree::scan(
        &fallback.entry_path(key),
        crate::source_tree::DEFAULT_LIMITS,
        Exclusions::None,
    )
    .unwrap();
    let entry = cache.verified_or_quarantine(key).unwrap().unwrap();
    assert!(entry.payload.starts_with(&fallback.units));
    cache.record_cache_owner(key, &test_owner()).unwrap();
    assert!(!cache.units.exists());
    assert_eq!(
        Tree::scan(
            &fallback.entry_path(key),
            crate::source_tree::DEFAULT_LIMITS,
            Exclusions::None
        )
        .unwrap(),
        before
    );
    let parent = cache.entry_path(key).parent().unwrap().to_owned();
    fs::create_dir_all(&parent).unwrap();
    fs::rename(fallback.entry_path(key), cache.entry_path(key)).unwrap();
    let entry = cache.verified_or_quarantine(key).unwrap().unwrap();
    assert!(entry.payload.starts_with(&cache.units));
}

#[test]
fn corrupt_read_only_entries_miss_and_rebuild_in_the_writable_cache() {
    let fixture = Fixture::new();
    let fallback = BuildCache::for_test(&fixture.0.join("user"));
    let mut cache = BuildCache::for_test(&fixture.0.join("none"));
    cache.read_only_units = Some(fallback.units.clone());
    let key = CacheKey([28; 32]);
    let built = output(&fixture.0.join("built"), b"rebuilt");
    fs::create_dir_all(fallback.entry_path(key)).unwrap();
    let corrupt = fallback.entry_path(key).join("incomplete");
    fs::write(&corrupt, b"leave this alone").unwrap();
    let restored = RustcOutput::Library {
        rlib: fixture.0.join("restored.rlib"),
        rmeta: fixture.0.join("restored.rmeta"),
        archive: None,
        dep_info: fixture.0.join("restored.d"),
    };
    assert!(cache.restore(key, &restored, None).unwrap().is_none());
    cache
        .store(
            key,
            &built,
            None,
            None,
            (b"", b""),
            &Tracked::new(),
            &test_owner(),
        )
        .unwrap();
    assert!(cache.restore(key, &restored, None).unwrap().is_some());
    assert_eq!(fs::read(corrupt).unwrap(), b"leave this alone");
    assert_eq!(fs::read_dir(fallback.entry_path(key)).unwrap().count(), 1);
    assert!(!fallback.quarantine.exists());

    // An invalid ancestor cannot be repaired from the build role either.
    let mut cache = BuildCache::for_test(&fixture.0.join("another-none"));
    cache.read_only_units = Some(fixture.0.join("not-a-directory"));
    fs::write(cache.read_only_units.as_ref().unwrap(), "keep").unwrap();
    assert!(cache.verified_or_quarantine(key).unwrap().is_none());
}
