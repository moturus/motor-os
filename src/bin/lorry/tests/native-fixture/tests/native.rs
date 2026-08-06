#[test]
fn integration_test_links_the_library() {
    assert_eq!(
        lorry_native_fixture::value(),
        "registry|build-script|motor-target"
    );
}
