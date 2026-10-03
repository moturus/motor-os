#[test]
fn library_source_is_workspace_relative() {
    assert_eq!(app::source(), "app/src/lib.rs");
}
