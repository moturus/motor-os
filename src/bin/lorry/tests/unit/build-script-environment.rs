#[test]
fn native_compiler_environment_preserves_cargo_variants_and_empty_values() {
    let caller = BTreeMap::from([
        ("PATH", "/tools"),
        ("CC", "cc"),
        ("HOST_CXX", "host-c++"),
        ("TARGET_AR", "target-ar"),
        ("CFLAGS_x86_64-unknown-motor", "-O2"),
        ("ARFLAGS_x86_64_unknown_motor", ""),
        ("RANLIB_x86_64_unknown_linux_gnu", "ranlib"),
        ("HOME", "/private"),
        ("CC_OTHER_SECRET", "private"),
    ]);
    let environment =
        tool_environment_with("x86_64-unknown-linux-gnu", "x86_64-unknown-motor", |name| {
            caller.get(name).map(OsString::from)
        });
    assert_eq!(environment.len(), 7);
    assert_eq!(environment["PATH"], "/tools");
    assert_eq!(environment["HOST_CXX"], "host-c++");
    assert_eq!(environment["TARGET_AR"], "target-ar");
    assert_eq!(environment["CFLAGS_x86_64-unknown-motor"], "-O2");
    assert_eq!(environment["ARFLAGS_x86_64_unknown_motor"], "");
    assert!(!environment.contains_key("CXX"));
}
