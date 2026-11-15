type HarnessNode = (String, String, String, String, bool, String, Vec<String>);
type HarnessEdges = BTreeSet<(HarnessNode, HarnessNode, String)>;

// These expectations describe the Cargo-compatible graph of the generated
// a/b dev cycle, including the macro's distinct host and selected profiles.
fn expected_harness_graph(
    integration: Option<&str>,
    cross: bool,
    checking: bool,
    opt: &str,
) -> (BTreeSet<HarnessNode>, HarnessEdges) {
    let normal = if checking { "check" } else { "build" };
    let harness = if checking { "check" } else { "test" };
    let mut nodes = BTreeMap::new();
    let mut add = |id,
                   package: &str,
                   kind: &str,
                   name: &str,
                   mode: &str,
                   target,
                   opt: &str,
                   features: &[&str]| {
        nodes.insert(
            id,
            (
                package.to_owned(),
                kind.to_owned(),
                name.to_owned(),
                mode.to_owned(),
                target && cross,
                opt.to_owned(),
                features.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            ),
        );
    };
    add("a", "a", "lib", "a", normal, true, opt, &["normal"]);
    add("b", "b", "lib", "b", normal, true, opt, &["dev"]);
    add(
        "integration",
        "a",
        "test",
        integration.unwrap_or("integration"),
        harness,
        true,
        opt,
        &["normal"],
    );
    add(
        "a-build",
        "a",
        "custom-build",
        "build-script-build",
        "build",
        false,
        "0",
        &["normal"],
    );
    add(
        "a-script",
        "a",
        "custom-build",
        "build-script-build",
        "run-custom-build",
        true,
        opt,
        &["normal"],
    );
    add(
        "macro",
        "derive",
        "proc-macro",
        "derive",
        "build",
        false,
        "0",
        &["default", "harness"],
    );
    add(
        "macro-build",
        "derive",
        "custom-build",
        "build-script-build",
        "build",
        false,
        "0",
        &["default", "harness"],
    );
    add(
        "macro-script",
        "derive",
        "custom-build",
        "build-script-build",
        "run-custom-build",
        false,
        "0",
        &["default", "harness"],
    );
    add(
        "host",
        "helper",
        "lib",
        "helper",
        "build",
        false,
        "0",
        &["build", "normal"],
    );
    add(
        "target",
        "helper",
        "lib",
        "helper",
        normal,
        true,
        opt,
        &["normal"],
    );
    if integration.is_none() || !checking {
        add("bin", "a", "bin", "a", normal, true, opt, &["normal"]);
    }
    if integration.is_none() {
        add("a-test", "a", "lib", "a", harness, true, opt, &["normal"]);
        add("b-test", "b", "lib", "b", harness, true, opt, &["dev"]);
        add("bin-test", "a", "bin", "a", harness, true, opt, &["normal"]);
        add(
            "macro-test",
            "derive",
            "proc-macro",
            "derive",
            harness,
            false,
            opt,
            &["default", "harness"],
        );
        add(
            "selected-script",
            "derive",
            "custom-build",
            "build-script-build",
            "run-custom-build",
            false,
            opt,
            &["default", "harness"],
        );
        if checking {
            add(
                "host-check",
                "helper",
                "lib",
                "helper",
                "check",
                false,
                "0",
                &["build", "normal"],
            );
        }
    }
    let mut edges = BTreeSet::new();
    let mut edge = |parent, dependency, alias: &str| {
        edges.insert((
            nodes[parent].clone(),
            nodes[dependency].clone(),
            alias.to_owned(),
        ));
    };
    for (parent, dependency, alias) in [
        ("a", "a-script", "build_script_build"),
        ("a", "macro", "derive"),
        ("a", "target", "helper"),
        ("b", "a", "a"),
        ("a-build", "host", "helper"),
        ("a-script", "a-build", "build_script_build"),
        ("macro", "macro-script", "build_script_build"),
        ("macro", "host", "helper"),
        ("macro-build", "host", "helper"),
        ("macro-script", "macro-build", "build_script_build"),
        ("integration", "a", "a"),
        ("integration", "b", "b"),
        ("integration", "a-script", "build_script_build"),
        ("integration", "macro", "derive"),
        ("integration", "target", "helper"),
    ] {
        edge(parent, dependency, alias);
    }
    if !checking {
        edge("integration", "bin", "a");
    }
    if integration.is_none() || !checking {
        for (dependency, alias) in [
            ("a", "a"),
            ("a-script", "build_script_build"),
            ("macro", "derive"),
            ("target", "helper"),
        ] {
            edge("bin", dependency, alias);
        }
    }
    if integration.is_none() {
        for parent in ["a-test", "bin-test"] {
            for (dependency, alias) in [
                ("b", "b"),
                ("a-script", "build_script_build"),
                ("macro", "derive"),
                ("target", "helper"),
            ] {
                edge(parent, dependency, alias);
            }
        }
        edge("bin-test", "a", "a");
        edge("b-test", "a", "a");
        edge("macro-test", "selected-script", "build_script_build");
        edge(
            "macro-test",
            if checking { "host-check" } else { "host" },
            "helper",
        );
        edge("selected-script", "macro-build", "build_script_build");
    }
    (nodes.into_values().collect(), edges)
}
