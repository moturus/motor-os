mod support;

#[cfg(unix)]
use std::fs;
use support::{Project, artifacts};

#[test]
fn member_build_script_uses_native_compiler_environment_and_tracks_inputs() {
    let p = Project::new();
    let tools = Project::new();
    p.write(
        "Cargo.toml",
        "[workspace]\nmembers=[\"grammar\"]\nresolver=\"2\"\n",
    );
    p.package("grammar", "grammar", "");
    p.write("grammar/src/main.rs", "unsafe extern \"C\" { fn grammar_scanner() -> i32; }\nfn main() { assert_eq!(unsafe { grammar_scanner() }, include!(concat!(env!(\"OUT_DIR\"), \"/generated.rs\"))); }\n");
    p.write("grammar/scanner.h", "#define GRAMMAR_VALUE 42\n");
    p.write("grammar/scanner.cc", "#include \"scanner.h\"\nnamespace grammar { constexpr int value = GRAMMAR_VALUE; }\nextern \"C\" int grammar_scanner() { return grammar::value; }\n");
    p.write(
        "grammar/build.rs",
        r#"
use std::{env, fs, path::PathBuf, process::Command};
fn main() {
    let suffix = env::var("TARGET").unwrap().replace(['-', '.'], "_");
    assert_eq!(env::var(format!("CXXSTDLIB_{suffix}")).unwrap(), "");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    fs::write(out.join("generated.rs"), "42").unwrap();
    let compiler = env::var_os(format!("CXX_{suffix}")).unwrap();
    let archiver = env::var_os(format!("AR_{suffix}")).unwrap();
    assert!(Command::new(compiler).args(["-std=c++17", "-c", "scanner.cc", "-o"])
        .arg(out.join("scanner.o")).status().unwrap().success());
    assert!(Command::new(archiver).arg("crs").arg(out.join("libscanner.a"))
        .arg(out.join("scanner.o")).status().unwrap().success());
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=scanner");
    println!("cargo:rerun-if-changed=scanner.cc");
    println!("cargo:rerun-if-changed=scanner.h");
}
"#,
    );
    p.lock(&[("grammar", &[])]);
    p.admit();
    let target = if cfg!(target_os = "motor") {
        "x86_64_unknown_motor"
    } else {
        "x86_64_unknown_linux_gnu"
    };
    let compiler;
    let archiver;
    #[cfg(unix)]
    {
        let clang = fs::canonicalize("/usr/bin/clang++").unwrap();
        archiver = clang.parent().unwrap().join("llvm-ar");
        tools.write(
            "native tools/include/compiler.h",
            "#define CUSTOM_COMPILER_HEADER 1\n",
        );
        tools.write(
            "native tools/bin/custom-c++",
            format!(
                "#!/bin/sh\nexec {:?} -include {:?} \"$@\"\n",
                clang,
                tools.root.join("native tools/include/compiler.h")
            ),
        );
        compiler = tools.root.join("native tools/bin/custom-c++");
        support::executable_permissions(&compiler).unwrap();
    }
    #[cfg(target_os = "motor")]
    {
        compiler = std::path::PathBuf::from("/user/bin/dev/c++");
        archiver = std::path::PathBuf::from("/user/bin/dev/ar");
    }
    let build = |arguments: &[&str], through_path: bool| {
        let mut command = p.command(arguments);
        let selected = if through_path {
            compiler.file_name().unwrap()
        } else {
            compiler.as_os_str()
        };
        let mut paths = vec![compiler.parent().unwrap().to_owned()];
        paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
        let output = command
            .env(format!("CXX_{target}"), selected)
            .env(format!("CXXSTDLIB_{target}"), "")
            .env(format!("AR_{target}"), &archiver)
            .env("PATH", std::env::join_paths(paths).unwrap())
            .output()
            .unwrap();
        assert!(output.status.success(), "{arguments:?}: {output:?}");
        output
    };
    for through_path in [false, true] {
        build(&["run", "--offline"], through_path);
        let fresh = build(
            &["build", "--offline", "--message-format=json"],
            through_path,
        );
        assert!(artifacts(&fresh).iter().all(|a| a["fresh"] == true));
        build(&["check", "--offline"], through_path);
    }
    p.write("grammar/scanner.h", "#define GRAMMAR_VALUE 42 // edited\n");
    let rebuilt = build(&["build", "--offline"], false);
    assert!(String::from_utf8_lossy(&rebuilt.stderr).contains("Running build script grammar"));
    build(&["run", "--offline"], false);
    drop(tools);
}
