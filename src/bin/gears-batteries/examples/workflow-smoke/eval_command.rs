//! Criteria use frozen original programs, literal arguments and each copied cwd.

use gears::process::Cancellation;
use gears_batteries::eval_command;
use std::{path::Path, time::Duration};

pub fn run_fixture(root: &Path, compiler: &str) -> Result<(), String> {
    std::fs::create_dir_all(root.join("programs")).unwrap();
    std::fs::create_dir(root.join("copy")).unwrap();
    let source = root.join("programs/judge.rs");
    std::fs::write(&source,r#"fn main(){
        assert_eq!(std::env::args().nth(1).unwrap(),"literal a*;echo");
        assert_eq!(std::env::current_dir().unwrap(),std::path::PathBuf::from(std::env::var("GEARS_EVAL_WORKSPACE").unwrap()));
        assert!(std::env::var_os("OPENROUTER_API_KEY").is_none());
        assert_eq!(std::fs::read("answer*").unwrap(),b"accepted");
    }"#).unwrap();
    let compiled = eval_command::run(
        &[
            compiler.into(),
            source.display().to_string(),
            "-o".into(),
            root.join("programs/judge").display().to_string(),
        ],
        root,
        root,
        Duration::from_secs(60),
        &Cancellation::new(),
    )?;
    assert_eq!(compiled["passed"], true, "{compiled}");
    std::fs::write(root.join("copy/answer*"), "accepted").unwrap();
    let argv = vec!["./judge".into(), "literal a*;echo".into()];
    let check = eval_command::run(
        &argv,
        &root.join("programs"),
        &root.join("copy"),
        Duration::from_secs(30),
        &Cancellation::new(),
    )?;
    assert_eq!(check["passed"], true, "{check}");
    std::fs::write(root.join("copy/answer*"), "wrong").unwrap();
    let rejected = eval_command::run(
        &argv,
        &root.join("programs"),
        &root.join("copy"),
        Duration::from_secs(30),
        &Cancellation::new(),
    )?;
    assert_eq!(rejected["passed"], false);
    let missing = eval_command::run(
        &["./missing".into()],
        &root.join("programs"),
        root,
        Duration::from_secs(1),
        &Cancellation::new(),
    )?;
    assert_eq!(missing["passed"], false);
    assert_eq!(missing["started"], false);
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
