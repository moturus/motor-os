//! Budgets and a quality criterion are required before any evaluation side effects.

use gears_batteries::eval_options::Options;
use std::path::Path;

pub fn run_fixture(root: &Path) -> Result<(), String> {
    let args = vec![
        "eval".into(),
        "--task".into(),
        "first.toml".into(),
        "--task".into(),
        "second.toml".into(),
        "--config".into(),
        "eval.toml".into(),
        "--root".into(),
        root.display().to_string(),
        "--gears".into(),
        "./gears".into(),
        "--provider".into(),
        "local".into(),
        "--model".into(),
        "chosen-model".into(),
        "--trials".into(),
        "2".into(),
        "--seconds".into(),
        "60".into(),
        "--command-seconds".into(),
        "30".into(),
        "--criterion".into(),
        "More accepted tasks with no regressions.".into(),
        "--output".into(),
        "fresh-output".into(),
    ];
    let options = Options::parse(&args)?;
    assert_eq!(options.tasks.len(), 2);
    assert_eq!(options.settings.repetitions, 2);
    for flag in ["--trials", "--seconds", "--command-seconds", "--criterion"] {
        let index = args.iter().position(|s| s == flag).unwrap();
        let mut bad = args.clone();
        bad[index + 1] = if flag == "--criterion" {
            " ".into()
        } else {
            "0".into()
        };
        assert!(Options::parse(&bad).is_err());
        let mut missing = args.clone();
        missing.drain(index..=index + 1);
        assert!(Options::parse(&missing).is_err());
    }
    let mut duplicate = args.clone();
    duplicate.extend(["--model".into(), "extra".into()]);
    assert!(Options::parse(&duplicate).is_err());
    let mut excessive = args.clone();
    for _ in 0..31 {
        excessive.extend(["--task".into(), "extra.toml".into()]);
    }
    assert!(Options::parse(&excessive).is_err());
    assert!(Options::parse(&["eval".into()]).is_err());
    assert!(!root.exists());
    Ok(())
}
