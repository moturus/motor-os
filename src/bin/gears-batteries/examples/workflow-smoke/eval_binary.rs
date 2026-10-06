//! Pinned executable siblings keep their identities and native execute permissions.

use gears::{
    process::{self, Cancellation, Request},
    state::StateRoot,
};
use gears_batteries::eval_binary;
use std::{path::Path, time::Duration};

pub fn run_fixture(root: &Path, batteries: &Path, gears: &Path) -> Result<(), String> {
    let state = StateRoot::new(root.into())?;
    let manifest = eval_binary::pin(&state, gears, batteries)?;
    for name in ["gears", "gears-batteries"] {
        assert_eq!(manifest[name]["hash"].as_str().unwrap().len(), 64);
        assert!(manifest[name]["bytes"].as_u64().unwrap() > 0);
        let result = process::run(
            &Request {
                program: root.join("bin").join(name).display().to_string(),
                args: vec!["--help".into()],
                cwd: root.into(),
                stdin: None,
                timeout: Duration::from_secs(30),
                max_output_bytes: 8192,
                env: vec![],
                remove_env: vec![],
            },
            &Cancellation::new(),
            &mut |_, _| {},
        )
        .map_err(|e| e.to_string())?;
        assert!(result.success(), "{result:?}");
    }
    assert!(eval_binary::pin(&state, gears, batteries).is_err());
    let invalid = StateRoot::new(root.join("invalid"))?;
    assert!(eval_binary::pin(&invalid, root, batteries).is_err());
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
