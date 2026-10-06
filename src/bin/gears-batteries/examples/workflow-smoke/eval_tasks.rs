//! User-authored task criteria, relative sources and byte identities stay explicit.

use gears_batteries::eval_task;
use std::path::Path;

pub fn run_fixture(workspace: &Path, root: &Path) -> Result<(), String> {
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let path = root.join("literal-task.toml");
    let task = format!(
        "version=1\nworkspace={:?}\nprompt='Fix the literal fixture.'\nexclude=['target', '.git']\ncheck=['rustc', 'a file*', '--crate-type=lib']\nacceptance=[['judge', 'literal a*', '']]\nregressions=[['regression', '--offline']]\n",
        workspace
    );
    std::fs::write(&path, &task).map_err(|e| e.to_string())?;
    let loaded = eval_task::load(&path)?;
    assert_eq!(loaded.name, "literal-task");
    assert_eq!(loaded.task.workspace, workspace);
    assert_eq!(loaded.task.check[1], "a file*");
    assert_eq!(loaded.task.acceptance[0][2], "");
    assert_eq!(
        loaded.hash,
        gears_batteries::snapshot::digest(task.as_bytes())
    );
    std::fs::write(
        &path,
        task.replace("Fix the literal fixture.", "A different prompt."),
    )
    .unwrap();
    assert_ne!(eval_task::load(&path)?.hash, loaded.hash);
    let relative = task.replace(
        &format!("workspace={workspace:?}"),
        "workspace='../workspace'",
    );
    std::fs::write(&path, relative).unwrap();
    assert_eq!(eval_task::load(&path)?.task.workspace, workspace);
    for invalid in [
        task.replace("version=1", "version=2"),
        task.replace(
            "check=['rustc', 'a file*', '--crate-type=lib']",
            "check=['sh', '-c', 'true']",
        ),
        task.replace("prompt='Fix the literal fixture.'", "prompt='   '"),
        task.replace(
            "regressions=[['regression', '--offline']]",
            "regressions=[]",
        ),
        task.replace(
            "acceptance=[['judge', 'literal a*', '']]",
            "acceptance=[[]]",
        ),
        task.replace("exclude=['target', '.git']", "exclude=['../outside']"),
        task.replace("exclude=['target', '.git']", "exclude=['/outside']"),
        format!("{task}extra=true\n"),
    ] {
        std::fs::write(&path, invalid).unwrap();
        assert!(eval_task::load(&path).is_err());
    }
    std::fs::write(&path, "x".repeat(65537)).unwrap();
    assert!(eval_task::load(&path).is_err());
    #[cfg(unix)]
    {
        std::fs::write(&path, &task).unwrap();
        let link = root.join("linked-task.toml");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(eval_task::load(&link).is_err());
    }
    std::fs::remove_dir_all(root).map_err(|e| e.to_string())
}
