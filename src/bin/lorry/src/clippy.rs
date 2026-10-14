use std::path::{Path, PathBuf};

pub const ARG_SEPARATOR: &str = "__CLIPPY_HACKERY__";

pub fn configuration_candidates(
    manifest_dir: &Path,
    working_dir: &Path,
    arguments: &str,
    primary: bool,
) -> Vec<PathBuf> {
    if !primary
        && arguments
            .split(ARG_SEPARATOR)
            .any(|argument| argument == "--no-deps")
    {
        return Vec::new();
    }
    let start = std::env::var_os("CLIPPY_CONF_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.to_owned());
    let start = if start.is_absolute() {
        start
    } else {
        working_dir.join(start)
    };
    candidates_from(&start)
}

fn candidates_from(start: &Path) -> Vec<PathBuf> {
    // The driver reports an invalid starting directory itself; no successful
    // compiler result can become fresh in that case.
    let Ok(mut directory) = std::fs::canonicalize(start) else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    loop {
        let pair = [
            directory.join(".clippy.toml"),
            directory.join("clippy.toml"),
        ];
        let found = pair.iter().any(|path| path.is_file());
        candidates.extend(pair);
        if found || !directory.pop() {
            return candidates;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_search_tracks_nearer_files_and_both_spellings() {
        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = std::env::temp_dir().join(format!(
            "lorry-clippy-conf-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let fixture = Fixture(root);
        let member = fixture.0.join("workspace/member");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(fixture.0.join("clippy.toml"), "").unwrap();
        let above = candidates_from(&member);
        assert!(above.contains(&member.join(".clippy.toml")));
        assert!(above.contains(&member.join("clippy.toml")));
        assert_eq!(above.last(), Some(&fixture.0.join("clippy.toml")));
        std::fs::write(member.join(".clippy.toml"), "").unwrap();
        let nearer = candidates_from(&member);
        assert_eq!(
            nearer,
            [member.join(".clippy.toml"), member.join("clippy.toml")]
        );
        std::fs::write(member.join("clippy.toml"), "").unwrap();
        assert_eq!(candidates_from(&member), nearer);
        std::fs::remove_file(member.join(".clippy.toml")).unwrap();
        std::fs::remove_file(member.join("clippy.toml")).unwrap();
        assert_eq!(candidates_from(&member), above);
    }
}
