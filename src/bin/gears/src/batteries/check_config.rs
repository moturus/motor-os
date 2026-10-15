//! One workspace declaration, selected without consulting parent directories.

use std::io::Read;
use std::path::Path;

use serde::Deserialize;

use crate::batteries::paths::ToolContext;

#[derive(Deserialize)]
struct Configuration {
    check: Option<Declaration>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Declaration {
    Common(Vec<String>),
    Platforms(Platforms),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Platforms {
    common: Option<Vec<String>>,
    linux: Option<Vec<String>>,
    motor: Option<Vec<String>>,
}

pub fn system() -> &'static str {
    if cfg!(unix) { "linux" } else { "motor" }
}

pub fn load(context: &ToolContext, system: &str) -> Result<Option<Vec<String>>, String> {
    // Not followed through links: the check must be declared in this workspace.
    let Some(path) = crate::state::StateRoot::new(context.workspace.join(".gears"))?
        .existing_file(Path::new("batteries.toml"))?
    else {
        return Ok(None);
    };
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 65536 {
        return Err("workspace batteries.toml exceeds 64 KiB".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "workspace batteries.toml is not UTF-8")?;
    let config: Configuration =
        toml::from_str(text).map_err(|error| format!("invalid batteries.toml: {error}"))?;
    let Some(declaration) = config.check else {
        return Ok(None);
    };
    let vector = match declaration {
        Declaration::Common(vector) => Some(vector),
        Declaration::Platforms(platforms) => match system {
            "linux" => platforms.linux.or(platforms.common),
            "motor" => platforms.motor.or(platforms.common),
            _ => return Err("unknown check platform".into()),
        },
    };
    if let Some(vector) = &vector {
        validate(vector)?;
    }
    Ok(vector)
}

pub(crate) fn validate(vector: &[String]) -> Result<(), String> {
    if vector.is_empty()
        || vector.len() > 128
        || vector[0].is_empty()
        || vector.iter().any(|word| word.contains('\0'))
        || serde_json::to_vec(vector)
            .map_err(|error| error.to_string())?
            .len()
            > 8192
    {
        return Err(
            "check needs a nonempty program and at most 128 arguments / 8 KiB of JSON".into(),
        );
    }
    let program = Path::new(&vector[0])
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if matches!(program, "sh" | "bash" | "dash" | "rush")
        && vector
            .iter()
            .skip(1)
            .any(|word| word.starts_with('-') && !word.starts_with("--") && word[1..].contains('c'))
    {
        return Err("declare a check program or script directly, without shell -c".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_and_platform_vectors_are_literal_and_only_come_from_the_workspace() {
        let root =
            std::env::temp_dir().join(format!("batteries-check-config-{}", std::process::id()));
        std::fs::create_dir_all(root.join("workspace/.gears")).unwrap();
        let context = ToolContext::new(
            root.join("workspace"),
            root.join("state"),
            "s1".into(),
            None,
        )
        .unwrap();
        std::fs::create_dir_all(root.join(".gears")).unwrap();
        std::fs::write(root.join(".gears/batteries.toml"), "check = ['parent']").unwrap();
        assert_eq!(load(&context, "linux").unwrap(), None);
        let config = context.workspace.join(".gears/batteries.toml");
        std::fs::write(&config, "check = ['program', 'a file*', '--']").unwrap();
        assert_eq!(
            load(&context, "motor").unwrap().unwrap(),
            ["program", "a file*", "--"]
        );
        std::fs::write(
            &config,
            "[check]\ncommon = ['common']\nlinux = ['linux']\nmotor = ['motor']",
        )
        .unwrap();
        assert_eq!(load(&context, "linux").unwrap().unwrap(), ["linux"]);
        assert_eq!(load(&context, "motor").unwrap().unwrap(), ["motor"]);
        std::fs::write(&config, "[check]\nlinux = ['linux']").unwrap();
        assert_eq!(load(&context, "motor").unwrap(), None);
        for invalid in [
            "check = []",
            "check = ['']",
            "check = ['sh', '-c', 'true']",
            "check = [1]",
            "[check]\ntypo = ['x']",
        ] {
            std::fs::write(&config, invalid).unwrap();
            assert!(load(&context, "linux").is_err(), "{invalid}");
        }
        std::fs::remove_file(&config).unwrap();
        std::fs::create_dir(&config).unwrap();
        assert!(
            load(&context, "linux")
                .unwrap_err()
                .contains("regular file")
        );
        std::fs::remove_dir(&config).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join(".gears/batteries.toml"), &config).unwrap();
            assert!(
                load(&context, "linux")
                    .unwrap_err()
                    .contains("found symlink")
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
