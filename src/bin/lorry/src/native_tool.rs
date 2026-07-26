use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::PathBuf;

use crate::config::{NativeTool, NativeToolRole};
use crate::diagnostic::{Error, Result};
use crate::sandbox::Executable;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Projection {
    pub environment: BTreeMap<String, OsString>,
    pub executables: Vec<Executable>,
}

pub fn project(
    configured: &BTreeMap<(String, NativeToolRole), NativeTool>,
    granted: &BTreeSet<NativeToolRole>,
    target: &str,
) -> Result<Projection> {
    let mut projection = Projection::default();
    let suffix = target
        .chars()
        .map(|character| match character {
            '-' | '.' => '_',
            _ => character,
        })
        .collect::<String>();

    for role in granted {
        let tool = configured
            .get(&(target.to_owned(), *role))
            .ok_or_else(|| missing_tool(target, *role))?;
        let program = tool
            .program
            .as_ref()
            .ok_or_else(|| missing_tool(target, *role))?;
        validate_program(program, target, *role)?;

        let (program_variable, flags_variable) = match role {
            NativeToolRole::CCompiler => ("CC", "CFLAGS"),
            NativeToolRole::Archiver => ("AR", "ARFLAGS"),
        };
        projection.environment.insert(
            format!("{program_variable}_{suffix}"),
            command_value(program.as_os_str(), &tool.prefix_args),
        );
        projection.environment.insert(
            format!("{flags_variable}_{suffix}"),
            OsString::from(tool.flags.join(" ")),
        );
        projection.executables.push(Executable {
            path: program.clone(),
            argument_prefix: tool.prefix_args.iter().map(OsString::from).collect(),
        });
    }
    Ok(projection)
}

fn command_value(program: &OsStr, prefix_args: &[String]) -> OsString {
    let mut value = program.to_owned();
    for argument in prefix_args {
        value.push(" ");
        value.push(argument);
    }
    value
}

fn validate_program(program: &PathBuf, target: &str, role: NativeToolRole) -> Result<()> {
    if program
        .as_os_str()
        .to_string_lossy()
        .bytes()
        .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return Err(Error::failure(format!(
            "configured native {} for target `{target}` has whitespace or NUL in its program path",
            role_name(role)
        )));
    }
    let metadata = fs::metadata(program).map_err(|error| {
        Error::failure(format!(
            "failed to inspect configured native {} `{}` for target `{target}`: {error}",
            role_name(role),
            program.display()
        ))
    })?;
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = true;
    if !metadata.is_file() || !executable {
        return Err(Error::failure(format!(
            "configured native {} `{}` for target `{target}` is not a regular executable file",
            role_name(role),
            program.display()
        )));
    }
    Ok(())
}

fn missing_tool(target: &str, role: NativeToolRole) -> Error {
    let role = role_name(role);
    Error::failure(format!(
        "package is granted native {role}, but target `{target}` has no complete `native-tools.\"{target}\".{role}` configuration"
    ))
    .with_help(format!(
        "configure `native-tools.\"{target}\".{role}.program` in lorry.toml"
    ))
}

fn role_name(role: NativeToolRole) -> &'static str {
    match role {
        NativeToolRole::CCompiler => "c-compiler",
        NativeToolRole::Archiver => "archiver",
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn executable() -> PathBuf {
        std::env::current_exe().unwrap()
    }

    #[test]
    fn projects_only_granted_target_specific_cc_variables() {
        let target = "x86_64-unknown.motor";
        let compiler = NativeTool {
            program: Some(executable()),
            prefix_args: vec!["clang".to_owned()],
            flags: vec!["--target=x86_64-unknown-motor".to_owned()],
        };
        let archiver = NativeTool {
            program: Some(executable()),
            prefix_args: vec!["ar".to_owned()],
            flags: Vec::new(),
        };
        let configured = BTreeMap::from([
            (
                (target.to_owned(), NativeToolRole::CCompiler),
                compiler.clone(),
            ),
            ((target.to_owned(), NativeToolRole::Archiver), archiver),
        ]);
        let projection = project(
            &configured,
            &BTreeSet::from([NativeToolRole::CCompiler]),
            target,
        )
        .unwrap();

        let suffix = "x86_64_unknown_motor";
        assert_eq!(
            projection.environment[&format!("CC_{suffix}")],
            command_value(
                compiler.program.as_ref().unwrap().as_os_str(),
                &compiler.prefix_args
            )
        );
        assert_eq!(
            projection.environment[&format!("CFLAGS_{suffix}")],
            "--target=x86_64-unknown-motor"
        );
        assert_eq!(projection.environment.len(), 2);
        assert_eq!(projection.executables.len(), 1);
        assert_eq!(
            projection.executables[0].argument_prefix,
            [OsString::from("clang")]
        );
    }

    #[test]
    fn rejects_missing_or_non_executable_granted_tools() {
        let granted = BTreeSet::from([NativeToolRole::Archiver]);
        let error = project(&BTreeMap::new(), &granted, "test-target").unwrap_err();
        assert!(error.to_string().contains("native-tools"));

        let configured = BTreeMap::from([(
            ("test-target".to_owned(), NativeToolRole::Archiver),
            NativeTool {
                program: Some(std::env::temp_dir().join("lorry-missing-native-tool")),
                prefix_args: Vec::new(),
                flags: Vec::new(),
            },
        )]);
        let error = project(&configured, &granted, "test-target").unwrap_err();
        assert!(error.to_string().contains("failed to inspect"));
    }
}
