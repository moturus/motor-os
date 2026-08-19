use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::{NativeTool, NativeToolRole};
use crate::diagnostic::{Error, Result};
use crate::sandbox::Executable;
use crate::unit::SourceRemap;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Projection {
    pub environment: BTreeMap<String, OsString>,
    pub executables: Vec<Executable>,
    pub read_only: Vec<PathBuf>,
}

pub fn project(
    configured: &BTreeMap<(String, NativeToolRole), NativeTool>,
    granted: &BTreeSet<NativeToolRole>,
    target: &str,
    source_remap: Option<&SourceRemap>,
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
        let mut flags = tool.flags.iter().map(OsString::from).collect::<Vec<_>>();
        if *role == NativeToolRole::CCompiler
            && let Some(remap) = source_remap
        {
            flags.push(native_remap_argument(remap)?);
        }
        projection
            .environment
            .insert(format!("{flags_variable}_{suffix}"), join_arguments(&flags));
        projection.executables.push(Executable {
            path: program.clone(),
            argument_prefix: tool.prefix_args.iter().map(OsString::from).collect(),
        });
        if *role == NativeToolRole::CCompiler {
            projection
                .read_only
                .extend(compiler_read_only(program, &tool.flags)?);
        }
    }
    projection.read_only.sort();
    projection.read_only.dedup();
    Ok(projection)
}

fn compiler_read_only(program: &Path, flags: &[String]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    if let Some(resources) = program
        .parent()
        .and_then(std::path::Path::parent)
        .map(|root| root.join("lib"))
        .filter(|path| path.is_dir())
    {
        paths.push(fs::canonicalize(&resources).map_err(|error| {
            Error::failure(format!(
                "failed to resolve native C compiler resources `{}`: {error}",
                resources.display()
            ))
        })?);
    }
    for flag in flags {
        let Some(path) = flag.strip_prefix("--sysroot=") else {
            continue;
        };
        let path = PathBuf::from(path);
        if !path.is_absolute() || !path.is_dir() {
            return Err(Error::failure(format!(
                "configured native C compiler sysroot `{}` is not an absolute directory",
                path.display()
            )));
        }
        paths.push(fs::canonicalize(&path).map_err(|error| {
            Error::failure(format!(
                "failed to resolve native C compiler sysroot `{}`: {error}",
                path.display()
            ))
        })?);
    }
    Ok(paths)
}

fn native_remap_argument(remap: &SourceRemap) -> Result<OsString> {
    if [&remap.physical_root, &remap.presented_root]
        .into_iter()
        .any(|root| {
            root.as_os_str()
                .as_encoded_bytes()
                .iter()
                .any(|byte| *byte == 0 || byte.is_ascii_whitespace())
        })
    {
        return Err(Error::failure(
            "source roots with whitespace or NUL cannot be represented safely in native compiler flags",
        ));
    }
    let mut argument = OsString::from("-ffile-prefix-map=");
    argument.push(&remap.physical_root);
    argument.push("=");
    argument.push(&remap.presented_root);
    Ok(argument)
}

fn join_arguments(arguments: &[OsString]) -> OsString {
    let mut value = OsString::new();
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            value.push(" ");
        }
        value.push(argument);
    }
    value
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
            None,
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
        assert!(projection.read_only.is_empty());
        assert_eq!(
            projection.executables[0].argument_prefix,
            [OsString::from("clang")]
        );
    }

    #[test]
    fn rejects_missing_or_non_executable_granted_tools() {
        let granted = BTreeSet::from([NativeToolRole::Archiver]);
        let error = project(&BTreeMap::new(), &granted, "test-target", None).unwrap_err();
        assert!(error.to_string().contains("native-tools"));

        let configured = BTreeMap::from([(
            ("test-target".to_owned(), NativeToolRole::Archiver),
            NativeTool {
                program: Some(std::env::temp_dir().join("lorry-missing-native-tool")),
                prefix_args: Vec::new(),
                flags: Vec::new(),
            },
        )]);
        let error = project(&configured, &granted, "test-target", None).unwrap_err();
        assert!(error.to_string().contains("failed to inspect"));
    }

    #[test]
    fn exposes_only_the_granted_compiler_resources_and_sysroot() {
        let root =
            std::env::temp_dir().join(format!("lorry-native-sysroot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let target = "x86_64-unknown-motor";
        let configured = BTreeMap::from([(
            (target.to_owned(), NativeToolRole::CCompiler),
            NativeTool {
                program: Some(executable()),
                prefix_args: Vec::new(),
                flags: vec![format!("--sysroot={}", root.display())],
            },
        )]);
        let projection = project(
            &configured,
            &BTreeSet::from([NativeToolRole::CCompiler]),
            target,
            None,
        )
        .unwrap();
        assert!(
            projection
                .read_only
                .contains(&fs::canonicalize(&root).unwrap())
        );

        let ungranted = project(&configured, &BTreeSet::new(), target, None).unwrap();
        assert!(ungranted.read_only.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn adds_scoped_file_prefix_mapping_only_to_c_compiler_flags() {
        let target = "x86_64-unknown-linux-gnu";
        let executable = executable();
        let configured = BTreeMap::from([
            (
                (target.to_owned(), NativeToolRole::CCompiler),
                NativeTool {
                    program: Some(executable.clone()),
                    prefix_args: Vec::new(),
                    flags: vec!["-O2".to_owned()],
                },
            ),
            (
                (target.to_owned(), NativeToolRole::Archiver),
                NativeTool {
                    program: Some(executable),
                    prefix_args: Vec::new(),
                    flags: vec!["crs".to_owned()],
                },
            ),
        ]);
        let remap = SourceRemap::required_patch(
            PathBuf::from("/workspace").as_path(),
            PathBuf::from("/workspace/.lorry/vendor/ring/source").as_path(),
            PathBuf::from("/repository/ring/source").as_path(),
        )
        .unwrap();
        let projection = project(
            &configured,
            &BTreeSet::from([NativeToolRole::CCompiler, NativeToolRole::Archiver]),
            target,
            Some(&remap),
        )
        .unwrap();
        assert_eq!(
            projection.environment["CFLAGS_x86_64_unknown_linux_gnu"],
            "-O2 -ffile-prefix-map=/repository/ring/source=.lorry/vendor/ring/source"
        );
        assert_eq!(
            projection.environment["ARFLAGS_x86_64_unknown_linux_gnu"],
            "crs"
        );
    }
}
