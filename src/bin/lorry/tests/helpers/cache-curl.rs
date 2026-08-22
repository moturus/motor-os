use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const INDEX_PREFIX: &str = "https://index.crates.io/";
const ARCHIVE_PREFIX: &str = "https://static.crates.io/crates/";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Package {
    name: String,
    version: String,
    checksum: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lorry-cache-curl: {error}");
            ExitCode::from(22)
        }
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.first().is_some_and(|value| value == "prepare") {
        return prepare(&arguments[1..]);
    }
    serve(&arguments)
}

fn prepare(arguments: &[std::ffi::OsString]) -> Result<(), String> {
    if arguments.len() < 4 {
        return Err(
            "usage: lorry-cache-curl prepare CARGO_HOME ARCHIVE_CACHE OUTPUT LOCK...".to_owned(),
        );
    }
    let cargo_home = absolute(&arguments[0], "Cargo home")?;
    let archive_cache = absolute(&arguments[1], "archive cache")?;
    let output = absolute(&arguments[2], "fixture output")?;
    if output.exists() {
        return Err(format!(
            "fixture output `{}` already exists",
            output.display()
        ));
    }

    let mut packages = BTreeSet::new();
    for lock in &arguments[3..] {
        packages.extend(load_lock(Path::new(lock))?);
    }
    if packages.is_empty() {
        return Err("input lockfiles contain no crates.io packages".to_owned());
    }

    let index_roots = children(&cargo_home.join("registry/index"))?;
    let mut archive_roots = children(&cargo_home.join("registry/cache"))?;
    archive_roots.push(archive_cache);
    let mut by_name = BTreeMap::<String, Vec<Package>>::new();
    for package in packages {
        by_name
            .entry(package.name.clone())
            .or_default()
            .push(package);
    }

    for (name, packages) in &by_name {
        let relative = sparse_path(name)?;
        let mut records = Vec::new();
        for package in packages {
            records.push(find_record(&index_roots, &relative, package)?);
            if let Some(archive) = find_archive(&archive_roots, package)? {
                let destination = output
                    .join("archives")
                    .join(&package.name)
                    .join(format!("{}-{}.crate", package.name, package.version));
                create_parent(&destination)?;
                fs::copy(&archive, &destination).map_err(|error| {
                    format!(
                        "failed to copy Cargo archive `{}` to `{}`: {error}",
                        archive.display(),
                        destination.display()
                    )
                })?;
            }
        }
        let destination = output.join("index").join(relative);
        create_parent(&destination)?;
        let mut body = Vec::new();
        for record in records {
            body.extend_from_slice(&record);
            body.push(b'\n');
        }
        fs::write(&destination, body).map_err(|error| {
            format!(
                "failed to write sparse fixture `{}`: {error}",
                destination.display()
            )
        })?;
    }

    let executable =
        env::current_exe().map_err(|error| format!("failed to locate mock executable: {error}"))?;
    let installed = output.join("curl");
    fs::copy(&executable, &installed).map_err(|error| {
        format!(
            "failed to install mock executable at `{}`: {error}",
            installed.display()
        )
    })?;
    Ok(())
}

fn serve(arguments: &[std::ffi::OsString]) -> Result<(), String> {
    let url = option(arguments, "--url")?;
    let write_out = option(arguments, "--write-out")?;
    if option(arguments, "--output")? != "-" {
        return Err("mock accepts only `--output -`".to_owned());
    }
    let nonce = control_nonce(write_out)?;
    let executable =
        env::current_exe().map_err(|error| format!("failed to locate mock executable: {error}"))?;
    let root = executable
        .parent()
        .ok_or_else(|| "mock executable has no parent directory".to_owned())?;
    let path = if let Some(relative) = url.strip_prefix(INDEX_PREFIX) {
        safe_relative(relative)?;
        root.join("index").join(relative)
    } else if let Some(relative) = url.strip_prefix(ARCHIVE_PREFIX) {
        safe_relative(relative)?;
        root.join("archives").join(relative)
    } else {
        return Err(format!("request for non-crates.io URL `{url}` was denied"));
    };
    let body = fs::read(&path).map_err(|error| {
        format!(
            "request for unprepared crates.io fixture `{url}` (`{}`): {error}",
            path.display()
        )
    })?;
    io::stdout()
        .write_all(&body)
        .map_err(|error| format!("failed to write response body: {error}"))?;
    eprint!(
        "\nLORRY-CURL-1 {nonce}\nstatus=200\nurl={url}\nredirect=\nsize={}\nEND-LORRY-CURL-1 {nonce}\n",
        body.len()
    );
    Ok(())
}

fn load_lock(path: &Path) -> Result<BTreeSet<Package>, String> {
    let source = fs::read_to_string(path)
        .map_err(|error| format!("failed to read lockfile `{}`: {error}", path.display()))?;
    let mut packages = BTreeSet::new();
    let mut fields = BTreeMap::new();
    let mut in_package = false;
    for line in source.lines().chain(["[[package]]"]) {
        let line = line.trim();
        if line == "[[package]]" {
            if in_package {
                finish_package(path, &fields, &mut packages)?;
            }
            fields.clear();
            in_package = true;
            continue;
        }
        if !in_package {
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        if matches!(key, "name" | "version" | "source" | "checksum") {
            let value = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .ok_or_else(|| {
                    format!(
                        "lockfile `{}` has a non-string `{key}` field",
                        path.display()
                    )
                })?;
            fields.insert(key, value.to_owned());
        }
    }
    Ok(packages)
}

fn finish_package(
    path: &Path,
    fields: &BTreeMap<&str, String>,
    packages: &mut BTreeSet<Package>,
) -> Result<(), String> {
    if fields.get("source").map(String::as_str) != Some(REGISTRY_SOURCE) {
        return Ok(());
    }
    let field = |name| {
        fields.get(name).cloned().ok_or_else(|| {
            format!(
                "crates.io package in `{}` has no `{name}` field",
                path.display()
            )
        })
    };
    packages.insert(Package {
        name: field("name")?,
        version: field("version")?,
        checksum: field("checksum")?,
    });
    Ok(())
}

fn find_record(roots: &[PathBuf], relative: &Path, package: &Package) -> Result<Vec<u8>, String> {
    let name = format!("\"name\":\"{}\"", package.name);
    let version = format!("\"vers\":\"{}\"", package.version);
    let checksum = format!("\"cksum\":\"{}\"", package.checksum);
    let mut found = BTreeSet::new();
    for root in roots {
        let path = root.join(".cache").join(relative);
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        for field in bytes.split(|byte| *byte == 0) {
            if field.starts_with(b"{")
                && contains(field, name.as_bytes())
                && contains(field, version.as_bytes())
                && contains(field, checksum.as_bytes())
            {
                found.insert(field.to_vec());
            }
        }
    }
    if found.len() != 1 {
        return Err(format!(
            "Cargo sparse cache contains {} matching records for {} {} {}",
            found.len(),
            package.name,
            package.version,
            package.checksum
        ));
    }
    Ok(found.into_iter().next().unwrap())
}

fn find_archive(roots: &[PathBuf], package: &Package) -> Result<Option<PathBuf>, String> {
    let name = format!("{}-{}.crate", package.name, package.version);
    let matches = roots
        .iter()
        .map(|root| root.join(&name))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Ok(None),
        [path] => Ok(Some(path.clone())),
        [first, rest @ ..] => {
            let expected = fs::read(first).map_err(|error| {
                format!(
                    "failed to read Cargo archive `{}`: {error}",
                    first.display()
                )
            })?;
            for path in rest {
                let bytes = fs::read(path).map_err(|error| {
                    format!("failed to read Cargo archive `{}`: {error}", path.display())
                })?;
                if bytes != expected {
                    return Err(format!(
                        "Cargo caches contain different archives named `{name}`"
                    ));
                }
            }
            Ok(Some(first.clone()))
        }
    }
}

fn children(path: &Path) -> Result<Vec<PathBuf>, String> {
    let mut result = fs::read_dir(path)
        .map_err(|error| format!("failed to read Cargo cache `{}`: {error}", path.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            format!(
                "failed to enumerate Cargo cache `{}`: {error}",
                path.display()
            )
        })?;
    result.retain(|path| path.is_dir());
    result.sort();
    Ok(result)
}

fn sparse_path(name: &str) -> Result<PathBuf, String> {
    let name = name.to_ascii_lowercase();
    safe_component(&name)?;
    Ok(match name.len() {
        1 => PathBuf::from("1").join(name),
        2 => PathBuf::from("2").join(name),
        3 => PathBuf::from("3").join(&name[..1]).join(name),
        _ => PathBuf::from(&name[..2]).join(&name[2..4]).join(name),
    })
}

fn option<'a>(arguments: &'a [std::ffi::OsString], name: &str) -> Result<&'a str, String> {
    let position = arguments
        .iter()
        .position(|value| value == name)
        .ok_or_else(|| format!("request is missing `{name}`"))?;
    arguments
        .get(position + 1)
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("request has no UTF-8 value after `{name}`"))
}

fn control_nonce(write_out: &str) -> Result<&str, String> {
    let marker = "LORRY-CURL-1 ";
    let start = write_out
        .find(marker)
        .map(|position| position + marker.len())
        .ok_or_else(|| "request write-out has no Lorry control marker".to_owned())?;
    let nonce = write_out
        .get(start..start + 32)
        .ok_or_else(|| "request write-out has a truncated control nonce".to_owned())?;
    if !nonce
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("request write-out has an invalid control nonce".to_owned());
    }
    Ok(nonce)
}

fn safe_relative(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.starts_with('/')
        || value.split('/').any(|part| safe_component(part).is_err())
    {
        return Err(format!("request contains unsafe fixture path `{value}`"));
    }
    Ok(())
}

fn safe_component(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
    {
        return Err(format!("unsafe fixture component `{value}`"));
    }
    Ok(())
}

fn create_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path `{}` has no parent", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create `{}`: {error}", parent.display()))
}

fn absolute(value: &OsStr, description: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!(
            "{description} `{}` is not absolute",
            path.display()
        ));
    }
    Ok(path)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}
