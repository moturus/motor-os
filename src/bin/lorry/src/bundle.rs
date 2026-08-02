use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use crate::diagnostic::{Error, Result};
use crate::hash::{Sha256, hex, sha256_file};
use crate::process::RustcCommand;
use crate::source_tree::{Exclusions, Limits as TreeLimits, Tree};
use crate::toolchain::{TargetInfo, Toolchain};

const FORMAT_TAG: &[u8] = b"lorry-test-bundle-v1\0";

pub struct LayoutOptions<'a> {
    pub extraction_root: &'a Path,
    pub package_name: &'a str,
    pub package_root: &'a Path,
    pub lorry: &'a Path,
    pub toolchain: &'a Toolchain,
    pub target: &'a TargetInfo,
    pub release: bool,
    pub test_name: Option<&'a str>,
    pub source_limits: TreeLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Layout {
    extraction_root: PathBuf,
    directory: PathBuf,
    id: String,
}

pub struct BuildOptions<'a> {
    pub layout: &'a Layout,
    pub package_name: &'a str,
    pub package_root: &'a Path,
    pub staging: &'a Path,
    pub rustc: &'a Path,
    pub physical_target: Option<&'a str>,
    pub linker: Option<&'a Path>,
    pub rustflags: &'a [String],
    pub release: bool,
    pub verbose: bool,
    pub color: bool,
    pub harnesses: &'a [PathBuf],
    pub program: Option<(&'a str, &'a Path)>,
}

struct Payload<'a> {
    name: String,
    source: &'a Path,
    bytes: u64,
    sha256: [u8; 32],
    run: bool,
}

impl Layout {
    pub fn new(options: &LayoutOptions<'_>) -> Result<Self> {
        if !options.extraction_root.is_absolute() {
            return Err(Error::failure(format!(
                "test bundle extraction root `{}` is not absolute",
                options.extraction_root.display()
            ))
            .with_help("set `[test].extraction-root` to an absolute private directory"));
        }
        let source = Tree::scan(
            options.package_root,
            options.source_limits,
            Exclusions::GitAndTarget,
        )?;
        let mut digest = Digest::new();
        digest.field(FORMAT_TAG);
        digest.string(options.package_name);
        digest.field(&source.manifest_bytes());
        digest.field(&sha256_file(options.lorry)?);
        digest.field(&sha256_file(&options.toolchain.rustc)?);
        digest.string(&options.toolchain.verbose_version);
        digest.string(&options.target.triple);
        for (name, value) in options.target.cfg.cargo_environment() {
            digest.string(&name);
            digest.string(&value);
        }
        digest.string(if options.release { "release" } else { "debug" });
        digest.string(options.test_name.unwrap_or("<all>"));
        digest.field(options.extraction_root.as_os_str().as_encoded_bytes());
        let id = hex(&digest.finish());
        let directory = options
            .extraction_root
            .join(format!("{}-{id}", options.package_name));
        Ok(Self {
            extraction_root: options.extraction_root.to_owned(),
            directory,
            id,
        })
    }

    pub fn program(&self, name: &str) -> PathBuf {
        self.directory.join("bin").join(name)
    }

    pub fn temporary_directory(&self) -> PathBuf {
        self.directory.join("tmp")
    }
}

pub fn build(options: &BuildOptions<'_>) -> Result<PathBuf> {
    if options.harnesses.is_empty() {
        return Err(Error::failure("test bundle has no harness payloads"));
    }
    let mut payloads = Vec::new();
    if let Some((name, path)) = options.program {
        validate_payload_name(name)?;
        payloads.push(payload(format!("bin/{name}"), path, false)?);
    }
    for (index, path) in options.harnesses.iter().enumerate() {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                Error::failure(format!(
                    "test harness path is not UTF-8: `{}`",
                    path.display()
                ))
            })?;
        validate_payload_name(name)?;
        payloads.push(payload(format!("tests/{index:03}-{name}"), path, true)?);
    }
    let manifest = payload_manifest(options.layout, &payloads);
    let source = launcher_source(options.layout, &payloads, &manifest)?;
    let source_path = options.staging.join(".lorry-test-bundle.rs");
    fs::write(&source_path, source).map_err(|error| {
        Error::failure(format!(
            "failed to write generated test-bundle launcher `{}`: {error}",
            source_path.display()
        ))
    })?;
    let output = options
        .staging
        .join(format!("{}-test-bundle", options.package_name));
    let mut arguments = vec![
        "--crate-name".into(),
        format!("{}_test_bundle", options.package_name.replace('-', "_")).into(),
        "--edition=2024".into(),
        source_path.as_os_str().to_owned(),
        "--error-format=json".into(),
        "--json=diagnostic-rendered-ansi,future-incompat".into(),
        "-o".into(),
        output.as_os_str().to_owned(),
        "-C".into(),
        format!("metadata={}", &options.layout.id[..16]).into(),
    ];
    if options.release {
        arguments.extend([
            OsString::from("-C"),
            OsString::from("opt-level=3"),
            OsString::from("-C"),
            OsString::from("panic=abort"),
            OsString::from("-C"),
            OsString::from("strip=symbols"),
        ]);
    } else {
        arguments.extend([OsString::from("-C"), OsString::from("debuginfo=2")]);
    }
    if let Some(target) = options.physical_target {
        arguments.extend([OsString::from("--target"), target.into()]);
    }
    if let Some(linker) = options.linker {
        arguments.extend([
            OsString::from("-C"),
            format!("linker={}", linker.display()).into(),
        ]);
    }
    arguments.extend(options.rustflags.iter().map(OsString::from));
    let result = RustcCommand {
        program: options.rustc,
        arguments: &arguments,
        environment: &BTreeMap::new(),
        current_dir: options.package_root,
        verbose: options.verbose,
        color: options.color,
    }
    .run();
    let _ = fs::remove_file(&source_path);
    result?;
    if !output.is_file() {
        return Err(Error::failure(format!(
            "rustc succeeded but test bundle `{}` is missing",
            output.display()
        )));
    }
    Ok(output)
}

fn payload<'a>(name: String, source: &'a Path, run: bool) -> Result<Payload<'a>> {
    let metadata = fs::metadata(source).map_err(|error| {
        Error::failure(format!(
            "failed to inspect test-bundle payload `{}`: {error}",
            source.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(Error::failure(format!(
            "test-bundle payload `{}` is not a regular file",
            source.display()
        )));
    }
    Ok(Payload {
        name,
        source,
        bytes: metadata.len(),
        sha256: sha256_file(source)?,
        run,
    })
}

fn validate_payload_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains(['\n', '\r', '\t', '\0'])
    {
        return Err(Error::failure(format!(
            "unsafe test-bundle payload name `{name}`"
        )));
    }
    Ok(())
}

fn payload_manifest(layout: &Layout, payloads: &[Payload<'_>]) -> String {
    let mut manifest = format!("lorry-test-bundle-v1\nid\t{}\n", layout.id);
    for payload in payloads {
        manifest.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            if payload.run { "run" } else { "data" },
            payload.name,
            payload.bytes,
            hex(&payload.sha256)
        ));
    }
    manifest
}

fn launcher_source(layout: &Layout, payloads: &[Payload<'_>], manifest: &str) -> Result<String> {
    let extraction_root = layout.extraction_root.to_str().ok_or_else(|| {
        Error::failure(format!(
            "test extraction root is not UTF-8: `{}`",
            layout.extraction_root.display()
        ))
    })?;
    let directory = layout.directory.to_str().ok_or_else(|| {
        Error::failure(format!(
            "test extraction directory is not UTF-8: `{}`",
            layout.directory.display()
        ))
    })?;
    let mut table = String::new();
    for payload in payloads {
        let source = payload.source.to_str().ok_or_else(|| {
            Error::failure(format!(
                "test-bundle payload path is not UTF-8: `{}`",
                payload.source.display()
            ))
        })?;
        table.push_str(&format!(
            "    Payload {{ name: {:?}, bytes: include_bytes!({:?}), length: {}, sha256: {:?}, run: {} }},\n",
            payload.name, source, payload.bytes, payload.sha256, payload.run
        ));
    }
    Ok(format!(
        "const EXTRACTION_ROOT: &str = {extraction_root:?};\n\
         const EXTRACTION_DIRECTORY: &str = {directory:?};\n\
         const MANIFEST: &[u8] = {manifest:?}.as_bytes();\n\
         static PAYLOADS: &[Payload] = &[\n{table}];\n\n{LAUNCHER_RUNTIME}"
    ))
}

struct Digest(Sha256);

impl Digest {
    fn new() -> Self {
        Self(Sha256::new())
    }

    fn string(&mut self, value: &str) {
        self.field(value.as_bytes());
    }

    fn field(&mut self, value: &[u8]) {
        self.0.update(&(value.len() as u64).to_le_bytes());
        self.0.update(value);
    }

    fn finish(self) -> [u8; 32] {
        self.0.finish()
    }
}

const LAUNCHER_RUNTIME: &str = r#"
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Payload {
    name: &'static str,
    bytes: &'static [u8],
    length: u64,
    sha256: [u8; 32],
    run: bool,
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("error: test bundle: {error}");
            std::process::exit(101);
        }
    }
}

fn run() -> Result<i32, String> {
    verify_embedded()?;
    let root = Path::new(EXTRACTION_ROOT);
    ensure_directory_chain(root)?;
    set_private_directory(root)?;
    let extraction = Path::new(EXTRACTION_DIRECTORY);
    match fs::symlink_metadata(extraction) {
        Ok(_) => verify_extraction(extraction)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => extract(root, extraction)?,
        Err(error) => return Err(format!("failed to inspect `{}`: {error}", extraction.display())),
    }
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let mut failed = false;
    for payload in PAYLOADS.iter().filter(|payload| payload.run) {
        let executable = extraction.join(payload.name);
        eprintln!("Running {}", executable.display());
        match Command::new(&executable).args(&arguments).status() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                failed = true;
                match status.code() {
                    Some(code) => eprintln!("test harness `{}` failed with status {code}", payload.name),
                    None => eprintln!("test harness `{}` was terminated", payload.name),
                }
            }
            Err(error) => {
                failed = true;
                eprintln!("failed to run test harness `{}`: {error}", payload.name);
            }
        }
    }
    Ok(if failed { 1 } else { 0 })
}

fn verify_embedded() -> Result<(), String> {
    let mut names = BTreeSet::new();
    for payload in PAYLOADS {
        validate_name(payload.name)?;
        if !names.insert(payload.name) {
            return Err(format!("duplicate embedded payload `{}`", payload.name));
        }
        if payload.bytes.len() as u64 != payload.length
            || sha256(payload.bytes) != payload.sha256
        {
            return Err(format!("embedded payload `{}` failed verification", payload.name));
        }
    }
    if !PAYLOADS.iter().any(|payload| payload.run) {
        return Err("bundle contains no runnable harness".to_owned());
    }
    Ok(())
}

fn extract(root: &Path, destination: &Path) -> Result<(), String> {
    let label = destination.file_name().and_then(|name| name.to_str()).unwrap_or("bundle");
    for attempt in 0..100_u64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |value| value.as_nanos());
        let staging = root.join(format!(".{label}.staging-{}-{now:x}-{attempt:x}", std::process::id()));
        match fs::create_dir(&staging) {
            Ok(()) => {
                let mut guard = Staging { path: staging, committed: false };
                set_private_directory(&guard.path)?;
                fs::create_dir(guard.path.join("bin")).map_err(display("create payload bin directory"))?;
                fs::create_dir(guard.path.join("tests")).map_err(display("create payload tests directory"))?;
                fs::create_dir(guard.path.join("tmp")).map_err(display("create payload temporary directory"))?;
                set_private_directory(&guard.path.join("bin"))?;
                set_private_directory(&guard.path.join("tests"))?;
                set_private_directory(&guard.path.join("tmp"))?;
                for payload in PAYLOADS {
                    let path = guard.path.join(payload.name);
                    let mut file = OpenOptions::new().write(true).create_new(true).open(&path)
                        .map_err(display("create payload file"))?;
                    file.write_all(payload.bytes).map_err(display("write payload file"))?;
                    file.sync_all().map_err(display("persist payload file"))?;
                    set_private_executable(&path)?;
                }
                let manifest = guard.path.join("manifest");
                let mut file = OpenOptions::new().write(true).create_new(true).open(&manifest)
                    .map_err(display("create payload manifest"))?;
                file.write_all(MANIFEST).map_err(display("write payload manifest"))?;
                file.sync_all().map_err(display("persist payload manifest"))?;
                set_private_file(&manifest)?;
                match fs::rename(&guard.path, destination) {
                    Ok(()) => {
                        guard.committed = true;
                        return verify_extraction(destination);
                    }
                    Err(_) if destination.exists() => {
                        verify_extraction(destination)?;
                        return Ok(());
                    }
                    Err(error) => return Err(format!("failed to publish extraction: {error}")),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("failed to create extraction staging: {error}")),
        }
    }
    Err("could not allocate extraction staging".to_owned())
}

struct Staging {
    path: PathBuf,
    committed: bool,
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn verify_extraction(root: &Path) -> Result<(), String> {
    regular_directory(root, "extraction directory")?;
    let expected_top_level = ["bin", "manifest", "tests", "tmp"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut actual_top_level = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(display("read extraction directory"))? {
        let entry = entry.map_err(display("read extraction entry"))?;
        let name = entry.file_name().into_string()
            .map_err(|_| "extraction filename is not UTF-8".to_owned())?;
        actual_top_level.insert(name);
    }
    if actual_top_level.iter().map(String::as_str).collect::<BTreeSet<_>>() != expected_top_level {
        return Err("extracted payload file set was modified".to_owned());
    }
    regular_directory(&root.join("bin"), "payload bin directory")?;
    regular_directory(&root.join("tests"), "payload tests directory")?;
    regular_directory(&root.join("tmp"), "payload temporary directory")?;
    let manifest = root.join("manifest");
    regular_file(&manifest, "payload manifest", false)?;
    if fs::read(&manifest).map_err(display("read payload manifest"))? != MANIFEST {
        return Err("extracted payload manifest was modified".to_owned());
    }
    let expected = PAYLOADS.iter().map(|payload| payload.name).collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for directory in ["bin", "tests"] {
        for entry in fs::read_dir(root.join(directory)).map_err(display("read payload directory"))? {
            let entry = entry.map_err(display("read payload entry"))?;
            let name = entry.file_name().into_string().map_err(|_| "payload filename is not UTF-8".to_owned())?;
            actual.insert(format!("{directory}/{name}"));
        }
    }
    if actual.iter().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err("extracted payload file set was modified".to_owned());
    }
    for payload in PAYLOADS {
        let path = root.join(payload.name);
        regular_file(&path, "payload file", true)?;
        let metadata = fs::metadata(&path).map_err(display("inspect payload file"))?;
        if metadata.len() != payload.bytes.len() as u64
            || sha256_file(&path)? != payload.sha256
        {
            return Err(format!("extracted payload `{}` was modified", payload.name));
        }
    }
    Ok(())
}

fn ensure_directory_chain(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("extraction root `{}` is not absolute", path.display()));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => current.push(component.as_os_str()),
            Component::Normal(_) => {
                current.push(component.as_os_str());
                match fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                        return Err(format!("extraction path `{}` is not a regular directory", current.display()));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        fs::create_dir(&current).map_err(display("create extraction directory"))?;
                    }
                    Err(error) => return Err(format!("failed to inspect `{}`: {error}", current.display())),
                }
            }
            Component::CurDir | Component::ParentDir => {
                return Err("extraction root is not normalized".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), String> {
    let mut components = name.split('/');
    let directory = components.next();
    let file = components.next();
    if !matches!(directory, Some("bin" | "tests"))
        || file.is_none_or(|file| file.is_empty() || file == "." || file == "..")
        || components.next().is_some()
        || name.contains(['\\', '\n', '\r', '\t', '\0'])
    {
        return Err(format!("unsafe embedded payload name `{name}`"));
    }
    Ok(())
}

fn regular_directory(path: &Path, description: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(display(description))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{description} `{}` is linked or not a directory", path.display()));
    }
    verify_private_mode(&metadata, 0o700, description, path)?;
    Ok(())
}

fn regular_file(path: &Path, description: &str, executable: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(display(description))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{description} `{}` is linked or not a file", path.display()));
    }
    verify_private_mode(&metadata, if executable { 0o700 } else { 0o600 }, description, path)?;
    Ok(())
}

#[cfg(unix)]
fn verify_private_mode(
    metadata: &fs::Metadata,
    expected: u32,
    description: &str,
    path: &Path,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let actual = metadata.permissions().mode() & 0o777;
    if actual != expected {
        return Err(format!(
            "{description} `{}` has permissions {actual:03o}, expected {expected:03o}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_mode(
    _metadata: &fs::Metadata,
    _expected: u32,
    _description: &str,
    _path: &Path,
) -> Result<(), String> {
    Ok(())
}

fn display(context: &str) -> impl FnOnce(std::io::Error) -> String + '_ {
    move |error| format!("{context}: {error}")
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(display("set private directory permissions"))
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<(), String> { Ok(()) }

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(display("set private file permissions"))
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<(), String> { Ok(()) }

#[cfg(unix)]
fn set_private_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(display("set private executable permissions"))
}

#[cfg(not(unix))]
fn set_private_executable(_path: &Path) -> Result<(), String> { Ok(()) }

fn sha256_file(path: &Path) -> Result<[u8; 32], String> {
    let bytes = fs::read(path).map_err(display("read payload for verification"))?;
    Ok(sha256(&bytes))
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ];
    let mut state = [0x6a09e667_u32,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 { padded.push(0); }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for block in padded.chunks_exact(64) {
        let mut w = [0_u32; 64];
        for (index, bytes) in block.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes(bytes.try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = w[index-15].rotate_right(7) ^ w[index-15].rotate_right(18) ^ (w[index-15] >> 3);
            let s1 = w[index-2].rotate_right(17) ^ w[index-2].rotate_right(19) ^ (w[index-2] >> 10);
            w[index] = w[index-16].wrapping_add(s0).wrapping_add(w[index-7]).wrapping_add(s1);
        }
        let [mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[index]).wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h=g; g=f; f=e; e=d.wrapping_add(t1); d=c; c=b; b=a; a=t1.wrapping_add(t2);
        }
        for (slot, value) in state.iter_mut().zip([a,b,c,d,e,f,g,h]) { *slot = slot.wrapping_add(value); }
    }
    let mut output = [0_u8; 32];
    for (chunk, value) in output.chunks_exact_mut(4).zip(state) { chunk.copy_from_slice(&value.to_be_bytes()); }
    output
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "lorry-test-bundle-{}-{sequence}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn payload_manifest_and_launcher_are_canonical() {
        let temporary = TemporaryDirectory::new();
        let source = temporary.0.join("harness");
        fs::write(&source, b"bundle-payload").unwrap();
        let payload = payload("tests/000-harness".to_owned(), &source, true).unwrap();
        let extraction_root = temporary.0.join("extract");
        let layout = Layout {
            directory: extraction_root.join(format!("package-{}", "a".repeat(64))),
            extraction_root,
            id: "a".repeat(64),
        };
        assert_eq!(
            payload_manifest(&layout, std::slice::from_ref(&payload)),
            format!(
                "lorry-test-bundle-v1\nid\t{}\nrun\ttests/000-harness\t14\te174faf66a2ed8c00f9c20cf12e4033a10bb31f41be0b1e2c5ce66437a693f2d\n",
                "a".repeat(64)
            )
        );
        let manifest = payload_manifest(&layout, std::slice::from_ref(&payload));
        let first = launcher_source(&layout, std::slice::from_ref(&payload), &manifest).unwrap();
        let second = launcher_source(&layout, std::slice::from_ref(&payload), &manifest).unwrap();
        assert_eq!(first, second);
        assert!(first.contains("length: 14"));
        assert!(first.contains("tests/000-harness"));
    }

    #[test]
    fn payload_names_cannot_escape_the_extraction_directory() {
        for name in [
            "",
            ".",
            "..",
            "../test",
            "dir/test",
            "test\\name",
            "test\nname",
        ] {
            assert!(validate_payload_name(name).is_err(), "accepted `{name:?}`");
        }
        assert!(validate_payload_name("test-harness").is_ok());
    }
}
