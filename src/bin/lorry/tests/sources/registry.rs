use flate2::{Compression, write::GzEncoder};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::support::Project;

pub struct Registry {
    pub project: Project,
    pub state: Project,
    config: PathBuf,
    original: Option<Vec<u8>>,
}

impl Registry {
    fn decisions(&self) -> PathBuf {
        self.config
            .parent()
            .unwrap()
            .join(if cfg!(target_os = "motor") {
                "lorry-workspaces"
            } else {
                "workspaces"
            })
    }

    pub fn decision(&self, workspace: &Path) -> Option<PathBuf> {
        let directory = self.decisions();
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => panic!("{error}"),
        };
        let marker = format!("workspace = {:?}", workspace.to_str().unwrap());
        entries
            .map(|entry| entry.unwrap().path())
            .find(|path| fs::read_to_string(path).unwrap().contains(&marker))
    }

    pub fn forget_accept_all(&self) {
        let directory = self.decisions();
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let text = fs::read_to_string(&path).unwrap();
            if text.contains(self.project.root.to_str().unwrap()) {
                fs::write(path, text.replace("accept-all = true\n", "")).unwrap();
            }
        }
    }
    pub fn new() -> Self {
        let project = Project::new();
        let state = Project::new();
        let config = config_path(&project);
        let original = fs::read(&config).ok();
        fs::create_dir(state.root.join("network")).unwrap();
        let executable = state.root.join("network/curl");
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        executable_mode(&executable);
        let registry = Self {
            project,
            state,
            config,
            original,
        };
        registry.configure("");
        registry
    }

    pub fn configure(&self, extra: &str) {
        let root = self.state.root.to_str().unwrap();
        let layer = if cfg!(target_os = "motor") && self.config.starts_with("/none") {
            "none"
        } else {
            "user"
        };
        let cache = if cfg!(target_os = "motor") {
            String::new()
        } else {
            format!("[cache]\ndirectory=\"{root}/cache\"\n")
        };
        fs::write(&self.config, format!(
            "config-version=1\nuse-cargo-registry=false\n[repositories]\n{layer}=\"{root}/repository\"\n[network]\ncurl=\"{root}/network/curl\"\n{cache}[policy]\ndefault=\"allow\"\n{extra}"
        )).unwrap();
    }

    pub fn package(
        &self,
        name: &str,
        extra: &str,
        files: &[(&str, &str)],
        deps: serde_json::Value,
    ) -> String {
        self.versioned_package(name, "1.0.0", extra, files, deps)
    }

    pub fn default_cargo_cache(&self, extra: &str) {
        self.configure(extra);
        let text = fs::read_to_string(&self.config).unwrap();
        fs::write(&self.config, text.replace("use-cargo-registry=false\n", "")).unwrap();
    }

    pub fn versioned_package(
        &self,
        name: &str,
        version: &str,
        extra: &str,
        files: &[(&str, &str)],
        deps: serde_json::Value,
    ) -> String {
        let manifest = format!(
            "[package]\nname={name:?}\nversion={version:?}\nedition=\"2024\"\nlicense=\"MIT\"\n{extra}"
        );
        let mut tar = Vec::new();
        append(
            &mut tar,
            &format!("{name}-{version}/Cargo.toml"),
            manifest.as_bytes(),
        );
        for (path, contents) in files {
            append(
                &mut tar,
                &format!("{name}-{version}/{path}"),
                contents.as_bytes(),
            );
        }
        tar.resize(tar.len() + 1024, 0);
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(&tar).unwrap();
        let bytes = gzip.finish().unwrap();
        let checksum = format!("{:x}", Sha256::digest(&bytes));
        self.state.write(
            &format!("network/archives/{name}/{name}-{version}.crate"),
            bytes,
        );
        let index = format!("network/index/{}", sparse(name));
        let previous = fs::read_to_string(self.state.root.join(&index)).unwrap_or_default();
        self.state.write(
            &index,
            format!(
                "{previous}{}\n",
                json!({
                    "name": name, "vers": version, "deps": deps, "cksum": checksum,
                    "features": {}, "yanked": false
                })
            ),
        );
        checksum
    }

    pub fn requests(&self) -> String {
        fs::read_to_string(self.state.root.join("network/requests")).unwrap_or_default()
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        if let Some(bytes) = &self.original {
            fs::write(&self.config, bytes).unwrap();
        } else {
            fs::remove_file(&self.config).unwrap();
        }
    }
}

#[cfg(not(target_os = "motor"))]
fn config_path(p: &Project) -> PathBuf {
    p.root.join("home/.config/lorry/lorry.toml")
}

#[cfg(target_os = "motor")]
fn config_path(_: &Project) -> PathBuf {
    let interactive = moto_sdk::sys::ProcessStaticPage::get().capabilities
        & moto_sdk::sys::caps::CAP_INTERACTIVE
        != 0;
    PathBuf::from(if interactive {
        "/user/cfg/lorry.toml"
    } else {
        "/none/cfg/lorry.toml"
    })
}

fn executable_mode(path: &Path) {
    crate::support::executable_permissions(path).unwrap();
}

pub fn sparse(name: &str) -> String {
    let name = name.to_lowercase();
    match name.len() {
        1 | 2 => format!("{}/{name}", name.len()),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

fn append(tar: &mut Vec<u8>, path: &str, contents: &[u8]) {
    let mut header = [0_u8; 512];
    assert!(path.len() < 100);
    header[..path.len()].copy_from_slice(path.as_bytes());
    for (range, value) in [
        (100..108, 0o644),
        (108..116, 0),
        (116..124, 0),
        (124..136, contents.len()),
        (136..148, 0),
    ] {
        let text = format!("{value:0width$o}", width = range.len() - 1);
        header[range.start..range.end - 1].copy_from_slice(text.as_bytes());
    }
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u64 = header.iter().map(|byte| *byte as u64).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    tar.extend_from_slice(&header);
    tar.extend_from_slice(contents);
    tar.resize(tar.len().div_ceil(512) * 512, 0);
}

pub fn curl() {
    let args: Vec<_> = std::env::args().collect();
    let option = |name| &args[args.iter().position(|arg| arg == name).unwrap() + 1];
    let url = option("--url");
    let nonce = option("--write-out")
        .split_once("LORRY-CURL-1 ")
        .unwrap()
        .1
        .lines()
        .next()
        .unwrap();
    let exe = std::env::current_exe().unwrap();
    let root = exe.parent().unwrap();
    let mut log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("requests"))
        .unwrap();
    writeln!(log, "{url}").unwrap();
    let path = if let Some(path) = url.strip_prefix("https://index.crates.io/") {
        root.join("index").join(path)
    } else if let Some(path) = url.strip_prefix("https://static.crates.io/crates/") {
        root.join("archives").join(path)
    } else {
        panic!("unexpected network request: {url}");
    };
    assert!(!url.contains(".."));
    let bytes = fs::read(path).unwrap();
    std::io::stdout().write_all(&bytes).unwrap();
    eprint!(
        "\nLORRY-CURL-1 {nonce}\nstatus=200\nurl={url}\nredirect=\nsize={}\nEND-LORRY-CURL-1 {nonce}\n",
        bytes.len()
    );
}
