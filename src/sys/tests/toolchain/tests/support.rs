use moto_sdk::io::fs::{AccessPermissions, FsClient};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

pub fn interactive() -> bool {
    moto_sdk::sys::ProcessStaticPage::get().capabilities & moto_sdk::sys::caps::CAP_INTERACTIVE != 0
}

pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new(name: &str) -> Self {
        Self::under("/none/dev", name)
    }

    pub fn under(parent: &str, name: &str) -> Self {
        let root = Path::new(parent).join(format!("{name}-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        share(&root, true);
        Self(root)
    }

    pub fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut directory = path.parent().unwrap();
        while directory != self.0 {
            share(directory, true);
            directory = directory.parent().unwrap();
        }
        fs::write(&path, text).unwrap();
        share(&path, false);
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            fs::remove_dir_all(&self.0).unwrap();
        } else {
            eprintln!("test artifacts: {}", self.0.display());
        }
    }
}

pub fn share(path: &Path, directory: bool) {
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let fs = FsClient::connect().unwrap();
        let (id, _) = fs.stat(path.to_str().unwrap()).await.unwrap();
        let mut permissions = fs.metadata(id).await.unwrap().permissions().unwrap();
        permissions.none = if directory {
            AccessPermissions::Rwx
        } else {
            AccessPermissions::Rw
        };
        fs.set_all_permissions(id, permissions).await.unwrap();
    });
}

pub fn command(root: &Path, tool: &str) -> Command {
    // Motor resolves the executable before applying the child's current_dir.
    let program = if tool.starts_with("./") {
        root.join(&tool[2..])
    } else {
        PathBuf::from(tool)
    };
    let mut command = Command::new(program);
    command
        .current_dir(root)
        .env("PATH", "/user/bin:/user/bin/dev");
    command
}

pub fn output(command: &mut Command, input: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || stdin.write_all(input).unwrap());
        let output = child.wait_with_output().unwrap();
        writer.join().unwrap();
        output
    })
}

#[track_caller]
pub fn success(command: &mut Command, input: &[u8]) -> Output {
    let output = output(command, input);
    assert!(output.status.success(), "{command:?}: {output:?}");
    output
}

pub fn compile(root: &Path, tool: &str, args: &[&str]) {
    success(
        command(root, tool).env("MOTOR_OS_CAPS", "0x204").args(args),
        b"",
    );
}
