//! Guard the async-first contract of `moto_io::net` (networking plan,
//! step 4): the data path must never block or spawn on its own -- blocking
//! policy belongs to the vdso veneer, execution to the caller's runtime.
//! A violation fails the build here rather than surfacing as a stall.

use std::path::Path;

const FORBIDDEN: &[&str] = &[
    "SysCpu::spawn",
    "block_on_sync",
    "SyncWaiter",
    "thread::sleep",
    "sched_yield",
];

fn main() {
    let net_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/net");
    println!("cargo::rerun-if-changed={}", net_dir.display());
    for entry in std::fs::read_dir(&net_dir).expect("src/net unreadable") {
        let path = entry.expect("src/net entry").path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("unreadable source");
        for (idx, line) in source.lines().enumerate() {
            // Comments may discuss the blocking world; code may not touch it.
            if line.trim_start().starts_with("//") {
                continue;
            }
            for token in FORBIDDEN {
                if line.contains(token) {
                    panic!(
                        "{}:{} contains `{token}`: moto_io::net must stay \
                         async-first (blocking lives in the vdso veneer)",
                        path.display(),
                        idx + 1
                    );
                }
            }
        }
    }
}
