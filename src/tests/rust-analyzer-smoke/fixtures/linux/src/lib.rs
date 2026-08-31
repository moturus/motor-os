#[cfg(not(target_os = "linux"))]
compile_error!("Linux fixture used the wrong target");

use std::os::linux::fs::MetadataExt;

pub fn inode(metadata: &std::fs::Metadata) -> u64 {
    metadata.st_ino()
}
