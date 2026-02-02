//! Misc helpers.

use std::path::Path;

use async_fs::file_block_device::AsyncFileBlockDevice;
use async_fs::EntryId;
use async_fs::FileSystem;
use motor_fs::MotorFs;

pub async fn motor_fs_create_dir_all(
    fs: &mut MotorFs<AsyncFileBlockDevice>,
    path: &Path,
) -> std::io::Result<EntryId> {
    let components: Vec<_> = path.components().collect();

    let mut parent_id = motor_fs::ROOT_DIR_ID;

    for c in components {
        let filename = c.as_os_str().to_str().unwrap();
        if filename.is_empty() || filename == "/" {
            continue;
        }

        let stat_result = fs.stat(parent_id, filename).await.unwrap();
        parent_id = if let Some((entry_id, _)) = stat_result {
            entry_id
        } else {
            fs.create_entry(parent_id, srfs::EntryKind::Directory, filename)
                .await
                .unwrap()
        };
    }

    Ok(parent_id)
}

/// FNV-1a hash.
///
/// See https://en.wikipedia.org/wiki/Fowler-Noll-Vo_hash_function
pub fn fnv1a_hash_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV_OFFSET_BASIS
    const FNV_PRIME: u64 = 0x100000001b3; // FNV_PRIME

    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash
}
