//! Misc helpers.

use std::path::Path;

use async_fs::EntryId;
use async_fs::FileSystem;
use motor_fs::MotorFs;

pub async fn motor_fs_create_dir_all(fs: &mut MotorFs, path: &Path) -> std::io::Result<EntryId> {
    let components: Vec<_> = path.components().collect();

    let mut parent_id = motor_fs::ROOT_DIR_ID;

    for c in components {
        let filename = c.as_os_str().to_str().unwrap();
        if filename.is_empty() || filename == "/" {
            continue;
        }

        let entry_id = fs.stat(parent_id, filename).await.unwrap();
        if let Some(entry_id) = entry_id {
            parent_id = entry_id;
        } else {
            parent_id = fs
                .create_entry(parent_id, srfs::EntryKind::Directory, filename)
                .await
                .unwrap();
        }
    }

    Ok(parent_id)
}
