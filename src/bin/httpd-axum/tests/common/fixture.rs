use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Fixture(pub PathBuf);

impl Fixture {
    pub fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("httpd-{label}-{nonce}"));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
