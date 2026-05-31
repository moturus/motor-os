//! Statistics for Net runtime, including devices and sockets.

use std::{cell::Cell, rc::Rc};

use async_fs::FileSystem;

#[derive(Default)]
pub(super) struct NetStats {
    pub num_devices: Rc<Cell<u64>>,
    pub active_clients: Rc<Cell<u64>>,
    pub total_clients: Rc<Cell<u64>>,
    pub tcp_sockets: Rc<Cell<u64>>,
    pub total_tcp_sockets: Rc<Cell<u64>>,
    pub tcp_listening_sockets: Rc<Cell<u64>>,
    // pub udp_sockets: Rc<Cell<u64>>,
    // pub total_udp_sockets: Rc<Cell<u64>>,
}

impl NetStats {
    fn log(&self) -> String {
        let mut result = format!(
            "\n{}: sys-io net stats: {} devices;\n",
            now_time(),
            self.num_devices.get()
        );

        result.push_str(
            format!("{:>25}: {}\n", "active_clients", self.active_clients.get()).as_str(),
        );
        result
            .push_str(format!("{:>25}: {}\n", "total_clients", self.total_clients.get()).as_str());
        result.push_str(format!("{:>25}: {}\n", "tcp_sockets", self.tcp_sockets.get()).as_str());
        result.push_str(
            format!(
                "{:>25}: {}\n",
                "total_tcp_sockets",
                self.total_tcp_sockets.get()
            )
            .as_str(),
        );
        result.push_str(
            format!(
                "{:>25}: {}\n",
                "tcp_listening_sockets",
                self.tcp_listening_sockets.get()
            )
            .as_str(),
        );

        result
    }
}

pub(super) async fn stat_logging_task(
    stats: Rc<NetStats>,
    fs: Rc<moto_async::LocalMutex<crate::runtime::fs::FS>>,
    log_filename: String,
    log_interval_secs: u32,
) {
    moto_async::sleep(std::time::Duration::from_secs(log_interval_secs as u64)).await;

    if let Ok(Some((entry_id, entry_kind))) =
        crate::util::stat(fs.clone(), log_filename.as_str()).await
    {
        if !matches!(entry_kind, async_fs::EntryKind::File) {
            log::error!("Log file '{log_filename}' is not a file: net stats logging disabled.");
            return;
        } else {
            let mut fs_mut = fs.lock().await;
            if let Err(err) = fs_mut.delete_entry(entry_id).await {
                log::error!("Failed to delete '{log_filename}'; net stats logging disabled.");
                return;
            }
        }
    }

    let Ok(log_file) = crate::util::create_file(fs.clone(), log_filename.as_str()).await else {
        log::error!("Failed to create '{log_filename}'; net stats logging disabled.");
        return;
    };

    log::debug!(
        "started sys-io net stats logging to '{log_filename}' every {log_interval_secs} secs."
    );

    let mut offset = 0;
    loop {
        let line = stats.log();

        assert_eq!(
            line.len(),
            crate::util::write_file(&fs, log_file, offset, line.as_bytes())
                .await
                .unwrap()
        );

        offset += line.len() as u64;

        moto_async::sleep(std::time::Duration::from_secs(log_interval_secs as u64)).await;
    }
}

fn now_time() -> String {
    let now = moto_rt::time::Instant::now().duration_since(moto_rt::time::Instant::from_u64(0));
    let millis = now.as_millis();
    let secs = millis / 1000;
    let millis = millis % 1000;

    format!("{:3}:{:03}", secs, millis)
}
