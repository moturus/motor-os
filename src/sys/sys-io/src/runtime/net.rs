use std::{
    io::{ErrorKind, Result},
    rc::Rc,
};

use virtio_async::virtio_net::NetDevice;

mod config;

pub(super) async fn init(
    devices: Vec<virtio_async::VirtioDevice>,
    fs: Rc<moto_async::LocalMutex<super::fs::FS>>,
) -> Result<()> {
    let cfg = config::load(fs).await?;
    log::debug!("NET cfg loaded OK.");

    Err(std::io::Error::from(ErrorKind::Unsupported))
}
