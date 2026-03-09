use std::{
    io::{ErrorKind, Result},
    rc::Rc,
};

use virtio_async::virtio_net::NetDevice;

pub(super) async fn init(devices: Vec<virtio_async::VirtioDevice>) -> Result<()> {
    Err(std::io::Error::from(ErrorKind::Unsupported))
}
