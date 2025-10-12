use std::io::Result;
use std::rc::Rc;

pub(super) struct Filesystem {
    block_device: Rc<moto_async::LocalMutex<virtio_async::BlockDevice>>,
    fs: Box<dyn async_fs::FileSystem>,
}

async fn init(block_device: Rc<moto_async::LocalMutex<virtio_async::BlockDevice>>) -> Filesystem {
    todo!()
}
