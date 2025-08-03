//! Async FS runtime.

/*

DRAFT design:
- a virtio-blk driver that implements
  AsyncBlockDevice trait from async-fs
- MotorFS (implementing async-fs::Filesystem trait)
  on top of the BLK device
- moto_ipc::io_channel as an async facility

questions:
 - block device has async iface; so its implementation
   should implement Poll(), which takes the waker and
   wakes it upon an event; the easy way: the implementation
   runs its own io thread that pushes stuff to virtio
   and waits for virtio events;
   - thus two threads: virtio, and the executor?

*/
