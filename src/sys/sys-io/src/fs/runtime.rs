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

the I/O (main) task waits on a selector for requests.
Each request spawns a task to handle it. Each task
gets the FS handle from a "local mutex"; this way
when the FS op waits, other tasks, and the I/O task,
can do non-FS things (request validation, send/receive, stats,
connect/disconnect, etc.),

On the other hand, maybe having long-running tasks per
connection that use mutex to share the FS handle is enough?

2025-09-27

Virtio: async read/write requests: submit to virtq, get
a future with u16 (req ID)

the future, when polled, polls the queue

when the virtq is polled, it ads completions to an
internal set of completed requests

when a specific future polls the queue with its ID,
the queue removes the ID from the list of completions

multiple virtio futures may wait for the same virtq

*/
