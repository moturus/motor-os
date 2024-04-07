use moto_ipc::io_channel;
use moto_sys::SysHandle;

mod io_thread;

pub struct PendingCompletion {
    pub msg: io_channel::Msg,
    pub endpoint_handle: SysHandle,
}

// Either net or (later) fs.
pub trait IoSubsystem {
    fn wait_handles(&self) -> Vec<SysHandle>;
    fn process_wakeup(&mut self, handle: SysHandle);
    fn process_sqe(
        &mut self,
        conn: &std::rc::Rc<io_channel::ServerConnection>,
        sqe: io_channel::Msg,
    ) -> Result<Option<io_channel::Msg>, ()>;

    // Returns a completion for a process. If none, the device has nothing
    // to do and the IO thread may sleep.
    fn poll(&mut self) -> Option<PendingCompletion>;

    fn on_connection_drop(&mut self, conn: SysHandle);

    // For how long the IO thread may sleep without calling poll.
    // This is particularly useful in networking, where TCP have various timers.
    fn wait_timeout(&mut self) -> Option<core::time::Duration>;
}

pub static STARTED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub fn start() {
    io_thread::start();
    while STARTED.load(std::sync::atomic::Ordering::Relaxed) == 0 {
        moto_runtime::futex_wait(&STARTED, 0, None);
    }
}
