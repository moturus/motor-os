use moto_ipc::io_channel;
use moto_sys::SysHandle;

mod io_thread;
pub mod process;

pub struct PendingCompletion {
    pub cqe: io_channel::QueueEntry,
    pub endpoint_handle: SysHandle,
}

// Either net or (later) fs.
pub trait IoSubsystem {
    fn wait_handles(&self) -> Vec<SysHandle>;
    fn process_wakeup(&mut self, handle: SysHandle);
    fn process_sqe(
        &mut self,
        proc: &mut process::Process,
        sqe: io_channel::QueueEntry,
    ) -> Option<io_channel::QueueEntry>;

    // Returns a completion for a process. If none, the device has nothing
    // to do and the IO thread may sleep.
    fn poll(&mut self) -> Option<PendingCompletion>;

    fn on_process_drop(&mut self, proc: &mut process::Process);

    // For how long the IO thread may sleep without calling poll.
    // This is particularly useful in networking, where TCP have various timers.
    fn wait_timeout(&mut self) -> Option<core::time::Duration>;
}

pub fn start() {
    io_thread::start()
}
