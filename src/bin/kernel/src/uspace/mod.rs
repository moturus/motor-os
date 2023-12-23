pub mod process;
pub mod syscall;

pub use process::Process;

// Public because arch::irq interacts with serial_console.
pub mod serial_console;

mod shared;

mod sys_object;
pub use sys_object::SysObject;

// Syscalls.
mod sys_cpu;
mod sys_ctl;
mod sys_mem;

pub use sys_object::process_wake_events;

pub fn init() {
    shared::init();
}
