pub mod process;
pub mod syscall;

pub use process::Process;

// Public because arch::irq interacts with serial_console.
pub mod serial_console;

mod shared;

mod sysobject;
pub use sysobject::SysObject;

// Syscalls.
mod sys_cpu;
mod sys_mem;
mod sys_obj;
mod sys_ray;

pub use sysobject::process_wake_events;

pub fn init() {
    shared::init();
}
