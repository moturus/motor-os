use super::sysobject::SysObject;
use alloc::{borrow::ToOwned, sync::Arc};
use core::sync::atomic::*;
use moto_sys::{process::ProcessId, ErrorCode};

struct SerialConsole {
    owner_pid: AtomicU64,
    this_object: Arc<SysObject>,
}

static CONSOLE: crate::util::StaticRef<SerialConsole> = crate::util::StaticRef::default_const();

pub fn init() {
    use alloc::boxed::Box;

    CONSOLE.set(Box::leak(Box::new(SerialConsole {
        owner_pid: AtomicU64::new(ProcessId::Kernel.into()),
        this_object: SysObject::new(Arc::new("serial_console".to_owned())),
    })));
}

pub(super) fn get_for_process(
    process: &super::process::Process,
) -> Result<Arc<SysObject>, ErrorCode> {
    if CONSOLE.owner_pid.load(Ordering::Acquire) != ProcessId::Kernel.into() {
        // We do not support transferring console ownership for now.
        log::warn!("Console transfer not allowed.");
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    if process.capabilities() & moto_sys::caps::CAP_IO_MANAGER == 0 {
        return Err(moto_rt::E_NOT_ALLOWED);
    }

    CONSOLE
        .owner_pid
        .store(process.pid().into(), Ordering::Relaxed);
    Ok(CONSOLE.this_object.clone())
}

pub fn on_irq() {
    if CONSOLE.owner_pid.load(Ordering::Acquire) == ProcessId::Kernel.into() {
        crate::raw_log!("\nserial_console interrupt: bye\n");
        crate::arch::kernel_exit();
    }
    SysObject::wake_irq(&CONSOLE.this_object);
}
