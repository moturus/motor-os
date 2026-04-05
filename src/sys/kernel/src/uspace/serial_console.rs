//! Support for the userspace serial console "driver" (sys-tty).
//!
//! At the moment, once the "driver" is set, it cannot be changed.
//! An important part of this logic is to forward kernel logs to
//! the userspace driver to avoid kernel logs intermixing with userspace
//! output.
use crate::util::StaticRef;

use super::sysobject::SysObject;
use alloc::{borrow::ToOwned, boxed::Box, sync::Arc};
use core::sync::atomic::*;
use moto_sys::{ErrorCode, SysRay};

struct SerialConsole {
    owner_pid: AtomicU64,
    this_object: Arc<SysObject>,

    uspace_log_buf_addr: AtomicUsize,
    uspace_log_buf_offset_addr: AtomicUsize,
    uspace_log_buf_offset: crate::util::SpinLock<usize>,

    console_driver_address_space:
        crate::util::SpinLock<Option<Arc<crate::mm::user::UserAddressSpace>>>,
}

static CONSOLE: crate::util::StaticRef<SerialConsole> = crate::util::StaticRef::default_const();

// We don't (want to) support nested logging, so we protect top-level log
// routines with per cpu bool flags, and log directly to serial port when nested.
static PERCPU_LOG_GUARD: StaticRef<crate::util::StaticPerCpu<bool>> = StaticRef::default_const();

pub fn init() {
    CONSOLE.set(Box::leak(Box::new(SerialConsole {
        owner_pid: AtomicU64::new(super::process::KERNEL_PID.as_u64()),
        this_object: SysObject::new(Arc::new("serial_console".to_owned())),

        uspace_log_buf_addr: AtomicUsize::new(0),
        uspace_log_buf_offset_addr: AtomicUsize::new(0),
        uspace_log_buf_offset: crate::util::SpinLock::new(0),

        console_driver_address_space: crate::util::SpinLock::new(None),
    })));
}

pub(super) fn get_for_process(
    process: &super::process::Process,
    addresses: &str,
) -> Result<Arc<SysObject>, ErrorCode> {
    if CONSOLE.owner_pid.load(Ordering::Acquire) != super::process::KERNEL_PID.as_u64() {
        // We do not support transferring console ownership for now.
        log::warn!("Console transfer not allowed.");
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    if process.capabilities() & moto_sys::caps::CAP_IO_MANAGER == 0 {
        return Err(moto_rt::E_NOT_ALLOWED);
    }

    let Some((buf_addr, offset_addr)) = addresses.split_once(':') else {
        log::error!("Failed to parse serial console handler parameters");
        return Err(moto_rt::E_INVALID_ARGUMENT);
    };

    let Ok(buf_addr) = buf_addr.parse::<usize>() else {
        log::error!("Failed to parse serial console handler parameters");
        return Err(moto_rt::E_INVALID_ARGUMENT);
    };

    let Ok(offset_addr) = offset_addr.parse::<usize>() else {
        log::error!("Failed to parse serial console handler parameters");
        return Err(moto_rt::E_INVALID_ARGUMENT);
    };

    PERCPU_LOG_GUARD.set(Box::leak(Box::new(crate::util::StaticPerCpu::init())));

    *CONSOLE.console_driver_address_space.lock(line!()) = Some(process.address_space().clone());

    CONSOLE
        .uspace_log_buf_addr
        .store(buf_addr, Ordering::Relaxed);
    CONSOLE
        .owner_pid
        .store(process.pid().as_u64(), Ordering::Relaxed);
    CONSOLE
        .uspace_log_buf_offset_addr
        .store(offset_addr, Ordering::Release);

    Ok(CONSOLE.this_object.clone())
}

pub fn on_irq() {
    if CONSOLE.owner_pid.load(Ordering::Acquire) == super::process::KERNEL_PID.as_u64() {
        crate::raw_log!("\nserial_console interrupt: bye\n");
        crate::arch::kernel_exit();
    }
    SysObject::wake_irq(&CONSOLE.this_object);
}

pub fn logging_to_uspace() -> bool {
    CONSOLE.uspace_log_buf_offset_addr.load(Ordering::Relaxed) != 0
}

pub fn log_to_uspace(msg: &str) -> bool {
    assert!(msg.len() < SysRay::CONSOLE_SHARED_BUF_SZ);

    let uspace_log_buf_offset_addr = CONSOLE.uspace_log_buf_offset_addr.load(Ordering::Relaxed);
    if uspace_log_buf_offset_addr == 0 {
        return false;
    }

    let uspace_log_buf_addr = CONSOLE.uspace_log_buf_addr.load(Ordering::Relaxed);
    if uspace_log_buf_addr == 0 {
        return false; // Raced with console setup?
    }

    let bytes = msg.as_bytes();

    if PERCPU_LOG_GUARD.is_null() {
        PERCPU_LOG_GUARD.set_per_cpu(Box::leak(Box::new(false)));
    }
    *PERCPU_LOG_GUARD.get_per_cpu() = true;

    let mut offset = CONSOLE.uspace_log_buf_offset.lock(line!());
    let start = (*offset) & (SysRay::CONSOLE_SHARED_BUF_SZ - 1);
    let end = start + bytes.len();

    let address_space_guard = CONSOLE.console_driver_address_space.lock(line!());
    let address_space = address_space_guard.as_ref().unwrap();

    if end <= SysRay::CONSOLE_SHARED_BUF_SZ {
        if let Err(err) = address_space.copy_to_user(bytes, (uspace_log_buf_addr + start) as u64) {
            log::error!("Failed to log to userspace: {err:?}.");
            *PERCPU_LOG_GUARD.get_per_cpu() = false;
            return false;
        }
    } else {
        if let Err(err) = address_space.copy_to_user(
            &bytes[..(SysRay::CONSOLE_SHARED_BUF_SZ - start)],
            (uspace_log_buf_addr + start) as u64,
        ) {
            log::error!("Failed to log to userspace: {err:?}.");
            *PERCPU_LOG_GUARD.get_per_cpu() = false;
            return false;
        }

        if let Err(err) = address_space.copy_to_user(
            &bytes[(SysRay::CONSOLE_SHARED_BUF_SZ - start)..],
            uspace_log_buf_addr as u64,
        ) {
            log::error!("Failed to log to userspace: {err:?}.");
            *PERCPU_LOG_GUARD.get_per_cpu() = false;
            return false;
        }
    }

    *offset += bytes.len();
    let offset_bytes = offset.to_ne_bytes();

    if let Err(err) = address_space.copy_to_user(&offset_bytes, uspace_log_buf_offset_addr as u64) {
        log::error!("Failed to log to userspace: {err:?}.");
    }

    core::mem::drop(address_space_guard);
    core::mem::drop(offset);

    SysObject::wake_irq(&CONSOLE.this_object);
    *PERCPU_LOG_GUARD.get_per_cpu() = false;

    true
}

pub fn log_to_uspace_protected(msg: &str) -> bool {
    if CONSOLE.uspace_log_buf_offset_addr.load(Ordering::Relaxed) == 0 {
        return false;
    }
    if PERCPU_LOG_GUARD.is_null() {
        return false;
    }
    if *PERCPU_LOG_GUARD.get_per_cpu() {
        return false;
    }

    log_to_uspace(msg)
}
