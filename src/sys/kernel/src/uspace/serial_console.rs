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
use moto_sys::{
    kernel_log::{
        encode_kernel_log_frame_header, kernel_log_control_is_aligned, KernelLogControl,
        KERNEL_LOG_FRAME_HEADER_SIZE, KERNEL_LOG_MAX_PAYLOAD, KERNEL_LOG_RING_SIZE,
    },
    ErrorCode,
};

#[derive(Default)]
struct KernelLogRingState {
    end: u64,
    next_sequence: u32,
    generation: u64,
}

struct SerialConsole {
    owner_pid: AtomicU64,
    this_object: Arc<SysObject>,

    uspace_log_buf_addr: AtomicUsize,
    kernel_log_control_addr: AtomicUsize,
    kernel_log_ring_state: crate::util::SpinLock<KernelLogRingState>,

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
        kernel_log_control_addr: AtomicUsize::new(0),
        kernel_log_ring_state: crate::util::SpinLock::new(KernelLogRingState::default()),

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

    let Ok(control_addr) = offset_addr.parse::<usize>() else {
        log::error!("Failed to parse serial console handler parameters");
        return Err(moto_rt::E_INVALID_ARGUMENT);
    };
    if !kernel_log_control_is_aligned(control_addr) {
        log::error!("The serial console control block is not aligned");
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let page_size = crate::mm::PAGE_SIZE_SMALL as usize;
    let control_page = control_addr & !(page_size - 1);
    let control_offset = control_addr - control_page;
    if control_offset + core::mem::size_of::<KernelLogControl>() > page_size {
        log::error!("The serial console control block crosses a page");
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let address_space = process.address_space().clone();
    let kernel_control_page = match address_space.get_user_page_as_kernel(control_page as u64) {
        Ok(addr) => addr as usize,
        Err(err) => {
            log::error!("The serial console control block is not mapped: {err:?}");
            return Err(err);
        }
    };
    let kernel_control_addr = kernel_control_page + control_offset;
    let control = unsafe { &*(kernel_control_addr as *const KernelLogControl) };
    control.end.store(0, Ordering::Relaxed);
    control.generation.store(0, Ordering::Release);

    PERCPU_LOG_GUARD.set(Box::leak(Box::new(crate::util::StaticPerCpu::init())));

    *CONSOLE.console_driver_address_space.lock(line!()) = Some(address_space);
    *CONSOLE.kernel_log_ring_state.lock(line!()) = KernelLogRingState::default();

    CONSOLE
        .uspace_log_buf_addr
        .store(buf_addr, Ordering::Relaxed);
    CONSOLE
        .owner_pid
        .store(process.pid().as_u64(), Ordering::Relaxed);
    CONSOLE
        .kernel_log_control_addr
        .store(kernel_control_addr, Ordering::Release);

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
    CONSOLE.kernel_log_control_addr.load(Ordering::Acquire) != 0
}

fn copy_to_ring(
    address_space: &crate::mm::user::UserAddressSpace,
    ring_addr: usize,
    end: u64,
    bytes: &[u8],
) -> Result<(), ErrorCode> {
    let start = end as usize & (KERNEL_LOG_RING_SIZE - 1);
    let first_len = bytes.len().min(KERNEL_LOG_RING_SIZE - start);
    address_space.copy_to_user(&bytes[..first_len], (ring_addr + start) as u64)?;
    if first_len != bytes.len() {
        address_space.copy_to_user(&bytes[first_len..], ring_addr as u64)?;
    }
    Ok(())
}

pub fn log_to_uspace(msg: &str) -> bool {
    let kernel_control_addr = CONSOLE.kernel_log_control_addr.load(Ordering::Acquire);
    if kernel_control_addr == 0 {
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

    let mut state = CONSOLE.kernel_log_ring_state.lock(line!());
    let sequence = state.next_sequence;
    state.next_sequence = state.next_sequence.wrapping_add(1);

    if bytes.len() > KERNEL_LOG_MAX_PAYLOAD {
        core::mem::drop(state);
        *PERCPU_LOG_GUARD.get_per_cpu() = false;
        return false;
    }

    let mut header = [0; KERNEL_LOG_FRAME_HEADER_SIZE];
    encode_kernel_log_frame_header(&mut header, sequence, bytes.len()).unwrap();
    let control = unsafe { &*(kernel_control_addr as *const KernelLogControl) };

    let odd_generation = state.generation.wrapping_add(1);
    control.generation.store(odd_generation, Ordering::Relaxed);
    fence(Ordering::Release);

    let address_space_guard = CONSOLE.console_driver_address_space.lock(line!());
    let address_space = address_space_guard.as_ref().unwrap();

    let copy_result = copy_to_ring(address_space, uspace_log_buf_addr, state.end, &header)
        .and_then(|()| {
            copy_to_ring(
                address_space,
                uspace_log_buf_addr,
                state.end.wrapping_add(KERNEL_LOG_FRAME_HEADER_SIZE as u64),
                bytes,
            )
        });

    let even_generation = odd_generation.wrapping_add(1);
    state.generation = even_generation;
    if copy_result.is_err() {
        control.generation.store(even_generation, Ordering::Release);
        *PERCPU_LOG_GUARD.get_per_cpu() = false;
        core::mem::drop(address_space_guard);
        core::mem::drop(state);
        return false;
    }

    state.end = state
        .end
        .wrapping_add((KERNEL_LOG_FRAME_HEADER_SIZE + bytes.len()) as u64);
    control.end.store(state.end, Ordering::Relaxed);
    control.generation.store(even_generation, Ordering::Release);

    core::mem::drop(address_space_guard);
    core::mem::drop(state);

    SysObject::wake_irq(&CONSOLE.this_object);
    *PERCPU_LOG_GUARD.get_per_cpu() = false;

    true
}

pub fn log_to_uspace_protected(msg: &str) -> bool {
    if CONSOLE.kernel_log_control_addr.load(Ordering::Relaxed) == 0 {
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

pub fn sys_panic_notify() {
    // Force raw serial writes, as the VM is going bye-bye, and logs via
    // sys-tty are likely to get lost.
    CONSOLE.kernel_log_control_addr.store(0, Ordering::SeqCst)
}
