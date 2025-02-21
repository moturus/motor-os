use core::sync::atomic::AtomicU64;

// Custom userspace region (1TB): the kernel will never allocate a vaddr in a userspace
// address space in this region, it is used by lib/iort.
pub const CUSTOM_USERSPACE_REGION_START: u64 = (1_u64 << 45) + (1_u64 << 40);
pub const CUSTOM_USERSPACE_REGION_END: u64 = CUSTOM_USERSPACE_REGION_START + (1_u64 << 40);

// Describes a global static page populated by the kernel and mapped
// into the address space of each user process (read-only).
// Readonly in the userspace.
// NOTE: this is considered private/unstable API and is subject to change.
#[doc(hidden)]
#[repr(C)]
pub struct KernelStaticPage {
    pub version: u64,

    // Fields for tsc time conversion from KVM struct pvclock_vcpu_time_info.
    // See https://www.kernel.org/doc/Documentation/virt/kvm/msr.rst
    pub tsc_shift: i8,
    pub tsc_mul: u32,
    pub tsc_in_sec: u64,
    pub tsc_ts: u64,
    pub system_time: u64,

    // Wallclock base from struct pvclock_wall_clock.
    // See https://www.kernel.org/doc/Documentation/virt/kvm/msr.rst
    pub base_nsec: u64, // Add this to system_time.

    // The kernel's view of system start time.
    pub system_start_time_tsc: u64,

    pub num_cpus: u32,
}

impl KernelStaticPage {
    pub const PAGE_SIZE: u64 = 4096;
    pub const VADDR: u64 = 0x3F7FFFE00000; // See STATIC_SHARED_PAGE_USER_VADDR in virt.rs in the kernel.

    #[cfg(feature = "userspace")]
    pub fn get() -> &'static Self {
        // Safety: the OS is supposed to have taken care of this.
        unsafe {
            (Self::VADDR as usize as *const KernelStaticPage)
                .as_ref()
                .unwrap_unchecked()
        }
    }
}
const _: () =
    assert!(core::mem::size_of::<KernelStaticPage>() as u64 <= KernelStaticPage::PAGE_SIZE);

// Describes a per-process page shared between the kernel and the process.
// Readonly in the userspace.
#[derive(Debug)]
#[repr(C)]
pub struct ProcessStaticPage {
    pub version: u64,
    pub pid: u64,

    // The capabilities of the process.
    pub capabilities: u64,
    pub active_threads: AtomicU64, // Includes stdio relay threads.
}

impl ProcessStaticPage {
    pub const PAGE_SIZE: u64 = 4096;
    pub const VADDR: u64 = KernelStaticPage::VADDR - crate::sys_mem::PAGE_SIZE_MID;

    #[cfg(feature = "userspace")]
    pub fn get() -> &'static Self {
        // Safety: the OS is supposed to have taken care of this.
        unsafe {
            (Self::VADDR as usize as *const ProcessStaticPage)
                .as_ref()
                .unwrap_unchecked()
        }
    }
}
const _: () =
    assert!(core::mem::size_of::<ProcessStaticPage>() as u64 <= ProcessStaticPage::PAGE_SIZE);

// Describes a static per-thread page shared between the kernel and the thread.
// Usually resides at the top of the stack and is pointed at by FS register on x64.
// Writable by the userspace.
#[derive(Debug)]
#[repr(C)]
pub struct UserThreadControlBlock {
    pub guard: u64,          // For kernel use.
    pub kernel_version: u32, // The kernel tells the user the version of the struct.
    pub user_version: u32,   // The userspace tells the kernel the version of the struct.
    pub tls: u64,            // TLS. For userspace use.
    pub self_handle: u64,    // Used to wake this thread.
    pub self_tid: u64,       // This thread's tid.
    pub stack_guard: u64,    // fs:0x28 - this is what stack protectors use.
    pub current_cpu: core::sync::atomic::AtomicU32,
    pub reserved0: [u8; 3],
    pub name_len: u8,
    pub name_bytes: [u8; crate::MAX_THREAD_NAME_LEN],
}

impl UserThreadControlBlock {
    #[cfg(feature = "userspace")]
    pub fn get_mut() -> &'static mut Self {
        // Safety: the OS is supposed to have taken care of this.
        // The userspace MUST NOT write to FS register.
        unsafe {
            let mut fsbase: u64;
            core::arch::asm!("rdfsbase {}", out(reg) fsbase, options(nostack, preserves_flags));
            (fsbase as usize as *mut Self).as_mut().unwrap()
        }
    }

    #[cfg(feature = "userspace")]
    pub fn get() -> &'static Self {
        Self::get_mut()
    }

    #[cfg(feature = "userspace")]
    pub fn this_thread_handle() -> crate::SysHandle {
        Self::get().self_handle.into()
    }

    #[cfg(feature = "userspace")]
    pub fn this_thread_tid() -> u64 {
        Self::get().self_tid
    }

    pub fn get_thread_name(&self) -> &str {
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let name_len = self.name_len as usize;
        if name_len > crate::MAX_THREAD_NAME_LEN {
            return "";
        }

        core::sync::atomic::fence(core::sync::atomic::Ordering::AcqRel);
        core::str::from_utf8(&self.name_bytes[0..name_len]).unwrap_or("")
    }
}

#[cfg(feature = "userspace")]
pub fn set_current_thread_name(name: &str) -> Result<(), crate::ErrorCode> {
    let bytes = name.as_bytes();
    if bytes.len() > crate::MAX_THREAD_NAME_LEN {
        return Err(moto_rt::E_INVALID_ARGUMENT);
    }

    let utcb = UserThreadControlBlock::get_mut();

    // Carefully order writes because reads can happen concurrently.
    utcb.name_len = 0;
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    utcb.name_bytes[0..bytes.len()].copy_from_slice(bytes);
    core::sync::atomic::fence(core::sync::atomic::Ordering::AcqRel);
    utcb.name_len = bytes.len() as u8;
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

    Ok(())
}
