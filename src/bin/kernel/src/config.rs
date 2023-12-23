use core::sync::atomic::*;

#[allow(non_camel_case_types)]
pub type uCpus = u8;
pub type AtomicUCpus = AtomicU8;

pub const MAX_CPUS: uCpus = 16;
pub const KERNEL_STACK_PAGES: u64 = 64;

pub const TRACE_BUFFER_SIZE: usize = 128;

static NUM_CPUS: AtomicUCpus = AtomicUCpus::new(0);

pub fn set_num_cpus(num_cpus: uCpus) {
    assert_eq!(0, NUM_CPUS.swap(num_cpus, Ordering::Relaxed));
}

pub fn num_cpus() -> uCpus {
    NUM_CPUS.load(Ordering::Relaxed)
}

// We do not want URLs to be used to pass data; 256 bytes seems enough
// for this use case.
pub const MAX_URL_SIZE: u64 = 256;

#[derive(Debug)]
pub struct KernelConfig {
    pub custom_irqs: u8,

    pub allow_user_logging: bool,
    pub log_level: log::LevelFilter,

    /// The scheduler will never put a CPU to sleep (hlt), but will wait
    /// for events spin-looping.
    pub nosleep: bool,

    // Runtime config
    pub default_max_user_memory: AtomicU64,
    pub max_wait_handles: AtomicU32,
}

impl KernelConfig {
    const DEFAULT_MAX_USER_MEMORY: u64 = u64::MAX; // 32_u64 * (1_u64 << 20);
    const DEFAULT_MAX_WAIT_HANDLES: u32 = 1024;

    const fn new() -> Self {
        Self {
            custom_irqs: 16,
            allow_user_logging: false,
            log_level: log::LevelFilter::Info,
            nosleep: false,
            default_max_user_memory: AtomicU64::new(Self::DEFAULT_MAX_USER_MEMORY),
            max_wait_handles: AtomicU32::new(Self::DEFAULT_MAX_WAIT_HANDLES),
        }
    }
}

static KERNEL_CONFIG: KernelConfig = KernelConfig::new();

pub fn get() -> &'static KernelConfig {
    &KERNEL_CONFIG
}
