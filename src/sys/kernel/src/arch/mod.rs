pub mod x64;

pub use x64::*;

pub use x64::serial::write_serial_ as arch_write_serial;
pub use x64::tlb::invalidate as tlb_invalidate;

#[macro_export]
macro_rules! arch_raw_log {
    ($($arg:tt)*) => {
        {
            let _lock = crate::xray::logger::lock();
            $crate::arch::serial::write_serial_!($($arg)*);
            $crate::arch::serial::write_serial_!("\n");
        }
    };
}

pub use arch_raw_log;

use crate::config::uCpus;

pub fn cpu_id() -> uCpus {
    x64::apic_cpu_id_32() as uCpus
}
