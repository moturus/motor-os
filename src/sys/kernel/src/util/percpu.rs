use crate::config::{uCpus, MAX_CPUS};
use core::{marker::PhantomData, sync::atomic::*};

pub struct StaticPerCpu<T> {
    data: [AtomicUsize; MAX_CPUS as usize],
    _unused: PhantomData<T>,
}

impl<T> StaticPerCpu<T> {
    pub fn init() -> Self {
        Self {
            data: {
                let arr = [0_usize; MAX_CPUS as usize];
                unsafe {
                    core::mem::transmute::<
                        [usize; MAX_CPUS as usize],
                        [AtomicUsize; MAX_CPUS as usize],
                    >(arr)
                }
            },
            _unused: PhantomData,
        }
    }

    pub fn set_per_cpu(&self, val: &'static mut T) -> &'static mut T {
        let cpu = crate::arch::current_cpu();
        assert!(self.is_null());

        let addr = val as *mut T;
        let addr = addr as usize;
        self.data[cpu as usize].store(addr, core::sync::atomic::Ordering::Release);
        val
    }
    pub fn set_for_cpu(&self, cpu: uCpus, val: &'static mut T) -> &'static mut T {
        let addr = val as *mut T;
        let addr = addr as usize;
        let prev = self.data[cpu as usize].swap(addr, core::sync::atomic::Ordering::AcqRel);
        assert_eq!(prev, 0);
        val
    }

    pub fn get_per_cpu(&self) -> &'static mut T {
        let addr: usize = self.data[crate::arch::current_cpu() as usize].load(Ordering::Acquire);
        debug_assert_ne!(addr, 0usize);
        unsafe { &mut *(addr as *mut T) }
    }

    #[allow(clippy::mut_from_ref)]
    pub fn get(&self) -> Option<&mut T> {
        let addr: usize = self.data[crate::arch::current_cpu() as usize].load(Ordering::Relaxed);
        if addr == 0 {
            None
        } else {
            Some(unsafe { &mut *(addr as *mut T) })
        }
    }

    pub fn get_for_cpu(&self, cpu: uCpus) -> &'static T {
        let addr: usize = self.data[cpu as usize].load(Ordering::Acquire);
        debug_assert_ne!(addr, 0usize);
        unsafe { &*(addr as *const T) }
    }

    pub fn for_each_cpu<F: FnMut(uCpus, &T) -> bool>(&self, f: &mut F) {
        for cpu in 0..MAX_CPUS {
            let addr: usize = self.data[cpu as usize].load(Ordering::Acquire);
            if addr == 0 {
                break;
            }

            let val = unsafe { &*(addr as *mut T) as &T };
            if f(cpu, val) {
                break;
            }
        }
    }

    pub fn is_null(&self) -> bool {
        self.data[crate::arch::current_cpu() as usize].load(core::sync::atomic::Ordering::Relaxed)
            == 0
    }

    pub fn count_set(&self) -> uCpus {
        let mut count: uCpus = 0;

        for entry in &self.data {
            if entry.load(Ordering::Acquire) != 0 {
                count += 1;
            }
        }
        count
    }

    pub fn spin_until_all_set(&self) {
        while self.count_set() < crate::arch::num_cpus() {
            crate::arch::nop();
        }
    }
}
