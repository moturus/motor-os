//! Emulated-TLS runtime: `__emutls_get_address`, implemented directly over the
//! VDSO's key-based TLS (instead of compiler-rt's pthread-based emutls.c).
//!
//! Design: one VDSO TLS key holds a per-thread growable slot array; each
//! `_Thread_local` variable lazily gets a process-wide 1-based index and
//! per-thread storage. The VDSO runs key destructors at thread exit
//! (rt.vdso/src/rt_tls.rs, tolerating reinsertion), which frees the storage.
//!
//! The control-struct layout must match clang's `__emutls_v.*` lowering
//! (llvm/lib/CodeGen/LowerEmuTLS.cpp): { size, align, index, default_value },
//! all pointer-sized. The compiler-rt copy of `__emutls_get_address` must NOT
//! be linked (delete emutls.c.o from libclang_rt.builtins*.a).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Must match clang's __emutls_v.<name> layout exactly.
#[repr(C)]
pub struct EmutlsControl {
    size: usize,
    align: usize,
    /// 0 = no index assigned yet; written only via atomics (we are the only accessor).
    index: AtomicUsize,
    /// Initial-value template, or null for zero-init.
    default_value: *const u8,
}

static NEXT_INDEX: AtomicUsize = AtomicUsize::new(1);
static EMUTLS_KEY: AtomicUsize = AtomicUsize::new(0); // 0 = key not created yet

type Slots = Vec<Option<(usize /* ptr */, Layout)>>;

unsafe extern "C" fn slots_dtor(p: *mut u8) {
    if p.is_null() {
        return;
    }
    let slots = unsafe { Box::from_raw(p as *mut Slots) };
    for (ptr, layout) in slots.iter().flatten() {
        unsafe { alloc::alloc::dealloc(*ptr as *mut u8, *layout) };
    }
}

fn emutls_key() -> usize {
    let key = EMUTLS_KEY.load(Ordering::Acquire);
    if key != 0 {
        return key;
    }
    let new_key = moto_rt::tls::create(Some(slots_dtor));
    match EMUTLS_KEY.compare_exchange(0, new_key, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => new_key,
        Err(winner) => {
            unsafe { moto_rt::tls::destroy(new_key) };
            winner
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __emutls_get_address(control: *mut EmutlsControl) -> *mut u8 {
    let control = unsafe { &*control };

    let mut index = control.index.load(Ordering::Acquire);
    if index == 0 {
        let candidate = NEXT_INDEX.fetch_add(1, Ordering::Relaxed);
        index = match control.index.compare_exchange(
            0,
            candidate,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => candidate,
            Err(winner) => winner, // lost the race; `candidate` becomes an unused gap
        };
    }

    let key = emutls_key();
    let mut slots_ptr = unsafe { moto_rt::tls::get(key) } as *mut Slots;
    if slots_ptr.is_null() {
        slots_ptr = Box::into_raw(Box::new(Slots::new()));
        unsafe { moto_rt::tls::set(key, slots_ptr as *mut u8) };
    }
    let slots = unsafe { &mut *slots_ptr };
    if slots.len() < index {
        slots.resize(index, None);
    }
    let slot = &mut slots[index - 1];
    if slot.is_none() {
        let layout = Layout::from_size_align(control.size.max(1), control.align.max(1)).unwrap();
        let p = if control.default_value.is_null() {
            unsafe { alloc::alloc::alloc_zeroed(layout) }
        } else {
            let p = unsafe { alloc::alloc::alloc(layout) };
            unsafe { core::ptr::copy_nonoverlapping(control.default_value, p, control.size) };
            p
        };
        assert!(!p.is_null());
        *slot = Some((p as usize, layout));
    }
    slot.as_ref().unwrap().0 as *mut u8
}
