use alloc::boxed::Box;
use core::cell::Cell;
use core::cell::UnsafeCell;
use core::fmt;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{self, AtomicU32, AtomicUsize, Ordering};

#[macro_export]
macro_rules! moturus_log {
    ($($arg:tt)*) => {
        {
            extern crate alloc;
            moto_sys::syscalls::SysMem::log(alloc::format!($($arg)*).as_str()).ok();
        }
    };
}

pub use moturus_log;

pub fn get_cpu_usage() -> alloc::vec::Vec<f32> {
    let num_cpus = moto_sys::KernelStaticPage::get().num_cpus;

    let mut cpu_usage = alloc::vec::Vec::new();
    for _ in 0..num_cpus {
        cpu_usage.push(0.0_f32);
    }

    moto_sys::stats::get_cpu_usage(&mut cpu_usage[..]).unwrap();
    cpu_usage
}

pub struct ScopedTimer<'a> {
    started: moto_sys::time::Instant,
    ring_after: core::time::Duration,
    msg: &'a str,
    die: bool,
}

impl<'a> Drop for ScopedTimer<'a> {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        if elapsed >= self.ring_after {
            moturus_log!("{}: {:?} elapsed.", self.msg, elapsed);

            if self.die {
                moto_sys::syscalls::SysCpu::exit(1);
            }
        }
    }
}

impl<'a> ScopedTimer<'a> {
    pub fn start(ring_after: core::time::Duration, msg: &'a str) -> ScopedTimer<'a> {
        Self {
            started: moto_sys::time::Instant::now(),
            ring_after,
            msg,
            die: false,
        }
    }

    pub fn die_after(die_after: core::time::Duration, msg: &'a str) -> ScopedTimer<'a> {
        Self {
            started: moto_sys::time::Instant::now(),
            ring_after: die_after,
            msg,
            die: true,
        }
    }
}

// ArrayQueue and dependencies below have been lifted from crossbeam, as crossbeam
// cannot be rustc-dep-of-std without some surgery (as of 2023-05-30).
const SPIN_LIMIT: u32 = 6;
const YIELD_LIMIT: u32 = 10;

struct Backoff {
    step: Cell<u32>,
}

impl Backoff {
    #[inline]
    fn new() -> Self {
        Backoff { step: Cell::new(0) }
    }

    #[inline]
    fn _reset(&self) {
        self.step.set(0);
    }

    #[inline]
    fn spin(&self) {
        for _ in 0..1 << self.step.get().min(SPIN_LIMIT) {
            core::hint::spin_loop();
        }

        if self.step.get() <= SPIN_LIMIT {
            self.step.set(self.step.get() + 1);
        }
    }

    #[inline]
    fn snooze(&self) {
        if self.step.get() <= SPIN_LIMIT {
            for _ in 0..1 << self.step.get() {
                core::hint::spin_loop();
            }
        } else {
            for _ in 0..1 << self.step.get() {
                core::hint::spin_loop();
            }

            // #[cfg(feature = "std")]
            // ::std::thread::yield_now();
        }

        if self.step.get() <= YIELD_LIMIT {
            self.step.set(self.step.get() + 1);
        }
    }

    #[inline]
    pub fn is_completed(&self) -> bool {
        self.step.get() > YIELD_LIMIT
    }
}

impl fmt::Debug for Backoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Backoff")
            .field("step", &self.step)
            .field("is_completed", &self.is_completed())
            .finish()
    }
}

impl Default for Backoff {
    fn default() -> Backoff {
        Backoff::new()
    }
}

#[derive(Clone, Copy, Default, Hash, PartialEq, Eq)]
#[repr(align(64))]
pub struct CachePadded<T> {
    value: T,
}

unsafe impl<T: Send> Send for CachePadded<T> {}
unsafe impl<T: Sync> Sync for CachePadded<T> {}

impl<T> CachePadded<T> {
    pub const fn new(t: T) -> CachePadded<T> {
        CachePadded::<T> { value: t }
    }

    pub fn into_inner(self) -> T {
        self.value
    }
}

impl<T> Deref for CachePadded<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> DerefMut for CachePadded<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T: fmt::Debug> fmt::Debug for CachePadded<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachePadded")
            .field("value", &self.value)
            .finish()
    }
}

impl<T> From<T> for CachePadded<T> {
    fn from(t: T) -> Self {
        CachePadded::new(t)
    }
}

struct Slot<T> {
    stamp: AtomicUsize,
    value: UnsafeCell<MaybeUninit<T>>,
}

pub struct ArrayQueue<T> {
    head: CachePadded<AtomicUsize>,
    tail: CachePadded<AtomicUsize>,
    buffer: Box<[Slot<T>]>,
    cap: usize,
    one_lap: usize,
}

unsafe impl<T: Send> Sync for ArrayQueue<T> {}
unsafe impl<T: Send> Send for ArrayQueue<T> {}

impl<T> ArrayQueue<T> {
    pub fn new(cap: usize) -> ArrayQueue<T> {
        assert!(cap > 0, "capacity must be non-zero");

        // Head is initialized to `{ lap: 0, index: 0 }`.
        // Tail is initialized to `{ lap: 0, index: 0 }`.
        let head = 0;
        let tail = 0;

        // Allocate a buffer of `cap` slots initialized
        // with stamps.
        let buffer: Box<[Slot<T>]> = (0..cap)
            .map(|i| {
                // Set the stamp to `{ lap: 0, index: i }`.
                Slot {
                    stamp: AtomicUsize::new(i),
                    value: UnsafeCell::new(MaybeUninit::uninit()),
                }
            })
            .collect();

        // One lap is the smallest power of two greater than `cap`.
        let one_lap = (cap + 1).next_power_of_two();

        ArrayQueue {
            buffer,
            cap,
            one_lap,
            head: CachePadded::new(AtomicUsize::new(head)),
            tail: CachePadded::new(AtomicUsize::new(tail)),
        }
    }

    fn push_or_else<F>(&self, mut value: T, f: F) -> Result<(), T>
    where
        F: Fn(T, usize, usize, &Slot<T>) -> Result<T, T>,
    {
        let backoff = Backoff::new();
        let mut tail = self.tail.load(Ordering::Relaxed);

        loop {
            // Deconstruct the tail.
            let index = tail & (self.one_lap - 1);
            let lap = tail & !(self.one_lap - 1);

            let new_tail = if index + 1 < self.cap {
                // Same lap, incremented index.
                // Set to `{ lap: lap, index: index + 1 }`.
                tail + 1
            } else {
                // One lap forward, index wraps around to zero.
                // Set to `{ lap: lap.wrapping_add(1), index: 0 }`.
                lap.wrapping_add(self.one_lap)
            };

            // Inspect the corresponding slot.
            debug_assert!(index < self.buffer.len());
            let slot = unsafe { self.buffer.get_unchecked(index) };
            let stamp = slot.stamp.load(Ordering::Acquire);

            // If the tail and the stamp match, we may attempt to push.
            if tail == stamp {
                // Try moving the tail.
                match self.tail.compare_exchange_weak(
                    tail,
                    new_tail,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // Write the value into the slot and update the stamp.
                        unsafe {
                            slot.value.get().write(MaybeUninit::new(value));
                        }
                        slot.stamp.store(tail + 1, Ordering::Release);
                        return Ok(());
                    }
                    Err(t) => {
                        tail = t;
                        backoff.spin();
                    }
                }
            } else if stamp.wrapping_add(self.one_lap) == tail + 1 {
                atomic::fence(Ordering::SeqCst);
                value = f(value, tail, new_tail, slot)?;
                backoff.spin();
                tail = self.tail.load(Ordering::Relaxed);
            } else {
                // Snooze because we need to wait for the stamp to get updated.
                backoff.snooze();
                tail = self.tail.load(Ordering::Relaxed);
            }
        }
    }

    pub fn push(&self, value: T) -> Result<(), T> {
        self.push_or_else(value, |v, tail, _, _| {
            let head = self.head.load(Ordering::Relaxed);

            // If the head lags one lap behind the tail as well...
            if head.wrapping_add(self.one_lap) == tail {
                // ...then the queue is full.
                Err(v)
            } else {
                Ok(v)
            }
        })
    }

    pub fn force_push(&self, value: T) -> Option<T> {
        self.push_or_else(value, |v, tail, new_tail, slot| {
            let head = tail.wrapping_sub(self.one_lap);
            let new_head = new_tail.wrapping_sub(self.one_lap);

            // Try moving the head.
            if self
                .head
                .compare_exchange_weak(head, new_head, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                // Move the tail.
                self.tail.store(new_tail, Ordering::SeqCst);

                // Swap the previous value.
                let old = unsafe { slot.value.get().replace(MaybeUninit::new(v)).assume_init() };

                // Update the stamp.
                slot.stamp.store(tail + 1, Ordering::Release);

                Err(old)
            } else {
                Ok(v)
            }
        })
        .err()
    }

    pub fn pop(&self) -> Option<T> {
        let backoff = Backoff::new();
        let mut head = self.head.load(Ordering::Relaxed);

        loop {
            // Deconstruct the head.
            let index = head & (self.one_lap - 1);
            let lap = head & !(self.one_lap - 1);

            // Inspect the corresponding slot.
            debug_assert!(index < self.buffer.len());
            let slot = unsafe { self.buffer.get_unchecked(index) };
            let stamp = slot.stamp.load(Ordering::Acquire);

            // If the the stamp is ahead of the head by 1, we may attempt to pop.
            if head + 1 == stamp {
                let new = if index + 1 < self.cap {
                    // Same lap, incremented index.
                    // Set to `{ lap: lap, index: index + 1 }`.
                    head + 1
                } else {
                    // One lap forward, index wraps around to zero.
                    // Set to `{ lap: lap.wrapping_add(1), index: 0 }`.
                    lap.wrapping_add(self.one_lap)
                };

                // Try moving the head.
                match self.head.compare_exchange_weak(
                    head,
                    new,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        // Read the value from the slot and update the stamp.
                        let msg = unsafe { slot.value.get().read().assume_init() };
                        slot.stamp
                            .store(head.wrapping_add(self.one_lap), Ordering::Release);
                        return Some(msg);
                    }
                    Err(h) => {
                        head = h;
                        backoff.spin();
                    }
                }
            } else if stamp == head {
                atomic::fence(Ordering::SeqCst);
                let tail = self.tail.load(Ordering::Relaxed);

                // If the tail equals the head, that means the channel is empty.
                if tail == head {
                    return None;
                }

                backoff.spin();
                head = self.head.load(Ordering::Relaxed);
            } else {
                // Snooze because we need to wait for the stamp to get updated.
                backoff.snooze();
                head = self.head.load(Ordering::Relaxed);
            }
        }
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    pub fn is_empty(&self) -> bool {
        let head = self.head.load(Ordering::SeqCst);
        let tail = self.tail.load(Ordering::SeqCst);

        // Is the tail lagging one lap behind head?
        // Is the tail equal to the head?
        //
        // Note: If the head changes just before we load the tail, that means there was a moment
        // when the channel was not empty, so it is safe to just return `false`.
        tail == head
    }

    pub fn is_full(&self) -> bool {
        let tail = self.tail.load(Ordering::SeqCst);
        let head = self.head.load(Ordering::SeqCst);

        // Is the head lagging one lap behind tail?
        //
        // Note: If the tail changes just before we load the head, that means there was a moment
        // when the queue was not full, so it is safe to just return `false`.
        head.wrapping_add(self.one_lap) == tail
    }

    pub fn len(&self) -> usize {
        loop {
            // Load the tail, then load the head.
            let tail = self.tail.load(Ordering::SeqCst);
            let head = self.head.load(Ordering::SeqCst);

            // If the tail didn't change, we've got consistent values to work with.
            if self.tail.load(Ordering::SeqCst) == tail {
                let hix = head & (self.one_lap - 1);
                let tix = tail & (self.one_lap - 1);

                return if hix < tix {
                    tix - hix
                } else if hix > tix {
                    self.cap - hix + tix
                } else if tail == head {
                    0
                } else {
                    self.cap
                };
            }
        }
    }
}

impl<T> Drop for ArrayQueue<T> {
    fn drop(&mut self) {
        // Get the index of the head.
        let head = *self.head.get_mut();
        let tail = *self.tail.get_mut();

        let hix = head & (self.one_lap - 1);
        let tix = tail & (self.one_lap - 1);

        let len = if hix < tix {
            tix - hix
        } else if hix > tix {
            self.cap - hix + tix
        } else if tail == head {
            0
        } else {
            self.cap
        };

        // Loop over all slots that hold a message and drop them.
        for i in 0..len {
            // Compute the index of the next slot holding a message.
            let index = if hix + i < self.cap {
                hix + i
            } else {
                hix + i - self.cap
            };

            unsafe {
                debug_assert!(index < self.buffer.len());
                let slot = self.buffer.get_unchecked_mut(index);
                let value = &mut *slot.value.get();
                value.as_mut_ptr().drop_in_place();
            }
        }
    }
}

impl<T> fmt::Debug for ArrayQueue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad("ArrayQueue { .. }")
    }
}

impl<T> IntoIterator for ArrayQueue<T> {
    type Item = T;

    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter { value: self }
    }
}

#[derive(Debug)]
pub struct IntoIter<T> {
    value: ArrayQueue<T>,
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let value = &mut self.value;
        let head = *value.head.get_mut();
        if value.head.get_mut() != value.tail.get_mut() {
            let index = head & (value.one_lap - 1);
            let lap = head & !(value.one_lap - 1);
            // SAFETY: We have mutable access to this, so we can read without
            // worrying about concurrency. Furthermore, we know this is
            // initialized because it is the value pointed at by `value.head`
            // and this is a non-empty queue.
            let val = unsafe {
                debug_assert!(index < value.buffer.len());
                let slot = value.buffer.get_unchecked_mut(index);
                slot.value.get().read().assume_init()
            };
            let new = if index + 1 < value.cap {
                // Same lap, incremented index.
                // Set to `{ lap: lap, index: index + 1 }`.
                head + 1
            } else {
                // One lap forward, index wraps around to zero.
                // Set to `{ lap: lap.wrapping_add(1), index: 0 }`.
                lap.wrapping_add(value.one_lap)
            };
            *value.head.get_mut() = new;
            Some(val)
        } else {
            None
        }
    }
}

pub struct SpinLock<T: ?Sized> {
    lock_word: AtomicU32, // Unlocked == 0.
    data: UnsafeCell<T>,
}

#[derive(Debug)]
pub struct LockGuard<'a, T: ?Sized> {
    lock_word: &'a AtomicU32,
    data: &'a mut T,
}

unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}
unsafe impl<T: ?Sized + Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    pub const fn new(user_data: T) -> SpinLock<T> {
        SpinLock {
            lock_word: AtomicU32::new(0),
            data: UnsafeCell::new(user_data),
        }
    }
}

impl<T: ?Sized> SpinLock<T> {
    fn obtain_lock(&self, lockword: u32) {
        assert_ne!(0, lockword);
        let mut outer_iter = 0_u64;
        while self
            .lock_word
            .compare_exchange(0, lockword, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            outer_iter += 1;
            if outer_iter > 1_000 {
                panic!(
                    "spinlock outer deadlock: {} => {}",
                    self.lock_word.load(Ordering::Acquire),
                    lockword
                )
            }
            // Wait until the lock looks unlocked before retrying.
            let mut inner_iter = 0_u64;
            while self.lock_word.load(Ordering::Relaxed) != 0 {
                inner_iter += 1;
                if inner_iter > 100_000_000 {
                    panic!(
                        "spinlock inner deadlock: {} => {}",
                        self.lock_word.load(Ordering::Acquire),
                        lockword
                    )
                }
                core::hint::spin_loop();
            }
        }
    }

    pub fn lock(&self, lockword: u32) -> LockGuard<'_, T> {
        self.obtain_lock(lockword);
        LockGuard {
            lock_word: &self.lock_word,
            data: unsafe { &mut *self.data.get() },
        }
    }
}

impl<T: ?Sized + Default> Default for SpinLock<T> {
    fn default() -> SpinLock<T> {
        SpinLock::new(Default::default())
    }
}

impl<'a, T: ?Sized> Deref for LockGuard<'a, T> {
    type Target = T;
    fn deref<'b>(&'b self) -> &'b T {
        &*self.data
    }
}

impl<'a, T: ?Sized> DerefMut for LockGuard<'a, T> {
    fn deref_mut<'b>(&'b mut self) -> &'b mut T {
        &mut *self.data
    }
}

impl<'a, T: ?Sized> Drop for LockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock_word.store(0, Ordering::SeqCst);
    }
}
