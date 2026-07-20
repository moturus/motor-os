//! Runtime to support I/O and polling mechanisms.
//!
//! Somewhat similar to Linux's epoll, but supports only edge-triggered events.
//!
//! Note: when an FD is closed "on our side", no HANGUP events are triggered.

use core::any::Any;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

use moto_async::SyncWaiter;

use crate::posix;
use crate::posix::PosixFile;
use crate::posix::PosixKind;
use alloc::collections::btree_map::BTreeMap;
use alloc::collections::vec_deque::VecDeque;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use moto_ipc::io_channel;
use moto_rt::E_BAD_HANDLE;
use moto_rt::E_INVALID_ARGUMENT;
use moto_rt::E_OK;
use moto_rt::E_TIMED_OUT;
use moto_rt::ErrorCode;
use moto_rt::RtFd;
use moto_rt::poll::Event;
use moto_rt::poll::EventBits;
use moto_rt::poll::Interests;
use moto_rt::poll::Token;
use moto_rt::spinlock::SpinLock;
use moto_sys::SysHandle;

/// A leaf object that can be waited on.
///
/// Event sources are flat, they either represent sockets (and, later, files)
/// directly, or a user-managed EventObject, which is similar to eventfd in Linux.
/// Event sources are owned by their parent objects (e.g. sockets);
/// but an event source can be added to multiple "Registries" with different tokens.
///
struct EventSourceBase<MaybeBits> {
    // A single object, e.g. a TCP socket, can have multiple FDs, and these
    // FDs can be polled by multiple registries (many-to-many).
    // (Registry ID, SourceFd) -> (Token, Interests, V).
    #[allow(clippy::type_complexity)]
    registries: SpinLock<BTreeMap<(u64, RtFd), (Token, Interests, MaybeBits)>>,
    supported_interests: Interests,
}

impl<MaybeBits> EventSourceBase<MaybeBits> {
    fn new(supported_interests: Interests) -> Self {
        Self {
            registries: SpinLock::new(BTreeMap::new()),
            supported_interests,
        }
    }

    fn add_interests(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
        zero: MaybeBits,
    ) -> Result<(), ErrorCode> {
        if interests & !self.supported_interests != 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut registries = self.registries.lock();
        match registries.entry((r_id, source_fd)) {
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((token, interests, zero));
            }
            alloc::collections::btree_map::Entry::Occupied(_) => return Err(E_INVALID_ARGUMENT),
        }
        Ok(())
    }

    fn set_interests(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
        zero: MaybeBits,
    ) -> Result<(), ErrorCode> {
        if interests & !self.supported_interests != 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let mut registries = self.registries.lock();
        if let Some(val) = registries.get_mut(&(r_id, source_fd)) {
            *val = (token, interests, zero);
            Ok(())
        } else {
            Err(E_INVALID_ARGUMENT)
        }
    }

    fn del_interests(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        let Some((token, interests, _)) = self.registries.lock().remove(&(r_id, source_fd)) else {
            return Err(E_INVALID_ARGUMENT);
        };

        if let Some(registry) = Option::flatten(REGISTRIES.lock().get(&r_id).map(|r| r.upgrade())) {
            registry.clear_event_bits(token, interests);
        }

        Ok(())
    }

    fn on_closed_locally(&self, source_fd: RtFd) {
        self.registries
            .lock()
            .retain(|&(_, s_fd), _| s_fd != source_fd)
    }
}

// An event source that is managed by an internal I/O thread.
pub struct EventSourceManaged {
    base: EventSourceBase<()>,
}

impl EventSourceManaged {
    pub fn new(supported_interests: Interests) -> Self {
        Self {
            base: EventSourceBase::new(supported_interests),
        }
    }

    pub fn add_interests(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        if REGISTRIES.lock().get(&r_id).is_none() {
            return Err(E_BAD_HANDLE);
        }
        self.base
            .add_interests(r_id, source_fd, token, interests, ())
    }

    pub fn set_interests(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.base
            .set_interests(r_id, source_fd, token, interests, ())
    }

    pub fn del_interests(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        self.base.del_interests(r_id, source_fd)
    }

    pub fn on_event(&self, events: EventBits) {
        {
            // TODO: call registry.on_event() without holding the mutex.
            let mut dropped_registries = alloc::vec::Vec::new();
            let mut registries = self.base.registries.lock();
            for entry in &*registries {
                let ((r_id, s_fd), (token, interests, _)) = entry;
                // Update interests: *_CLOSED events are always of interest.
                let interests = interests
                    | moto_rt::poll::POLL_READ_CLOSED
                    | moto_rt::poll::POLL_WRITE_CLOSED
                    | moto_rt::poll::POLL_ERROR;
                if interests & events != 0 {
                    if let Some(registry) =
                        Option::flatten(REGISTRIES.lock().get(r_id).map(|r| r.upgrade()))
                    {
                        registry.on_event(*token, interests & events);
                    } else {
                        dropped_registries.push((*r_id, *s_fd));
                    }
                }
            }
            for id in dropped_registries {
                registries.remove(&id);
            }
        }
        // Blocking UDP recv/send no longer parks here (D5): a socket's own
        // waker list is woken directly at the RX / TX-ack points. This is
        // now purely the poll-registry notification.
    }

    pub fn on_closed_locally(&self, source_fd: RtFd) {
        self.base.on_closed_locally(source_fd);
    }
}

/// The veneer half of the Stage-F seam: a net socket's mio-agnostic readiness
/// edges become poll-ABI event bits here, then fan out via `on_event`. This
/// translation is deliberately outside the state machine so the latter stays
/// poll-agnostic.
impl crate::net::readiness::NetEventListener for EventSourceManaged {
    fn on_readiness(&self, edges: crate::net::readiness::Readiness) {
        use crate::net::readiness::Readiness;
        use moto_rt::poll;

        let mut bits: EventBits = 0;
        if edges.contains(Readiness::READABLE) {
            bits |= poll::POLL_READABLE;
        }
        if edges.contains(Readiness::WRITABLE) {
            bits |= poll::POLL_WRITABLE;
        }
        if edges.contains(Readiness::READ_CLOSED) {
            bits |= poll::POLL_READ_CLOSED;
        }
        if edges.contains(Readiness::WRITE_CLOSED) {
            bits |= poll::POLL_WRITE_CLOSED;
        }
        if edges.contains(Readiness::ERROR) {
            bits |= poll::POLL_ERROR;
        }
        self.on_event(bits);
    }
}

pub trait UnmanagedEventSourceHolder: Send + Sync {
    fn check_interests(&self, interests: Interests) -> EventBits;
    fn on_handle_error(&self);
}

// An event source that exposes a wait handle, watched by a readiness
// task on the core IO runtime.
pub struct EventSourceUnmanaged {
    wait_handle: SysHandle,
    base: EventSourceBase<EventBits>,
    owner: Weak<dyn UnmanagedEventSourceHolder>,
    closed: AtomicBool,
    task_spawned: AtomicBool,
}

/// Watches one source's wait handle and converts its level state into
/// edges pushed at every registered registry (design section 4). Holds
/// no strong ref: exits when the source dies or its handle goes bad.
async fn unmanaged_readiness_task(source: Weak<EventSourceUnmanaged>, wait_handle: SysHandle) {
    use moto_async::AsFuture;

    loop {
        let result = wait_handle.as_future().await;
        let Some(source) = source.upgrade() else {
            return;
        };

        if result.is_ok() {
            source.check_interests_all();
        } else {
            // The handle died: the remote end is gone, or the owner
            // closed it locally.
            source.on_handle_error();
            source.check_interests_all();
            return;
        }
    }
}

impl EventSourceUnmanaged {
    pub fn new(
        wait_handle: SysHandle,
        owner: Weak<dyn UnmanagedEventSourceHolder>,
        supported_interests: Interests,
    ) -> Arc<Self> {
        Arc::new(Self {
            wait_handle,
            base: EventSourceBase::new(supported_interests),
            owner,
            closed: AtomicBool::new(false),
            task_spawned: AtomicBool::new(false),
        })
    }

    pub fn add_interests(
        self: &Arc<Self>,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        if REGISTRIES.lock().get(&r_id).is_none() {
            return Err(E_BAD_HANDLE);
        }

        self.base
            .add_interests(r_id, source_fd, token, interests, 0 as EventBits)?;

        // Spawned on first registration, not in new(): sources are
        // built inside Arc::new_cyclic, and the task upgrades weak refs.
        if !self.task_spawned.swap(true, Ordering::AcqRel) {
            let source = Arc::downgrade(self);
            let wait_handle = self.wait_handle;
            crate::io_runtime::spawn(move || unmanaged_readiness_task(source, wait_handle));
        }

        // The task only sees handle edges; the level state at
        // registration time is reported here.
        self.check_interests_for_registry(r_id);
        Ok(())
    }

    pub fn set_interests(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.base
            .set_interests(r_id, source_fd, token, interests, 0 as EventBits)?;
        self.check_interests_for_registry(r_id);
        Ok(())
    }

    pub fn del_interests(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        self.base.del_interests(r_id, source_fd)
    }

    // Called by the owner when an interest becomes false (e.g. !readable).
    pub fn reset_interest(&self, interest: Interests) {
        let mut dropped_registries = alloc::vec::Vec::new();
        let mut registries = self.base.registries.lock();
        for entry in &mut *registries {
            let ((r_id, s_fd), (_token, _interests, events)) = entry;
            if interest & *events != 0 {
                if let Some(Some(registry)) = REGISTRIES.lock().get(r_id).map(|r| r.upgrade()) {
                    *events &= !interest;
                } else {
                    dropped_registries.push((*r_id, *s_fd));
                }
            }
        }
        for id in dropped_registries {
            registries.remove(&id);
        }
    }

    fn check_interests_for_registry(&self, reg_id: u64) {
        self.check_interests_filtered(Some(reg_id));
    }

    fn check_interests_all(&self) {
        self.check_interests_filtered(None);
    }

    // Checks if this object's owner has a new event to report to the
    // registries selected by `reg_filter` (None = all). Note that we must
    // convert "level-triggered events" into "edge-triggered events" here.
    fn check_interests_filtered(&self, reg_filter: Option<u64>) {
        // The owner may be mid-drop while its readiness task still runs.
        let Some(owner) = self.owner.upgrade() else {
            return;
        };

        let mut registries = self.base.registries.lock();
        let mut dropped_registries = alloc::vec::Vec::new();
        for entry in &mut *registries {
            let ((r_id, s_fd), (token, interests, events)) = entry;
            if reg_filter.is_some_and(|reg_id| reg_id != *r_id) {
                continue;
            }

            let (token, new_events) = {
                // Any not-yet-reported interests?
                let unreported_interests = *interests & !*events;
                if unreported_interests == 0 {
                    continue;
                }

                let mut new_events = owner.check_interests(unreported_interests);
                if new_events == 0 {
                    if self.closed.load(Ordering::Acquire) {
                        if *interests & moto_rt::poll::POLL_READABLE != 0 {
                            new_events |= moto_rt::poll::POLL_READ_CLOSED;
                        }
                        if *interests & moto_rt::poll::POLL_WRITABLE != 0 {
                            new_events |= moto_rt::poll::POLL_WRITE_CLOSED;
                        }

                        if new_events == 0 {
                            continue;
                        }
                    } else {
                        continue;
                    }
                } else {
                    *events |= new_events;
                }

                (*token, new_events)
            };

            if let Some(registry) = REGISTRIES.lock().get(r_id) {
                if let Some(registry) = registry.upgrade() {
                    registry.on_event(token, new_events);
                } else {
                    dropped_registries.push((*r_id, *s_fd));
                }
            } else {
                dropped_registries.push((*r_id, *s_fd));
            }
        }

        for id in dropped_registries {
            registries.remove(&id);
        }
    }

    pub fn on_closed_remotely(&self, leave_tombstones: bool) {
        self.closed.store(true, Ordering::Release);

        let mut registries = BTreeMap::new();
        #[allow(clippy::swap_with_temporary)]
        core::mem::swap(&mut registries, &mut self.base.registries.lock());

        if !leave_tombstones {
            return;
        }

        let mut tombstones = alloc::vec::Vec::new();
        for ((r_id, s_fd), (token, interests, _)) in registries {
            let mut events = 0;
            if interests & moto_rt::poll::POLL_READABLE != 0 {
                events |= moto_rt::poll::POLL_READ_CLOSED;
            }
            if interests & moto_rt::poll::POLL_WRITABLE != 0 {
                events |= moto_rt::poll::POLL_WRITE_CLOSED;
            }

            let event = moto_rt::poll::Event { token, events };
            tombstones.push((r_id, s_fd, event));
        }

        for (r_id, s_fd, tombstone) in tombstones {
            if let Some(registry) =
                Option::flatten(REGISTRIES.lock().get(&r_id).map(|r| r.upgrade()))
            {
                registry.add_tombstone(s_fd, tombstone);
            }
        }
    }

    fn on_handle_error(&self) {
        if let Some(owner) = self.owner.upgrade() {
            owner.on_handle_error();
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn on_closed_locally(&self, source_fd: RtFd) {
        self.base.on_closed_locally(source_fd);
    }
}

static REGISTRIES: SpinLock<BTreeMap<u64, Weak<Registry>>> = SpinLock::new(BTreeMap::new());

/// The delivery half of the registry's wait protocol (design section 6):
/// event producers call `wake()`, pollers park on the bridge parker.
///
/// wake() is sticky, so arm -> re-check -> park cannot lose a wakeup;
/// the price is occasional spurious returns, absorbed by the caller's
/// collect loop. The single-poller case (mio's `&mut Poll`) claims the
/// registry's own waiter with one CAS; concurrent extra pollers overflow
/// into a locked list of ad-hoc waiters, which makes multi-poller waits
/// correct -- the old single-slot protocol let one poller clobber
/// another's wake slot and sleep through its events.
struct PollerSlot {
    fast_waiter: SyncWaiter,
    fast_taken: AtomicBool,
    overflow: SpinLock<Vec<Arc<SyncWaiter>>>,
    overflow_waiters: AtomicUsize,
}

enum PollerTicket {
    Fast,
    Overflow(Arc<SyncWaiter>),
}

impl PollerSlot {
    fn new() -> Self {
        Self {
            fast_waiter: SyncWaiter::new(),
            fast_taken: AtomicBool::new(false),
            overflow: SpinLock::new(Vec::new()),
            overflow_waiters: AtomicUsize::new(0),
        }
    }

    /// Claim a waiter. Wakes after this reach us; the caller must
    /// re-check for events pushed before it, between arm() and park().
    fn arm(&self) -> PollerTicket {
        if self
            .fast_taken
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return PollerTicket::Fast;
        }

        let waiter = Arc::new(SyncWaiter::new());
        self.overflow.lock().push(waiter.clone());
        // The SeqCst RMW pairs with the fence in wake(): either wake()
        // sees the count, or we see its events in the re-check.
        self.overflow_waiters.fetch_add(1, Ordering::SeqCst);
        PollerTicket::Overflow(waiter)
    }

    fn park(&self, ticket: &PollerTicket, deadline: Option<moto_rt::time::Instant>) {
        match ticket {
            PollerTicket::Fast => self.fast_waiter.wait(deadline),
            PollerTicket::Overflow(waiter) => waiter.wait(deadline),
        }
    }

    fn disarm(&self, ticket: PollerTicket) {
        match ticket {
            PollerTicket::Fast => self.fast_taken.store(false, Ordering::Release),
            PollerTicket::Overflow(waiter) => {
                self.overflow
                    .lock()
                    .retain(|other| !Arc::ptr_eq(other, &waiter));
                self.overflow_waiters.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    /// Wake parked pollers. Callable from any thread.
    fn wake(&self) {
        // Unconditional: a signal with no waiter is remembered and
        // consumed by the next park, which then re-checks for events.
        self.fast_waiter.signal();

        // Pairs with the SeqCst RMW in arm(); the caller published its
        // events before calling us.
        core::sync::atomic::fence(Ordering::SeqCst);
        if self.overflow_waiters.load(Ordering::Relaxed) > 0 {
            for waiter in self.overflow.lock().iter() {
                waiter.signal();
            }
        }
    }
}

pub struct Registry {
    id: u64,
    events: SpinLock<BTreeMap<Token, EventBits>>,
    poller: PollerSlot,
    event_source: EventSourceManaged,

    // We need to keep week refs to added sources, otherwise fds are reused and bugs ensue.
    // We also need a way to remove waiting_handle_objects on poll_del (so that no
    // events occur), and we need to keep smth to respond with HANGUP when the file
    // is closed by before poll_del().
    pollees: SpinLock<BTreeMap<RtFd, Weak<dyn PosixFile>>>,

    // When a pollee goes away, it may leave a tombstone here if needed for
    // POLL_READ_CLOSED/POLL_WRITE_CLOSED.
    tombstones: SpinLock<BTreeMap<RtFd, Event>>,
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = REGISTRIES.lock().remove(&self.id);
    }
}

impl PosixFile for Registry {
    fn kind(&self) -> PosixKind {
        PosixKind::PollRegistry
    }

    fn poll_add(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        if interests != moto_rt::poll::POLL_READABLE {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        self.event_source
            .add_interests(r_id, source_fd, token, interests)?;
        Ok(())
    }

    fn poll_set(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        if interests != moto_rt::poll::POLL_READABLE {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        self.event_source
            .set_interests(r_id, source_fd, token, interests)?;
        Ok(())
    }

    fn poll_del(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        self.event_source.del_interests(r_id, source_fd)
    }

    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        Ok(())
    }
}

impl Registry {
    pub fn new() -> Arc<Self> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

        let result = Arc::new(Self {
            id,
            events: SpinLock::new(BTreeMap::new()),
            poller: PollerSlot::new(),
            event_source: EventSourceManaged::new(moto_rt::poll::POLL_READABLE),
            pollees: SpinLock::new(BTreeMap::new()),
            tombstones: SpinLock::new(BTreeMap::new()),
        });

        REGISTRIES.lock().insert(id, Arc::downgrade(&result));
        result
    }

    pub fn add(&self, source_fd: RtFd, token: Token, interests: Interests) -> ErrorCode {
        let Some(posix_file) = posix::get_file(source_fd) else {
            return E_BAD_HANDLE;
        };

        if let Err(err) = posix_file.poll_add(self.id, source_fd, token, interests) {
            err
        } else {
            assert!(
                self.pollees
                    .lock()
                    .insert(source_fd, Arc::downgrade(&posix_file))
                    .is_none()
            );
            E_OK
        }
    }

    pub fn set(&self, source_fd: RtFd, token: Token, interests: Interests) -> ErrorCode {
        let Some(posix_file) = self.pollees.lock().get(&source_fd).cloned() else {
            return E_BAD_HANDLE;
        };

        let Some(posix_file) = posix_file.upgrade() else {
            return E_BAD_HANDLE;
        };

        if let Err(err) = posix_file.poll_set(self.id, source_fd, token, interests) {
            err
        } else {
            E_OK
        }
    }

    pub fn del(&self, source_fd: RtFd) -> ErrorCode {
        let Some(posix_file) = self.pollees.lock().remove(&source_fd) else {
            return E_BAD_HANDLE;
        };

        let _ = self.tombstones.lock().remove(&source_fd);

        let Some(posix_file) = posix_file.upgrade() else {
            return E_OK;
        };

        if let Err(err) = posix_file.poll_del(self.id, source_fd) {
            err
        } else {
            E_OK
        }
    }

    fn clear_event_bits(&self, token: Token, event_bits: EventBits) {
        let mut events = self.events.lock();
        if let alloc::collections::btree_map::Entry::Occupied(mut entry) = events.entry(token) {
            *entry.get_mut() &= !event_bits;
            if *entry.get() == 0 {
                entry.remove();
            }
        }
    }

    pub fn wake(&self) -> ErrorCode {
        self.event_source.on_event(moto_rt::poll::POLL_READABLE);
        E_OK
    }

    pub fn wait(&self, events_buf: &mut [Event], deadline: Option<moto_rt::time::Instant>) -> i32 {
        if events_buf.is_empty() {
            return 0;
        }

        loop {
            // Collect phase: tombstones are returned alone, ahead of
            // regular events.
            let collected = self.collect_tombstones(events_buf);
            if collected > 0 {
                return collected as i32;
            }

            // Wait phase: arm before the event check (see arm()).
            let ticket = self.poller.arm();

            let collected = self.collect_events(events_buf);
            if collected > 0 {
                self.poller.disarm(ticket);
                return collected as i32;
            }

            self.poller.park(&ticket, deadline);
            // The claim is only needed while parked.
            self.poller.disarm(ticket);

            let collected = self.collect_events(events_buf);
            if collected > 0 {
                return collected as i32;
            }

            // MIO docs for poll() say that upon timeout poll() returns OK(()),
            // and MIO tests (specifically tcp::listen_then_close()) rely on this.
            if let Some(deadline) = deadline
                && moto_rt::time::Instant::now() >= deadline
            {
                return 0;
            }
        }
    }

    /// Collect closed-pollee tombstones into `events_buf`. Tombstones
    /// are delivered ahead of, and never mixed with, regular events.
    fn collect_tombstones(&self, events_buf: &mut [Event]) -> usize {
        let mut idx = 0;
        while idx < events_buf.len() {
            let Some((_, event)) = self.tombstones.lock().pop_first() else {
                break;
            };
            events_buf[idx] = event;
            idx += 1;
        }
        idx
    }

    /// Drain accumulated (token, bits) events into `events_buf`.
    fn collect_events(&self, events_buf: &mut [Event]) -> usize {
        let mut events = self.events.lock();
        let mut idx = 0;
        while idx < events_buf.len() {
            let Some((token, bits)) = events.pop_first() else {
                break;
            };
            events_buf[idx] = Event {
                token,
                events: bits,
            };
            idx += 1;
        }
        idx
    }

    fn on_event(&self, token: Token, event_bits: EventBits) {
        self.events
            .lock()
            .entry(token)
            .and_modify(|curr| *curr |= event_bits)
            .or_insert(event_bits);

        self.poller.wake();
    }

    fn add_tombstone(&self, source_fd: RtFd, tombstone: Event) {
        self.tombstones.lock().insert(source_fd, tombstone);
        self.poller.wake();
    }
}
