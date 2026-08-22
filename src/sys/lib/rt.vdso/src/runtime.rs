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

/// Every event bit that could have been queued for a registration holding
/// `interests`.
///
/// Delivery ors the closed/error bits in whether or not they were asked
/// for, so retiring a registration has to clear those too: a bit left
/// behind is handed to the next poller under a token whose owner is gone,
/// which for mio's users is a pointer they have already freed.
fn deliverable(interests: Interests) -> EventBits {
    interests
        | moto_rt::poll::POLL_READ_CLOSED
        | moto_rt::poll::POLL_WRITE_CLOSED
        | moto_rt::poll::POLL_ERROR
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RegLifecycle {
    Adding,
    Active,
    Retired,
}

struct RegState {
    token: Token,
    interests: Interests,
    queued: EventBits,
    reported: EventBits,
    pending: bool,
    lifecycle: RegLifecycle,
}

pub(crate) struct Registration {
    registry: Weak<Registry>,
    source: Weak<dyn PosixFile>,
    r_id: u64,
    source_fd: RtFd,
    state: SpinLock<RegState>,
}

enum DeliveryResult {
    Keep,
    Remove,
}

impl Registration {
    fn new(
        registry: Weak<Registry>,
        source: Weak<dyn PosixFile>,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry,
            source,
            r_id,
            source_fd,
            state: SpinLock::new(RegState {
                token,
                interests,
                queued: 0,
                reported: 0,
                pending: false,
                lifecycle: RegLifecycle::Adding,
            }),
        })
    }

    fn key(&self) -> (u64, RtFd) {
        (self.r_id, self.source_fd)
    }

    pub(crate) fn terms(&self) -> (Token, Interests) {
        let state = self.state.lock();
        (state.token, state.interests)
    }

    fn is_live_for(&self, source: &Arc<dyn PosixFile>) -> bool {
        self.state.lock().lifecycle != RegLifecycle::Retired
            && self
                .source
                .upgrade()
                .is_some_and(|current| Arc::ptr_eq(&current, source))
    }

    fn deliver(self: &Arc<Self>, events: EventBits) -> DeliveryResult {
        let Some(registry) = self.registry.upgrade() else {
            return DeliveryResult::Remove;
        };

        let mut state = self.state.lock();
        if state.lifecycle == RegLifecycle::Retired {
            return DeliveryResult::Remove;
        }
        let events = events & deliverable(state.interests);
        if events == 0 {
            return DeliveryResult::Keep;
        }

        state.queued |= events;
        let wake = if state.lifecycle == RegLifecycle::Active && !state.pending {
            state.pending = true;
            registry.ready.lock().push_back(self.clone());
            true
        } else {
            false
        };
        drop(state);

        if wake {
            registry.poller.wake();
        }
        DeliveryResult::Keep
    }

    fn activate(self: &Arc<Self>) -> bool {
        let Some(registry) = self.registry.upgrade() else {
            return false;
        };
        let mut state = self.state.lock();
        if state.lifecycle != RegLifecycle::Adding {
            return false;
        }
        state.lifecycle = RegLifecycle::Active;
        let wake = state.queued != 0 && !state.pending;
        if wake {
            state.pending = true;
            registry.ready.lock().push_back(self.clone());
        }
        drop(state);
        if wake {
            registry.poller.wake();
        }
        true
    }

    /// Retires the registration. Returns whether this call performed the
    /// retirement -- `false` means something else (a local close, a
    /// replacing add) got there first.
    fn retire(self: &Arc<Self>) -> bool {
        let registry = self.registry.upgrade();
        let mut state = self.state.lock();
        if state.lifecycle == RegLifecycle::Retired {
            return false;
        }
        state.lifecycle = RegLifecycle::Retired;
        state.queued = 0;
        if state.pending {
            state.pending = false;
            if let Some(registry) = registry {
                registry
                    .ready
                    .lock()
                    .retain(|queued| !Arc::ptr_eq(queued, self));
            }
        }
        true
    }
}

/// A leaf object that can be waited on.
///
/// Event sources are flat, they either represent sockets (and, later, files)
/// directly, or a user-managed EventObject, which is similar to eventfd in Linux.
/// Event sources are owned by their parent objects (e.g. sockets);
/// but an event source can be added to multiple "Registries" with different tokens.
///
struct EventSourceBase {
    // A single object, e.g. a TCP socket, can have multiple FDs, and these
    // FDs can be polled by multiple registries (many-to-many).
    registries: SpinLock<BTreeMap<(u64, RtFd), Arc<Registration>>>,
    supported_interests: Interests,
}

impl EventSourceBase {
    fn new(supported_interests: Interests) -> Self {
        Self {
            registries: SpinLock::new(BTreeMap::new()),
            supported_interests,
        }
    }

    fn add_interests(&self, registration: &Arc<Registration>) -> Result<(), ErrorCode> {
        let (_, interests) = registration.terms();
        if interests & !self.supported_interests != 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let mut registries = self.registries.lock();
        match registries.entry(registration.key()) {
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(registration.clone());
            }
            alloc::collections::btree_map::Entry::Occupied(_) => return Err(E_INVALID_ARGUMENT),
        }
        Ok(())
    }

    fn set_interests(
        &self,
        registration: &Arc<Registration>,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        if interests & !self.supported_interests != 0 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        let registries = self.registries.lock();
        if !registries
            .get(&registration.key())
            .is_some_and(|current| Arc::ptr_eq(current, registration))
        {
            return Err(E_INVALID_ARGUMENT);
        }

        let mut state = registration.state.lock();
        if state.lifecycle != RegLifecycle::Active {
            return Err(E_INVALID_ARGUMENT);
        }
        state.token = token;
        state.interests = interests;
        state.queued &= deliverable(interests);
        state.reported = 0;
        Ok(())
    }

    fn del_interests(&self, registration: &Arc<Registration>) -> Result<(), ErrorCode> {
        let mut registries = self.registries.lock();
        if !registries
            .get(&registration.key())
            .is_some_and(|current| Arc::ptr_eq(current, registration))
        {
            return Err(E_INVALID_ARGUMENT);
        }
        registries.remove(&registration.key());
        Ok(())
    }

    fn remove_if(&self, registration: &Arc<Registration>) -> bool {
        self.del_interests(registration).is_ok()
    }

    fn on_closed_locally(&self, source_fd: RtFd) {
        let mut closed = alloc::vec::Vec::new();
        self.registries.lock().retain(|&(_, s_fd), registration| {
            if s_fd == source_fd {
                closed.push(registration.clone());
                false
            } else {
                true
            }
        });

        for registration in closed {
            registration.retire();
        }
    }
}

// An event source that is managed by an internal I/O thread.
pub struct EventSourceManaged {
    base: EventSourceBase,
}

impl EventSourceManaged {
    pub fn new(supported_interests: Interests) -> Self {
        Self {
            base: EventSourceBase::new(supported_interests),
        }
    }

    pub fn add_interests(&self, registration: &Arc<Registration>) -> Result<(), ErrorCode> {
        self.base.add_interests(registration)
    }

    pub fn set_interests(
        &self,
        registration: &Arc<Registration>,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.base.set_interests(registration, token, interests)
    }

    pub fn del_interests(&self, registration: &Arc<Registration>) -> Result<(), ErrorCode> {
        self.base.del_interests(registration)
    }

    pub fn on_event(&self, events: EventBits) {
        {
            let mut dropped_registries = alloc::vec::Vec::new();
            let registries = self.base.registries.lock();
            for registration in registries.values() {
                if matches!(registration.deliver(events), DeliveryResult::Remove) {
                    dropped_registries.push(registration.clone());
                }
            }
            drop(registries);
            for registration in dropped_registries {
                self.base.remove_if(&registration);
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
impl moto_io::net::readiness::NetEventListener for EventSourceManaged {
    fn on_readiness(&self, edges: moto_io::net::readiness::Readiness) {
        use moto_io::net::readiness::Readiness;
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
    // The readiness task's own handle to the same object (0 = none). The
    // kernel's missed-wake latch is per handle: a task sharing `wait_handle`
    // could consume a wake that a concurrent blocking read/write on the
    // handle needed, leaving that thread parked with data pending.
    task_handle: AtomicU64,
    base: EventSourceBase,
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
            source.release_task_handle();
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
            task_handle: AtomicU64::new(0),
            base: EventSourceBase::new(supported_interests),
            owner,
            closed: AtomicBool::new(false),
            task_spawned: AtomicBool::new(false),
        })
    }

    fn release_task_handle(&self) {
        let handle = self.task_handle.swap(0, Ordering::AcqRel);
        if handle != 0 {
            let _ = moto_sys::SysObj::put(SysHandle::from_u64(handle));
        }
    }

    pub fn add_interests(
        self: &Arc<Self>,
        registration: &Arc<Registration>,
    ) -> Result<(), ErrorCode> {
        self.base.add_interests(registration)?;

        // Spawned on first registration, not in new(): sources are
        // built inside Arc::new_cyclic, and the task upgrades weak refs.
        if !self.task_spawned.swap(true, Ordering::AcqRel) {
            // If the dup fails (the handle is already dead), fall back to
            // sharing wait_handle: the task exits on its first wait error.
            let task_handle = match moto_sys::SysObj::dup(self.wait_handle) {
                Ok(handle) => {
                    self.task_handle.store(handle.as_u64(), Ordering::Release);
                    handle
                }
                Err(_) => self.wait_handle,
            };
            let source = Arc::downgrade(self);
            crate::io_runtime::spawn(move || unmanaged_readiness_task(source, task_handle));
        }

        // The task only sees handle edges; the level state at
        // registration time is reported here.
        self.check_interests_for_registration(registration);
        Ok(())
    }

    pub fn set_interests(
        &self,
        registration: &Arc<Registration>,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.base.set_interests(registration, token, interests)?;
        self.check_interests_for_registration(registration);
        Ok(())
    }

    pub fn del_interests(&self, registration: &Arc<Registration>) -> Result<(), ErrorCode> {
        self.base.del_interests(registration)
    }

    /// Clear `interest` where it was reported, then report it again if the
    /// owner still has it.
    ///
    /// Clearing it only when the level reads false is not the same thing: an
    /// arrival between the operation and that read keeps the level true, so
    /// nothing is cleared -- and a registry holds an interest reported until
    /// it is, which makes every later arrival unreportable too.
    pub fn rearm_interest(&self, interest: Interests) {
        if self.base.registries.lock().is_empty() {
            return;
        }
        self.reset_interest(interest);
        self.check_interests_all();
    }

    // Called by the owner when an interest becomes false (e.g. !readable).
    pub fn reset_interest(&self, interest: Interests) {
        let mut registries = self.base.registries.lock();
        registries.retain(|_, registration| {
            if registration.registry.upgrade().is_none() {
                return false;
            }
            let mut state = registration.state.lock();
            if state.lifecycle == RegLifecycle::Retired {
                return false;
            }
            state.reported &= !interest;
            true
        });
    }

    fn check_interests_for_registration(&self, registration: &Arc<Registration>) {
        self.check_interests_filtered(Some(registration));
    }

    /// Report the current level state at every registry.
    ///
    /// The readiness task calls this on a handle edge; an owner whose
    /// readiness can change with no edge behind it (stdio's relay stash)
    /// calls it itself.
    pub fn check_interests_all(&self) {
        self.check_interests_filtered(None);
    }

    // Checks if this object's owner has a new event to report to the
    // registries selected by `reg_filter` (None = all). Note that we must
    // convert "level-triggered events" into "edge-triggered events" here.
    fn check_interests_filtered(&self, reg_filter: Option<&Arc<Registration>>) {
        // The owner may be mid-drop while its readiness task still runs.
        let Some(owner) = self.owner.upgrade() else {
            return;
        };

        let registries = self.base.registries.lock();
        let mut dropped_registries = alloc::vec::Vec::new();
        for registration in registries.values() {
            if reg_filter.is_some_and(|filter| !Arc::ptr_eq(filter, registration)) {
                continue;
            }

            let new_events = {
                let mut state = registration.state.lock();
                if state.lifecycle == RegLifecycle::Retired {
                    dropped_registries.push(registration.clone());
                    continue;
                }
                // Any not-yet-reported interests?
                let unreported_interests = state.interests & !state.reported;
                if unreported_interests == 0 {
                    continue;
                }

                let mut new_events = owner.check_interests(unreported_interests);
                if new_events == 0 {
                    if self.closed.load(Ordering::Acquire) {
                        if state.interests & moto_rt::poll::POLL_READABLE != 0 {
                            new_events |= moto_rt::poll::POLL_READ_CLOSED;
                        }
                        if state.interests & moto_rt::poll::POLL_WRITABLE != 0 {
                            new_events |= moto_rt::poll::POLL_WRITE_CLOSED;
                        }

                        if new_events == 0 {
                            continue;
                        }
                        state.reported |= state.interests
                            & (moto_rt::poll::POLL_READABLE | moto_rt::poll::POLL_WRITABLE);
                    } else {
                        continue;
                    }
                }
                state.reported |= new_events;

                new_events
            };

            if matches!(registration.deliver(new_events), DeliveryResult::Remove) {
                dropped_registries.push(registration.clone());
            }
        }

        drop(registries);
        for registration in dropped_registries {
            self.base.remove_if(&registration);
        }
    }

    pub fn on_closed_remotely(&self, leave_tombstones: bool) {
        self.closed.store(true, Ordering::Release);

        if !leave_tombstones {
            return;
        }

        let registries = self.base.registries.lock();
        let mut dropped_registries = alloc::vec::Vec::new();
        for registration in registries.values() {
            let mut state = registration.state.lock();
            if state.lifecycle == RegLifecycle::Retired {
                dropped_registries.push(registration.clone());
                continue;
            }
            let mut events = 0;
            if state.interests & moto_rt::poll::POLL_READABLE != 0 {
                events |= moto_rt::poll::POLL_READ_CLOSED;
            }
            if state.interests & moto_rt::poll::POLL_WRITABLE != 0 {
                events |= moto_rt::poll::POLL_WRITE_CLOSED;
            }
            state.reported |= state.interests;
            drop(state);
            if matches!(registration.deliver(events), DeliveryResult::Remove) {
                dropped_registries.push(registration.clone());
            }
        }
        drop(registries);
        for registration in dropped_registries {
            self.base.remove_if(&registration);
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

// The task holds only a Weak ref, so the source can be dropped while the
// task is parked; the put makes its next wait fail and the task exit.
impl Drop for EventSourceUnmanaged {
    fn drop(&mut self) {
        self.release_task_handle();
    }
}

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
    self_ref: Weak<Registry>,
    ready: SpinLock<VecDeque<Arc<Registration>>>,
    ops: moto_rt::mutex::Mutex<()>,
    poller: PollerSlot,
    event_source: EventSourceManaged,

    // Keep the registration, rather than only a weak source reference: the
    // object is the identity shared by the source map and ready queue.
    pollees: SpinLock<BTreeMap<RtFd, Arc<Registration>>>,
}

impl PosixFile for Registry {
    fn kind(&self) -> PosixKind {
        PosixKind::PollRegistry
    }

    fn descriptor_attr(
        &self,
        object_id: core::num::NonZeroU64,
    ) -> Result<moto_rt::fs::FileAttr, ErrorCode> {
        Ok(posix::synthetic_attr(
            moto_rt::fs::FILETYPE_ANONYMOUS,
            object_id,
        ))
    }

    fn poll_add(&self, registration: &Arc<Registration>) -> Result<(), ErrorCode> {
        let (_, interests) = registration.terms();
        if interests != moto_rt::poll::POLL_READABLE {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        self.event_source.add_interests(registration)?;
        Ok(())
    }

    fn poll_set(
        &self,
        registration: &Arc<Registration>,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        if interests != moto_rt::poll::POLL_READABLE {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        self.event_source
            .set_interests(registration, token, interests)?;
        Ok(())
    }

    fn poll_del(&self, registration: &Arc<Registration>) -> Result<(), ErrorCode> {
        self.event_source.del_interests(registration)
    }

    fn close(&self, rt_fd: RtFd) -> Result<(), ErrorCode> {
        self.event_source.on_closed_locally(rt_fd);
        Ok(())
    }
}

impl Registry {
    pub fn new() -> Arc<Self> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

        Arc::new_cyclic(|self_ref| Self {
            id,
            self_ref: self_ref.clone(),
            ready: SpinLock::new(VecDeque::new()),
            ops: moto_rt::mutex::Mutex::new(()),
            poller: PollerSlot::new(),
            event_source: EventSourceManaged::new(moto_rt::poll::POLL_READABLE),
            pollees: SpinLock::new(BTreeMap::new()),
        })
    }

    pub fn add(&self, source_fd: RtFd, token: Token, interests: Interests) -> ErrorCode {
        let _ops = self.ops.lock();
        let Some(posix_file) = posix::get_file(source_fd) else {
            return E_BAD_HANDLE;
        };

        let existing = self.pollees.lock().get(&source_fd).cloned();
        if let Some(existing) = existing {
            if existing.is_live_for(&posix_file) {
                return E_INVALID_ARGUMENT;
            }
            self.remove_pollee_if(source_fd, &existing);
            existing.retire();
            if let Some(source) = existing.source.upgrade() {
                let _ = source.poll_del(&existing);
            }
        }

        let registration = Registration::new(
            self.self_ref.clone(),
            Arc::downgrade(&posix_file),
            self.id,
            source_fd,
            token,
            interests,
        );
        if let Err(err) = posix_file.poll_add(&registration) {
            registration.retire();
            let _ = posix_file.poll_del(&registration);
            return err;
        }

        let Some(current) = posix::get_file(source_fd) else {
            registration.retire();
            let _ = posix_file.poll_del(&registration);
            return E_BAD_HANDLE;
        };
        if !Arc::ptr_eq(&current, &posix_file) {
            registration.retire();
            let _ = posix_file.poll_del(&registration);
            return E_BAD_HANDLE;
        }

        self.pollees.lock().insert(source_fd, registration.clone());
        if !registration.activate() {
            self.remove_pollee_if(source_fd, &registration);
            let _ = posix_file.poll_del(&registration);
            return E_BAD_HANDLE;
        }
        E_OK
    }

    pub fn set(&self, source_fd: RtFd, token: Token, interests: Interests) -> ErrorCode {
        let _ops = self.ops.lock();
        let Some(registration) = self.pollees.lock().get(&source_fd).cloned() else {
            return E_BAD_HANDLE;
        };
        let Some(posix_file) = registration.source.upgrade() else {
            return E_BAD_HANDLE;
        };
        let Some(current) = posix::get_file(source_fd) else {
            return E_BAD_HANDLE;
        };
        if !Arc::ptr_eq(&current, &posix_file) || !registration.is_live_for(&posix_file) {
            return E_BAD_HANDLE;
        }

        posix_file
            .poll_set(&registration, token, interests)
            .map_or_else(|err| err, |()| E_OK)
    }

    /// Retire a source: after this the registry reports nothing under its
    /// token, which is what mio's users take a deregistration to mean.
    ///
    /// A registration this call finds live is deregistered, full stop: the
    /// source-side removal is identity-checked cleanup, and losing it to
    /// the delivery pass -- which garbage-collects a registration it sees
    /// retired -- is not a failure. A registration something else already
    /// retired is different: the caller closed the descriptor without
    /// deregistering, and when a duplicate keeps the source alive to say
    /// so, the source's error stands -- the deregister-after-close
    /// contract `run_self_stdio_close_child` pins.
    pub fn del(&self, source_fd: RtFd) -> ErrorCode {
        let _ops = self.ops.lock();
        let Some(registration) = self.pollees.lock().remove(&source_fd) else {
            return E_BAD_HANDLE;
        };

        let retired_here = registration.retire();
        let Some(posix_file) = registration.source.upgrade() else {
            return E_OK;
        };
        let result = posix_file.poll_del(&registration);
        if retired_here {
            E_OK
        } else {
            result.map_or_else(|err| err, |()| E_OK)
        }
    }

    fn remove_pollee_if(&self, source_fd: RtFd, registration: &Arc<Registration>) {
        let mut pollees = self.pollees.lock();
        if pollees
            .get(&source_fd)
            .is_some_and(|current| Arc::ptr_eq(current, registration))
        {
            pollees.remove(&source_fd);
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

    /// Drain one ready registration at a time without holding the queue lock
    /// while taking its state lock. Producers use the inverse-safe protocol:
    /// state first, then queue.
    fn collect_events(&self, events_buf: &mut [Event]) -> usize {
        let mut idx = 0;
        while idx < events_buf.len() {
            let Some(registration) = self.ready.lock().pop_front() else {
                break;
            };
            let mut state = registration.state.lock();
            state.pending = false;
            if state.lifecycle != RegLifecycle::Active || state.queued == 0 {
                continue;
            }
            events_buf[idx] = Event {
                token: state.token,
                events: core::mem::take(&mut state.queued),
            };
            idx += 1;
        }
        idx
    }
}
