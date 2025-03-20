// Userspace process.

use super::sys_ray_dbg::DebugSession;
use super::sysobject::SysObject;
use crate::arch::current_cpu;
use crate::arch::syscall::ThreadControlBlock;
use crate::arch::syscall::TOCR_KILLED_OTHER;
use crate::arch::syscall::TOCR_KILLED_SF;
use crate::arch::time::Instant;
use crate::config::uCpus;
use crate::mm;
use crate::mm::user::UserAddressSpace;
use crate::util::LockGuard;
use crate::util::SpinLock;
use crate::xray::stats::KProcessStats;
use alloc::borrow::ToOwned;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::assert_matches::assert_matches;
use core::sync::atomic::*;
use moto_sys::ErrorCode;
use moto_sys::SysHandle;
use moto_sys::UserThreadControlBlock;

// Process ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProcessId(u64);

pub const KERNEL_PID: ProcessId = ProcessId(moto_sys::stats::PID_KERNEL);
pub const SYS_IO_PID: ProcessId = ProcessId(moto_sys::stats::PID_SYS_IO);

pub enum UserError {
    InvalidSyscallReturnPointer,
    ShutdownRequested,
}

impl ProcessId {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(KERNEL_PID.as_u64() + 1);
        ProcessId(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    pub const fn from_u64(pid: u64) -> Self {
        Self(pid)
    }
}

// Globally unique Thread ID. Used in SysObject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ThreadId(u64);

impl ThreadId {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1); // Start with one, as zero is reserved for kernel.
        ThreadId(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub const fn from_u64(tid: u64) -> Self {
        Self(tid)
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum ProcessStatus {
    Created,
    Running,

    // When a process is a PausedDebuggee, its threads are resumed only
    // via explicit debugger commands. But when a Running process becomes
    // PausedDebuggee, its running threads may continue running until
    // they hit an edge (e.g. preemption) that make them PausedDebuggee
    // as well. So after a sched tick or two all live threads of a
    // PausedDebuggee process become PausedDebuggee threads.
    PausedDebuggee,

    Exiting(u64),
    Exited(u64),
    Error(ErrorCode),
    Killed,
}

#[derive(Clone)]
pub struct WaitObject {
    pub sys_object: Arc<SysObject>,
    pub wake_count: u64,
}

impl WaitObject {
    pub fn new(sys_object: Arc<SysObject>) -> Self {
        let wake_count = sys_object.wake_count();
        Self {
            sys_object,
            wake_count,
        }
    }
}

// Note: Process is never moved, but we don't use Pin<> because
//       we use Arc and Weak, and Pin interaction with Arc and Weak
//       is underdeveloped: see e.g. PinWeak.
pub struct Process {
    this: Weak<Self>,
    main_thread: Option<Arc<Thread>>,
    self_object: Option<Arc<SysObject>>, // Points at self.
    entry_point: u64,

    address_space: Arc<UserAddressSpace>,
    capabilities: AtomicU64,

    status: SpinLock<ProcessStatus>,

    // Protected by the status mutex.
    threads: BTreeMap<ThreadId, Arc<Thread>>,

    // The index in the vector is SysHandle minus CUSTOM_HANDLE_OFFSET.
    // These are the objects that this process has opened handles to.
    wait_objects: SpinLock<BTreeMap<SysHandle, WaitObject>>,
    next_wait_object_id: AtomicU64,

    stats: Arc<KProcessStats>,

    // If this is a debuggEE, debug_session below will contain the session
    // object.
    pub(super) debug_session: SpinLock<Option<Arc<DebugSession>>>,

    // Set to true when self.status == PausedDebuggee. This duplicates
    // the state, but helps with:
    // (a) performance: no need to lock Process::status to check this flag, and
    // (b) avoids potential deadlocks: the value of the flag is often used
    //     when Thread::status is locked; locking Process::status when
    //     Thread::status is locked is dangerous, as the normal pattern
    //     is to order the two locks from the larger (process) to the smaller (thread).
    paused_debuggee: AtomicBool,
}

unsafe impl Send for Process {}
unsafe impl Sync for Process {}

impl Drop for Process {
    fn drop(&mut self) {
        self.stats.process_dropped();
    }
}

impl Process {
    /*
     * There are built-in handles such as SysHandle::KERNEL. Custom handles
     * that are not available to every process and are quieried by url, all
     * have per-process numbers.
     */
    const MIN_WAIT_OBJECT_ID: u64 = 65536;

    pub fn new(
        parent: Arc<KProcessStats>,
        address_space: Arc<UserAddressSpace>,
        entry_point: u64,
        capabilities: u64,
        debug_name: String,
    ) -> Result<Arc<Self>, ErrorCode> {
        if !crate::mm::virt::is_user(entry_point) {
            return Err(moto_rt::E_NOT_ALLOWED);
        }

        if debug_name.trim().is_empty() {
            log::error!("Process:new(): empty debug_name.");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let user_stack = address_space.alloc_user_stack(Thread::DEFAULT_USER_STACK_SIZE_PAGES)?;

        let user_mem_stats = address_space.user_mem_stats().clone();
        let kernel_mem_stats = address_space.kernel_mem_stats().clone();

        let self_ = Arc::new_cyclic(|me| Process {
            address_space,
            entry_point,
            capabilities: AtomicU64::new(capabilities),
            status: SpinLock::new(ProcessStatus::Created),
            this: me.clone(),
            main_thread: None,
            threads: BTreeMap::default(),
            wait_objects: SpinLock::new(BTreeMap::new()),
            next_wait_object_id: AtomicU64::new(Self::MIN_WAIT_OBJECT_ID),
            self_object: None,
            stats: KProcessStats::new(
                parent,
                ProcessId::new(),
                debug_name,
                user_mem_stats,
                kernel_mem_stats,
                me.clone(),
            ),
            debug_session: SpinLock::new(None),
            paused_debuggee: AtomicBool::new(false),
        });

        // Safe because this is the "constructor" and no other references exit.
        // We cannot use Arc::get_mut() because of the weak self-reference in self.this.
        // And we don't want to use nightly Arc::get_mut_unchecked, as we try to
        // stick to stable API.
        let self_mut = unsafe {
            let ptr = Arc::as_ptr(&self_) as usize as *mut Process;
            ptr.as_mut().unwrap()
        };

        let process_page = self_mut.address_space.process_static_page_mut();
        process_page.pid = self_mut.pid().as_u64();
        process_page.capabilities = capabilities;

        self_mut.main_thread = Some(Thread::new(self_.clone(), user_stack, self_mut.entry_point));

        let thread = self_mut.main_thread.as_ref().unwrap();
        self_mut.threads.insert(thread.tid, thread.clone());

        self_mut.self_object = Some(SysObject::new_owned(
            Arc::new(alloc::format!("process:{}", self_mut.stats.pid().as_u64())),
            self_.clone(),
            Arc::downgrade(&self_),
        ));

        Ok(self_)
    }

    pub fn from_pid(pid: u64) -> Option<Arc<Self>> {
        crate::xray::stats::stats_from_pid(pid).and_then(|stats| stats.owner.upgrade())
    }

    pub fn new_child(
        parent_thread: &Thread,
        address_space_handle: SysHandle,
        url_part: &str,
    ) -> Result<Arc<Process>, ErrorCode> {
        let args: alloc::vec::Vec<&str> = url_part.split(';').collect();
        let entry_point: Option<u64> = crate::util::decode_arg::<u64>(&args, "entry_point");
        let capabilities: u64 = crate::util::decode_arg::<u64>(&args, "capabilities").unwrap_or(0);

        if entry_point.is_none() {
            log::debug!("missing entry_point");
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let parent = parent_thread.owner();
        let parent_caps = parent.capabilities();
        if parent_caps & moto_sys::caps::CAP_SYS == 0 {
            if capabilities & (moto_sys::caps::CAP_IO_MANAGER | moto_sys::caps::CAP_SYS) != 0 {
                return Err(moto_rt::E_NOT_ALLOWED);
            }

            if (capabilities & !parent_caps) != 0 {
                // Non-system processes cannot grant themseves caps they don't have.
                return Err(moto_rt::E_NOT_ALLOWED);
            }
        }

        let (address_space, url) = match parent.get_object(&address_space_handle) {
            None => {
                log::debug!("bad handle");
                return Err(moto_rt::E_INVALID_ARGUMENT);
            }
            Some(a) => {
                if let Ok(c) = Arc::downcast::<UserAddressSpace>(a.sys_object.owner().clone()) {
                    (c, a.sys_object.url().to_owned())
                } else {
                    log::debug!("bad handle");
                    return Err(moto_rt::E_INVALID_ARGUMENT);
                }
            }
        };

        let process = Self::new(
            parent.stats.clone(),
            address_space,
            entry_point.unwrap(),
            capabilities,
            url,
        )
        .map_err(|_| moto_rt::E_INTERNAL_ERROR)?;

        Ok(process)
    }

    pub fn pid(&self) -> ProcessId {
        self.stats.pid()
    }

    pub fn capabilities(&self) -> u64 {
        self.capabilities.load(Ordering::Relaxed)
    }

    pub(super) fn add_object(&self, object: Arc<SysObject>) -> SysHandle {
        let wait_object = WaitObject::new(object);
        let object_id = self
            .next_wait_object_id
            .fetch_add(1, Ordering::Relaxed)
            .into();
        let mut objects = self.wait_objects.lock(line!());
        objects.insert(object_id, wait_object);
        object_id
    }

    pub(super) fn get_object(&self, handle: &SysHandle) -> Option<WaitObject> {
        let objects = self.wait_objects.lock(line!());
        objects.get(handle).cloned()
    }

    // TODO: put_object should not remove live threads, as they can self-ref.
    pub(super) fn put_object(&self, handle: &SysHandle) -> Result<(), ()> {
        if let Some(obj) = {
            let mut objects = self.wait_objects.lock(line!());
            objects.remove(handle)
        } {
            drop(obj);
            Ok(())
        } else {
            Err(())
        }
    }

    // Note: we only mark the process as PausedDebuggee and don't
    // actively pause running threads, because this is potentially
    // a long running operation (imagine thousands of threads that
    // have to be looped over a couple of times to ensure that all
    // of them have paused), and we want our syscalls to be short.
    pub(super) fn dbg_pause(&self) -> Result<(), ErrorCode> {
        let mut status_lock = self.status.lock(line!());
        match *status_lock {
            ProcessStatus::Running => {
                *status_lock = ProcessStatus::PausedDebuggee;
                assert!(!self.paused_debuggee.swap(true, Ordering::SeqCst));
                Ok(())
            }
            ProcessStatus::PausedDebuggee => Err(moto_rt::E_ALREADY_IN_USE),
            ProcessStatus::Exiting(_)
            | ProcessStatus::Exited(_)
            | ProcessStatus::Error(_)
            | ProcessStatus::Created
            | ProcessStatus::Killed => Err(moto_rt::E_NOT_READY),
        }
    }

    // Note: we only mark the process as Created/Running and don't
    // actively resume paused threads, because this is potentially
    // a long running operation (imagine thousands of threads that
    // have to be looped over), and we want our syscalls to be short.
    pub(super) fn dbg_resume(&self) -> Result<(), ErrorCode> {
        let mut status_lock = self.status.lock(line!());
        match *status_lock {
            ProcessStatus::PausedDebuggee => {
                assert!(self.paused_debuggee.swap(false, Ordering::SeqCst));
                *status_lock = ProcessStatus::Running;
                Ok(())
            }
            _ => Err(moto_rt::E_NOT_READY),
        }
    }

    pub(super) fn dbg_resume_thread(&self, tid: ThreadId) -> Result<(), ErrorCode> {
        let thread = {
            let status = self.status.lock(line!());
            if *status != ProcessStatus::Running {
                return Err(moto_rt::E_NOT_READY);
            }
            if let Some(t) = self.threads.get(&tid) {
                t.clone()
            } else {
                return Err(moto_rt::E_NOT_FOUND);
            }
        };

        thread.resume_debuggee()
    }

    fn process_wake(&self, handle: &SysHandle) {
        let mut objects = self.wait_objects.lock(line!());
        if let Some(obj) = objects.get_mut(handle) {
            obj.wake_count = obj.sys_object.wake_count();
        }
    }

    pub fn debug_name(&self) -> &str {
        self.stats.debug_name()
    }

    pub(super) fn list_tids(&self, start_tid: &ThreadId, buf: &mut [u64]) -> usize {
        let _ = self.status.lock(line!());
        let tids = self.threads.range(start_tid..);
        let mut idx = 0;
        for (tid, _) in tids {
            buf[idx] = tid.as_u64();
            idx += 1;
            if idx >= buf.len() {
                break;
            }
        }

        idx
    }
    pub(super) fn get_thread_data(&self, tid: u64) -> Option<moto_sys::stats::ThreadDataV1> {
        let thread: Arc<Thread> = {
            let _ = self.status.lock(line!());
            self.threads.get(&ThreadId::from_u64(tid))?.clone()
        };

        Some(thread.get_thread_data())
    }

    pub(super) fn self_object(&self) -> Option<Arc<SysObject>> {
        self.status.lock(line!()); // Must lock status because self.self_object is mutated on exit.
        compiler_fence(Ordering::AcqRel);
        core::sync::atomic::fence(Ordering::AcqRel);
        self.self_object.as_ref().map(|o| o.clone())
    }

    pub(super) fn self_pinned(&self) -> Option<Arc<Process>> {
        self.status.lock(line!()); // Must lock status because self.self_object is mutated on exit.
        compiler_fence(Ordering::AcqRel);
        core::sync::atomic::fence(Ordering::AcqRel);
        self.self_object
            .as_ref()
            .and_then(super::sysobject::object_from_sysobject::<Process>)
    }

    pub fn status(&self) -> ProcessStatus {
        *self.status.lock(line!())
    }
    pub fn address_space(&self) -> &Arc<UserAddressSpace> {
        &self.address_space
    }
    pub fn main_thread(&self) -> &Option<Arc<Thread>> {
        &self.main_thread
    }

    pub fn start(&self) {
        self.main_thread.as_ref().unwrap().post_start(0);
    }

    pub fn spawn_thread(
        &self,
        stack_size: u64,
        thread_entry_point: u64,
        thread_arg: u64,
    ) -> Result<SysHandle, ErrorCode> {
        let stack_size = mm::align_up(stack_size, mm::PAGE_SIZE_SMALL);
        let num_pages = stack_size >> crate::mm::PAGE_SIZE_SMALL_LOG2;
        let stack = self.address_space.alloc_user_stack(num_pages)?;

        let thread = Thread::new(
            self.this.clone().upgrade().unwrap(),
            stack,
            thread_entry_point,
        );
        let mut error = None;
        'proc_lock: {
            let (self_mut, process_status) = unsafe { self.get_mut() };
            if *process_status != ProcessStatus::Running {
                error = Some(moto_rt::E_INTERNAL_ERROR);
                log::debug!("bad process status: {:?}", *process_status);
                break 'proc_lock;
            }

            self_mut.threads.insert(thread.tid, thread.clone());
        }

        if let Some(err) = error {
            return Err(err);
        }

        let thread_handle = thread.join_handle;
        log::debug!(
            "thread {:?} - {:x} created",
            thread.debug_name(),
            thread_handle.as_u64()
        );
        thread.post_start(thread_arg);
        Ok(thread_handle)
    }

    pub(super) fn kill(&self, target: SysHandle) -> Result<(), ErrorCode> {
        let target_obj = if let Some(obj) = self.get_object(&target) {
            obj
        } else {
            return Err(moto_rt::E_NOT_FOUND);
        };
        let target = if let Some(process) =
            super::sysobject::object_from_sysobject::<Process>(&target_obj.sys_object)
        {
            process
        } else {
            log::info!("victim 0x{:x} not process", target.as_u64());
            return Err(moto_rt::E_NOT_FOUND);
        };

        log::debug!("killing {}", target.debug_name());

        {
            let (target_mut, mut status_lock) = unsafe { target.get_mut() };
            let do_kill = match *status_lock {
                ProcessStatus::Created | ProcessStatus::Running => true,
                ProcessStatus::PausedDebuggee => todo!(),
                ProcessStatus::Exiting(_)
                | ProcessStatus::Exited(_)
                | ProcessStatus::Error(_)
                | ProcessStatus::Killed => false,
            };

            if do_kill {
                *status_lock = ProcessStatus::Exiting(u64::MAX);
                for thread in target_mut.threads.values() {
                    thread.post_kill(ThreadKilledReason::ProcessKilled);
                }
            }
        }

        Ok(())
    }

    pub(super) fn die(&self) {
        let (target_mut, mut status_lock) = unsafe { self.get_mut() };
        let do_kill = match *status_lock {
            ProcessStatus::Created | ProcessStatus::Running | ProcessStatus::PausedDebuggee => true,
            ProcessStatus::Exiting(_)
            | ProcessStatus::Exited(_)
            | ProcessStatus::Error(_)
            | ProcessStatus::Killed => false,
        };

        if do_kill {
            *status_lock = ProcessStatus::Exiting(u64::MAX);
            for thread in target_mut.threads.values() {
                thread.post_kill(ThreadKilledReason::ProcessKilled);
            }
        }
    }

    unsafe fn get_mut(&self) -> (&mut Self, LockGuard<ProcessStatus>) {
        let lock = self.status.lock(line!());
        ((self as *const Self as *mut Self).as_mut().unwrap(), lock)
    }

    fn on_thread_starting(&self, _thread: &Thread) -> bool {
        let mut status = self.status.lock(line!());
        match *status {
            ProcessStatus::Created => {
                log::debug!(
                    "started process {}: '{}'",
                    self.pid().as_u64(),
                    self.debug_name()
                );
                *status = ProcessStatus::Running;
                true
            }
            ProcessStatus::Exiting(_) => false,
            ProcessStatus::Running => true,
            _ => panic!("unexpected process status: {:?}", *status),
        }
    }

    fn on_thread_exited(&self, tid: ThreadId, thread_status: ThreadStatus) {
        self.stats.on_thread_exited();
        self.address_space
            .process_static_page_mut()
            .active_threads
            .fetch_add(1, Ordering::Relaxed);

        #[cfg(debug_assertions)]
        log::debug!(
            "on_thread_exited: pid: {} tid: {}",
            self.pid().as_u64(),
            tid.as_u64()
        );
        let mut exited = false;
        {
            let (self_mut, mut status_lock) = unsafe { self.get_mut() };
            #[cfg(debug_assertions)]
            match *status_lock {
                ProcessStatus::Running => {}
                ProcessStatus::Exiting(_) => {}
                _ => {
                    panic!("Unexpected process status {:?}.", *status_lock);
                }
            }

            {
                let thread = self_mut.threads.remove(&tid).unwrap();
                thread.cleanup();
            }

            if self_mut.threads.is_empty() {
                #[cfg(debug_assertions)]
                log::debug!(
                    "process {} '{}' exiting: no threads left.",
                    self.pid().as_u64(),
                    self.debug_name()
                );
                // Although it would have been nice to set the process status
                // to exited now, we need to first get the exit status value
                // from the main thread, and we would rather not have nested locks.
                exited = true;
            } else if self.main_thread.as_ref().unwrap().tid == tid {
                if !matches!(*status_lock, ProcessStatus::Exiting(_)) {
                    *status_lock = match thread_status {
                        ThreadStatus::Finished => ProcessStatus::Exiting(0),
                        ThreadStatus::Exited(val) => ProcessStatus::Exiting(val),
                        ThreadStatus::Killed(_) | ThreadStatus::Error(_) => {
                            ProcessStatus::Exiting(u64::MAX)
                        }
                        // _ => ProcessStatus::Exiting(u64::MAX),
                        _ => panic!("Unexpected thread status {:?}.", thread_status),
                    };
                }
                #[cfg(debug_assertions)]
                log::debug!(
                    "process {} '{}' exiting: main thread exited.",
                    self.pid().as_u64(),
                    self.debug_name()
                );
                for thread in self_mut.threads.values() {
                    thread.post_kill(ThreadKilledReason::MainThreadExited);
                }
            } else {
                match thread_status {
                    ThreadStatus::Finished => {}
                    ThreadStatus::Exited(val) => {
                        // std::process::exit(val) was called: kill the process.
                        if !matches!(*status_lock, ProcessStatus::Exiting(_)) {
                            *status_lock = ProcessStatus::Exiting(val);
                        }
                        #[cfg(debug_assertions)]
                        log::debug!(
                            "process {} '{}' killed: thread {} exited with status {}.",
                            self.pid().as_u64(),
                            self.debug_name(),
                            tid.as_u64(),
                            val
                        );
                        for thread in self_mut.threads.values() {
                            thread.post_kill(ThreadKilledReason::ProcessKilled);
                        }
                    }
                    ThreadStatus::Killed(_) | ThreadStatus::Error(_) => {
                        if !matches!(*status_lock, ProcessStatus::Exiting(_)) {
                            *status_lock = ProcessStatus::Exiting(u64::MAX);
                        }
                        #[cfg(debug_assertions)]
                        log::debug!(
                            "process {} '{}' killed: thread {} killed.",
                            self.pid().as_u64(),
                            self.debug_name(),
                            tid.as_u64()
                        );
                        for thread in self_mut.threads.values() {
                            thread.post_kill(ThreadKilledReason::ProcessKilled);
                        }
                    }
                    _ => panic!("Unexpected thread exit status {:?}", thread_status),
                }
            }
        }

        if exited {
            let self_obj = {
                let (self_mut, mut status_lock) = unsafe { self.get_mut() };
                match *status_lock {
                    ProcessStatus::Running => {
                        let main_thread_status = self.main_thread.as_ref().unwrap().status();
                        *status_lock = match main_thread_status {
                            ThreadStatus::Finished => ProcessStatus::Exited(0),
                            ThreadStatus::Exited(val) => ProcessStatus::Exited(val),
                            ThreadStatus::Killed(_) => ProcessStatus::Killed,
                            _ => panic!("Unexpected main thread status {:?}", main_thread_status),
                        };
                    }
                    ProcessStatus::Exiting(val) => {
                        *status_lock = ProcessStatus::Exited(val);
                    }
                    ProcessStatus::Error(_) => {}
                    _ => {
                        panic!("Unexpected process status {:?}.", *status_lock);
                    }
                }

                #[cfg(debug_assertions)]
                log::debug!(
                    "Process {}: '{}' exited with status {:?}.",
                    self.pid().as_u64(),
                    self.debug_name(),
                    *status_lock
                );

                self_mut.main_thread = None;
                self_mut.self_object.take().unwrap()
            };
            self_obj.mark_done();
            SysObject::wake(&self_obj, false);

            self.wait_objects.lock(line!()).clear();

            if self.pid().as_u64() == moto_sys::stats::PID_SYS_IO {
                crate::init::init_exited(self);
            }
        }
    }

    fn job_fn_kill_by_pid(_: Weak<Thread>, pid: u64) {
        crate::xray::tracing::trace("job_fn_kill_by_pid", pid, 0, 0);
        if let Some(target_stats) = crate::xray::stats::stats_from_pid(pid) {
            if let Some(target) = target_stats.owner.upgrade() {
                if target.capabilities() & moto_sys::caps::CAP_SYS == 0 {
                    target.die();
                }
            }
        }
    }
}

// Allowed live thread status transitions:
//
// Running -> Preempted
// Running -> Syscall
//
// Preempted -> Running (will be resume in the userspace)
//
// Syscall -> Running
// Syscall -> InWait
// Syscall -> Runnable
//
// InWait -> Runnable
//
// Runnable -> Running
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum LiveThreadStatus {
    Running, // Running in userspace.
    Preempted,

    // Numbers in statuses below represent the current syscall number/operation.
    Runnable(u8, u8), // Waiting to be scheduled by the kernel.
    Syscall(u8, u8),  // Running in the kenrel.
    InWait(u8, u8),   // Paused.
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum ThreadStatus {
    Created,
    Live(LiveThreadStatus),
    PausedDebuggee(LiveThreadStatus),
    Finished,    // Finished "normally", via SysCtl::OP_PUT(SELF).
    Exited(u64), // SysCpu::OP_EXIT.
    Error(ErrorCode),
    Killed(ThreadKilledReason),
}

// The reason a thread got off a CPU.
#[derive(Debug, Eq, PartialEq)]
pub enum ThreadOffCpuReason {
    Paused,
    Preempted,
    Exited,
    KilledSf,
    KilledGpf,
    KilledPf(u64),
    KilledOther,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum ThreadKilledReason {
    GPF,
    PageFault,
    SegFault,
    MainThreadExited,
    ProcessKilled,
    InternalError,
}

// Note: Thread is never moved, but we don't use Pin<> because
//       we use Arc and Weak, and Pin interaction with Arc and Weak
//       is underdeveloped: see e.g. PinWeak.
pub struct Thread {
    // Read-only fields:
    tid: ThreadId, // Used in SysObject (waiting threads). Must be globally unique.
    owner: Weak<Process>,
    this: Weak<Self>,
    thread_entry_point: u64,
    user_stack: crate::mm::user::UserStack,

    // Self object, points at self. Can be used to wake this thread either locally
    // or remotely.
    self_object: Option<Arc<SysObject>>,
    self_handle: SysHandle, // The handle for self_object. Used in UserThreadControlBlock.

    // Join object, used by other threads in the same process to "join" this thread.
    join_object: Option<Arc<SysObject>>,
    join_handle: SysHandle, // The handle for join_object.

    wakes_queued: AtomicU64, // Counts wakes for self wakes.
    wakes_taken: AtomicU64,

    kernel_stack_segment: Option<mm::MemorySegment>,

    // Fields that change over the thread runtime.
    status: SpinLock<ThreadStatus>,
    tcb: ThreadControlBlock,
    user_tcb_user_addr: u64, // *mut UserThreadControlBlock in the user address space.
    user_tcb_kernel_addr: u64, // *mut UserThreadControlBlock in the kernel address space.

    capabilities: AtomicU64,

    timer_id: AtomicU64,
    timer_cpu: AtomicU32,

    // The list of objects this thread is currently in sys_wait() for.
    sys_wait_objects: SpinLock<Vec<WaitObject>>,

    timed_out: AtomicBool,
    wakers: SpinLock<Vec<SysHandle>>,

    last_cpu: AtomicU32,
    affined_to: AtomicU32,

    pub process_stats: Arc<KProcessStats>,
}

unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}

#[cfg(debug_assertions)]
impl Drop for Thread {
    fn drop(&mut self) {
        // Note: at this point the thread's process may be gone,
        // so we can't do much here. Use Thread::cleanup().
        self.trace("Thread::drop", 0, 0);
        log::debug!("thread {} dropped.", self.tid.as_u64());
    }
}

impl Thread {
    const DEFAULT_USER_STACK_SIZE_PAGES: u64 = 254; // +2 are added as guards.
    #[cfg(debug_assertions)]
    const DEFAULT_KERNEL_STACK_SIZE_PAGES: u64 = 8; // +2 are added as guards.
    #[cfg(not(debug_assertions))]
    const DEFAULT_KERNEL_STACK_SIZE_PAGES: u64 = 4; // +2 are added as guards.

    const USER_TCB_GUARD: u64 = 0xdead_f00b_a4ba_22cd; // Whatever.

    fn new(
        owner: Arc<Process>,
        user_stack: crate::mm::user::UserStack,
        thread_entry_point: u64,
    ) -> Arc<Self> {
        let self_ = Arc::new(Self {
            tid: ThreadId::new(),
            tcb: ThreadControlBlock::new(),
            user_tcb_user_addr: 0,
            user_tcb_kernel_addr: 0,
            this: Weak::default(),
            self_object: None,
            self_handle: SysHandle::NONE,
            join_object: None,
            join_handle: SysHandle::NONE,
            wakes_queued: AtomicU64::new(0),
            wakes_taken: AtomicU64::new(0),
            owner: Arc::downgrade(&owner),
            thread_entry_point,
            user_stack,
            capabilities: AtomicU64::new(0),
            kernel_stack_segment: None,
            status: SpinLock::new(ThreadStatus::Created),
            timer_id: AtomicU64::new(0),
            timer_cpu: AtomicU32::new(u32::MAX),
            sys_wait_objects: SpinLock::new(Vec::new()),
            timed_out: AtomicBool::new(false),
            wakers: SpinLock::new(alloc::vec![]),
            last_cpu: AtomicU32::new(u32::MAX),
            affined_to: AtomicU32::new(uCpus::MAX as u32),
            process_stats: owner.stats.clone(),
        });

        unsafe {
            let (self_mut, _lock) = self_.get_mut();
            self_mut.this = Arc::downgrade(&self_);
            let self_object = SysObject::new_owned(
                Arc::new(alloc::format!(
                    "thread:{}:{}",
                    owner.pid().as_u64(),
                    self_mut.tid.as_u64()
                )),
                self_.clone(),
                Arc::downgrade(&owner),
            );

            self_mut.self_object = Some(self_object.clone());
            self_mut.self_handle = owner.add_object(self_object);

            let join_object = SysObject::new_owned(
                Arc::new(alloc::format!(
                    "thread_joiner:{}:{}",
                    owner.pid().as_u64(),
                    self_mut.tid.as_u64()
                )),
                self_.clone(),
                Arc::downgrade(&owner),
            );

            self_mut.join_object = Some(join_object.clone());
            self_mut.join_handle = owner.add_object(join_object);
        }

        owner
            .address_space
            .process_static_page_mut()
            .active_threads
            .fetch_add(1, Ordering::Relaxed);

        owner.stats.on_thread_added();
        self_
    }

    pub fn get(&self) -> Arc<Self> {
        self.this.upgrade().unwrap()
    }

    pub fn user_tcb_user_addr(&self) -> u64 {
        debug_assert_ne!(0, self.user_tcb_user_addr);
        self.user_tcb_user_addr
    }

    /// # Safety
    ///
    /// Assumes that self is not running in the userspace.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn user_tcb_mut(&self) -> &mut UserThreadControlBlock {
        debug_assert_ne!(0, self.user_tcb_kernel_addr);
        (self.user_tcb_kernel_addr as usize as *mut UserThreadControlBlock)
            .as_mut()
            .unwrap_unchecked()
    }

    fn check_user_tcb_guard(&self) -> Result<(), ()> {
        debug_assert_ne!(0, self.user_tcb_kernel_addr);
        let utcb = unsafe {
            (self.user_tcb_kernel_addr as usize as *const UserThreadControlBlock)
                .as_ref()
                .unwrap_unchecked()
        };

        if utcb.guard == Self::USER_TCB_GUARD {
            Ok(())
        } else {
            log::info!(
                "UTCB guard check failed: {}:{}",
                self.owner().pid().as_u64(),
                self.tid.as_u64()
            );
            Err(())
        }
    }

    pub fn get_weak(&self) -> Weak<Self> {
        self.this.clone()
    }

    pub(super) fn self_object(&self) -> Option<Arc<SysObject>> {
        self.status.lock(line!()); // Must lock status because self.self_object is mutated on exit.
        compiler_fence(Ordering::AcqRel);
        core::sync::atomic::fence(Ordering::AcqRel);
        self.self_object.as_ref().cloned()
    }

    pub fn cancel_timeout(&self) {
        let timer_id = self.timer_id.swap(0, Ordering::Relaxed);
        if timer_id != 0 {
            crate::sched::cancel_timer(timer_id, self.timer_cpu.load(Ordering::Relaxed) as uCpus);
        }
    }

    // Called when THIS thread is running and is calling wait(timeout).
    pub fn new_timeout(&self, when: Instant) {
        if when.is_nan() {
            self.post_wake(false);
        } else {
            // Note: timers are always created for the current CPU to avoid wait/wake races.
            let cpu = current_cpu();
            let timer = crate::sched::Timer::new(Self::job_fn_wake_by_timeout, self, when, cpu);
            let prev_id = self.timer_id.swap(timer.id(), Ordering::Relaxed);
            assert_eq!(0, prev_id);
            self.timer_cpu.store(cpu as u32, Ordering::Relaxed);
            crate::sched::post_timer(timer);
        }
    }

    pub(super) fn add_wait_objects(&self, objects: Vec<WaitObject>) {
        let mut list = self.sys_wait_objects.lock(line!());
        assert!(list.is_empty());
        *list = objects;
    }

    pub(super) fn add_waker(&self, waker: SysHandle) {
        if waker != SysHandle::NONE {
            self.wakers.lock(line!()).push(waker);
        }
    }

    unsafe fn get_mut(&self) -> (&mut Self, LockGuard<ThreadStatus>) {
        let lock = self.status.lock(line!());
        ((self as *const Self as *mut Self).as_mut().unwrap(), lock)
    }

    pub fn debug_name(&self) -> String {
        let parent = self.owner.upgrade().unwrap();
        alloc::format!(
            "{} {}:{} - '{}'",
            parent.debug_name(),
            parent.pid().as_u64(),
            self.tid.as_u64(),
            self.get_thread_data().thread_name()
        )
    }

    pub fn capabilities(&self) -> u64 {
        self.capabilities.load(Ordering::Relaxed)
    }

    pub fn owner(&self) -> Arc<Process> {
        self.owner.upgrade().unwrap()
    }

    pub fn last_cpu(&self) -> Option<uCpus> {
        let cpu = self.last_cpu.load(Ordering::Relaxed);
        if cpu == u32::MAX {
            None
        } else {
            Some(cpu as uCpus)
        }
    }

    pub fn trace(&self, event: &'static str, arg1: u64, arg2: u64) {
        crate::xray::tracing::trace(event, self.tid.as_u64(), arg1, arg2);
    }

    fn pause_debuggee_in_syscall(&self) {
        self.tcb.pause();
    }

    fn resume_debuggee(&self) -> Result<(), ErrorCode> {
        let mut status = self.status.lock(line!());
        match *status {
            ThreadStatus::Live(_) => Err(moto_rt::E_ALREADY_IN_USE),
            ThreadStatus::PausedDebuggee(live_thread_status) => match live_thread_status {
                LiveThreadStatus::Running => {
                    // Paused in on_syscall_exit().
                    *status = ThreadStatus::Live(LiveThreadStatus::Running);
                    self.post_wake_locked(false);
                    Ok(())
                }
                LiveThreadStatus::Preempted => {
                    // Paused in resume_in_userspace() or on_thread_preempted().
                    *status = ThreadStatus::Live(LiveThreadStatus::Preempted);
                    crate::sched::post(crate::sched::Job::new(
                        Self::job_fn_resume_in_userspace,
                        self,
                    ));
                    Ok(())
                }
                LiveThreadStatus::Syscall(_, _) => {
                    // Paused in on_syscall_enter().
                    *status = ThreadStatus::Live(live_thread_status);
                    self.post_wake_locked(false);
                    Ok(())
                }
                LiveThreadStatus::Runnable(_, _) => panic!("not possible"),
                LiveThreadStatus::InWait(_, _) => panic!("not possible"),
            },
            _ => Err(moto_rt::E_NOT_READY),
        }
    }

    // Called when the thread has entered the kernel via a syscall.
    pub fn on_syscall_enter(&self, syscall_nr: u8, operation: u8) {
        self.trace("on_syscall_enter", syscall_nr as u64, operation as u64);
        if self.check_user_tcb_guard().is_err() {
            self.die(ThreadKilledReason::SegFault); // Never returns.
        }
        let mut pause_debuggee = false;
        {
            let mut status = self.status.lock(line!());
            match *status {
                ThreadStatus::Live(LiveThreadStatus::Running) => {
                    if self.owner().paused_debuggee.load(Ordering::Relaxed) {
                        *status = ThreadStatus::PausedDebuggee(LiveThreadStatus::Syscall(
                            syscall_nr, operation,
                        ));
                        pause_debuggee = true;
                    } else {
                        *status =
                            ThreadStatus::Live(LiveThreadStatus::Syscall(syscall_nr, operation));
                    }
                }
                ThreadStatus::Killed(reason) => {
                    core::mem::drop(status); // Unlock.
                    self.die(reason); // Never returns.
                }
                _ => panic!("unexpected thread status {:?}", *status),
            }
        }
        if pause_debuggee {
            self.pause_debuggee_in_syscall();
        }
    }

    // Called when the thread is about to exit the syscall/kernel to userspace.
    pub fn on_syscall_exit(&self) {
        self.trace("on_sycall_exit", 0, 0);
        let mut pause_debuggee = false;
        {
            let mut status = self.status.lock(line!());
            match *status {
                ThreadStatus::Live(LiveThreadStatus::Syscall(_, _)) => {
                    if self.owner().paused_debuggee.load(Ordering::Relaxed) {
                        *status = ThreadStatus::PausedDebuggee(LiveThreadStatus::Running);
                        pause_debuggee = true;
                    } else {
                        *status = ThreadStatus::Live(LiveThreadStatus::Running);
                    }
                }
                ThreadStatus::Killed(reason) => {
                    core::mem::drop(status); // Unlock.
                    self.die(reason);
                }
                _ => panic!("unexpected thread status {:?}", *status),
            }
        }
        if pause_debuggee {
            self.pause_debuggee_in_syscall();
        }
    }

    pub fn tid(&self) -> ThreadId {
        self.tid
    }

    pub fn rip(&self) -> u64 {
        self.tcb.rip()
    }

    pub fn set_cpu_affinity(&self, cpu: Option<uCpus>) {
        match cpu {
            Some(cpu) => self.affined_to.store(cpu as u32, Ordering::Relaxed),
            None => self.affined_to.store(uCpus::MAX as u32, Ordering::Relaxed),
        }
    }

    pub fn get_cpu_affinity(&self) -> uCpus {
        self.affined_to.load(Ordering::Relaxed) as uCpus
    }

    fn init_user_tcb(&mut self) {
        self.user_tcb_user_addr = (self.user_stack.stack_top()
            - (core::mem::size_of::<UserThreadControlBlock>() as u64))
            & !15; // Align on 16 bytes.

        self.user_tcb_kernel_addr = self
            .owner()
            .address_space
            .virt_to_phys(self.user_tcb_user_addr)
            .unwrap()
            + crate::mm::PAGING_DIRECT_MAP_OFFSET;

        unsafe {
            let user_tcb = self.user_tcb_mut();
            user_tcb.guard = Self::USER_TCB_GUARD;
            user_tcb.kernel_version = 1;
            user_tcb.user_version = 0;
            user_tcb.self_handle = self.self_handle.as_u64();
            user_tcb.self_tid = self.tid.as_u64();
            user_tcb.stack_guard = Self::USER_TCB_GUARD;
            user_tcb.tls = 0;
            user_tcb.current_cpu.store(0, Ordering::Relaxed);
            user_tcb.reserved0 = [0; 3];
            user_tcb.name_len = 0;
            user_tcb.name_bytes = [0; 32];
        }
    }

    // Never returns.
    pub fn kill(&self, _error: UserError) -> ! {
        todo!()
    }

    fn post_kill(&self, reason: ThreadKilledReason) {
        // TODO: this post_exited thing is fragile and bad design.
        //        on_thread_exited() is called in too many places,
        //        so it could be called more than once or not at all.
        let mut post_exited = false;
        {
            let mut status = self.status.lock(line!());
            match *status {
                ThreadStatus::Created | ThreadStatus::PausedDebuggee(_) => {
                    *status = ThreadStatus::Killed(reason);
                }
                ThreadStatus::Live(live_status) => match live_status {
                    LiveThreadStatus::Running => {
                        *status = ThreadStatus::Killed(reason);
                        // log::warn!("TODO: preempt the running thread");
                    }
                    LiveThreadStatus::Runnable(_, _) | LiveThreadStatus::Syscall(_, _) => {
                        *status = ThreadStatus::Killed(reason);
                    }
                    LiveThreadStatus::InWait(_, _) => {
                        *status = ThreadStatus::Killed(reason);
                        self.post_wake_locked(false);
                    }
                    LiveThreadStatus::Preempted => {
                        *status = ThreadStatus::Killed(reason);
                        post_exited = true;
                    }
                },
                ThreadStatus::Killed(_)
                | ThreadStatus::Error(_)
                | ThreadStatus::Exited(_)
                | ThreadStatus::Finished => { /* Nothing to do here. */ }
            }
        };
        if post_exited {
            crate::sched::post(crate::sched::Job::new(Self::job_fn_on_thread_exited, self));
        }
    }

    fn post_start(&self, arg: u64) {
        self.wakes_taken
            .store(self.wakes_queued.load(Ordering::Relaxed), Ordering::Relaxed);

        let mut job = crate::sched::Job::new(Self::job_fn_start, self);
        job.arg = arg;
        crate::sched::post(job);
    }

    pub fn status(&self) -> ThreadStatus {
        *self.status.lock(line!())
    }

    // We use trampoline to start threads because Thread::start() is called
    // with the owner process locked, and we want to have it unlocked.
    //fn start_trampoline(thread: u64, arg: u64) {
    //    let self_ = thread as usize as *const Thread;
    fn do_start(&self, arg: u64) {
        let cpu_usage_scope = self.process_stats.cpu_usage_scope_kernel();

        self.trace("thread do_start", arg, 0);
        let entry_point = self.thread_entry_point;

        let process = self.owner.upgrade().unwrap();
        let start = 0; // process.as_ref().uspace_base;

        let mut error = None;
        let mut kernel_stack_segment: Option<mm::MemorySegment> = None;

        'proc_lock: {
            let (process_mut, mut process_status) = unsafe { process.get_mut() };
            match *process_status {
                ProcessStatus::Created => {}
                ProcessStatus::Running => {}
                _ => {
                    error = Some(moto_rt::E_INTERNAL_ERROR);
                    log::debug!("bad process status: {:?}", *process_status);
                    break 'proc_lock;
                }
            }

            match process_mut
                .address_space
                .alloc_kernel_stack(Self::DEFAULT_KERNEL_STACK_SIZE_PAGES)
            {
                Ok(k) => kernel_stack_segment = Some(k),
                Err(err) => {
                    log::error!(
                        "Process {}: '{}' OOMed when allocating kernel stack.",
                        process_mut.pid().as_u64(),
                        process_mut.debug_name()
                    );
                    *process_status = ProcessStatus::Error(err);
                    error = Some(err);
                    break 'proc_lock;
                }
            }
        }

        if let Some(err) = error {
            {
                *self.status.lock(line!()) = ThreadStatus::Error(err);
            }
            self.on_thread_exited();
            return;
        }

        {
            let tcb = {
                let (self_mut, mut thread_status_lock) = unsafe { self.get_mut() };
                if *thread_status_lock != ThreadStatus::Created {
                    assert_matches!(*thread_status_lock, ThreadStatus::Killed(_));
                    crate::sched::post(crate::sched::Job::new(Self::job_fn_on_thread_exited, self));
                    return;
                }
                let self_ptr = self_mut as *const Thread;

                let kernel_stack_start = kernel_stack_segment.unwrap().end() - mm::PAGE_SIZE_SMALL;

                self_mut.kernel_stack_segment = kernel_stack_segment;

                self_mut
                    .capabilities
                    .store(process.capabilities(), Ordering::Relaxed);

                let upt = process.address_space.user_page_table();

                self_mut.init_user_tcb();

                let tcb = &mut self_mut.tcb;
                tcb.init(
                    self_ptr as *const Thread,
                    start + entry_point,
                    // User stack starts after user_tcb.
                    // TODO: userspace with sse enabled uses movaps, which does #GPF(0)
                    //       if the argument is not aligned on 16 bytes. But for some reason
                    //       the rust compiler does "push %rbp" and then calls moveaps with
                    //       %rsp, so %rsp must be 8-byte aligned but not 16-byte aligned.
                    (self_mut.user_tcb_user_addr & !15) - 8, // Make sure user %rsp is 0x****8.
                    kernel_stack_start,
                    upt,
                );

                *thread_status_lock = ThreadStatus::Live(LiveThreadStatus::Running);
                tcb
            };

            if !process.on_thread_starting(self) {
                // The process is dying.
                {
                    *self.status.lock(line!()) =
                        ThreadStatus::Killed(ThreadKilledReason::ProcessKilled);
                }
                self.on_thread_exited();
                return;
            }
            core::mem::drop(cpu_usage_scope);
            self.trace("will spawn usermode", 0, 0);
            self.on_thread_descheduled(tcb.spawn_usermode_thread(arg));
            self.trace("back from spawn usermode", 0, 0);
        }
    }

    fn clear_wait_objects_on_wake(&self) {
        // Note: we consciously drop all wait objects on wakeup below and
        // require a full list of wait objects on each new wait. While it
        // may seem that requiring a full list of wait objects on each wait
        // is wasteful and does not scale, this is done consciously so that
        // we avoid synchronous designs (where many wait objects are needed).
        let wait_objects = core::mem::take(&mut *self.sys_wait_objects.lock(line!()));
        for obj in &wait_objects {
            obj.sys_object.remove_waiting_thread(self);
        }
        core::mem::drop(wait_objects); // Must drop before resuming the thread.
    }

    // Called for IO threads on non-blocking waits.
    pub fn take_wakers(&self) -> Vec<SysHandle> {
        self.clear_wait_objects_on_wake();

        self.wakes_taken
            .store(self.wakes_queued.load(Ordering::Relaxed), Ordering::Relaxed);
        self.timed_out.store(false, Ordering::Relaxed);
        let mut wakers = core::mem::take(&mut *self.wakers.lock(line!()));

        if wakers.len() > 1 {
            wakers.sort_unstable();
            wakers.dedup();
        }

        for waker in &wakers {
            self.owner().process_wake(waker);
        }

        wakers
    }

    // Returns true if the wait timed out, and/or a list of waker handles.
    pub fn wait(&self) -> (bool, Vec<SysHandle>) {
        let (timed_out, mut wakers) = {
            {
                self.trace("thread::wait", 0, 0);

                // tcb.pause() below will triger on_thread_paused() that will
                // change this thread's status to InWait. It will NOT return
                // until the thread wakes.
                self.tcb.pause();
                // tcb.pause() above is done, which means the thread is
                // no longer InWait.

                self.trace("thread::wait: woke", 0, 0);
                // The pause() above deschedules this thread from this CPU.
                // The thread will resume below via Self::resume().

                let mut status = self.status.lock(line!());
                let (nr, op) = match *status {
                    ThreadStatus::Live(LiveThreadStatus::Runnable(nr, op)) => (nr, op),
                    ThreadStatus::Killed(reason) => {
                        core::mem::drop(status); // Unlock.
                        self.die(reason); // Does not return.
                    }
                    x => panic!("bad status: {:?}", x),
                };
                *status = ThreadStatus::Live(LiveThreadStatus::Syscall(nr, op));
            }
            // else: have queued wakes.

            self.wakes_taken
                .store(self.wakes_queued.load(Ordering::Relaxed), Ordering::Relaxed);
            (
                self.timed_out.swap(false, Ordering::AcqRel),
                core::mem::take(&mut *self.wakers.lock(line!())),
            )
        };

        if wakers.len() > 1 {
            wakers.sort_unstable();
            wakers.dedup();
        }

        for waker in &wakers {
            self.owner().process_wake(waker);
        }

        (timed_out, wakers)
    }

    // This is called when a thread in a syscall calls self.tcb.pause(),
    // which happens either in sys_wait() or when the process is PausedDebuggee.
    fn on_thread_paused(&self) {
        self.trace("thread::on_thread_paused", 0, 0);
        self.tcb.validate_rsp();
        let mut call_on_exited = false;
        {
            let mut status = self.status.lock(line!());
            match *status {
                ThreadStatus::Live(LiveThreadStatus::Syscall(nr, op)) => {
                    if self.wakers.lock(line!()).is_empty()
                        && self.wakes_taken.load(Ordering::Relaxed)
                            == self.wakes_queued.load(Ordering::Relaxed)
                    {
                        *status = ThreadStatus::Live(LiveThreadStatus::InWait(nr, op))
                    } else {
                        *status = ThreadStatus::Live(LiveThreadStatus::Runnable(nr, op));
                        self.trace("thread::on_thread_paused: will resume", 0, 0);
                        self.post_wake_locked(false);
                    }
                }
                ThreadStatus::PausedDebuggee(_) => {}
                ThreadStatus::Killed(_) => {
                    call_on_exited = true;
                }
                _ => panic!(
                    "{}: unexpected thread status {:?}",
                    self.tid.as_u64(),
                    // self.debug_name(),
                    *status
                ),
            }
        }

        if call_on_exited {
            crate::sched::post(crate::sched::Job::new(Self::job_fn_on_thread_exited, self));
        }
    }

    // Resumes a thread sleeping in Thread::wait() or in Thread::pause_debuggee_in_syscall().
    fn resume_in_kernel(&self) {
        self.trace("thread::resume_in_kernel", 0, 0);
        self.tcb.validate_rsp();
        // @self is not currently running. So we don't check its status; it will
        // be checked when it is resumed in Self::wait().
        self.cancel_timeout();
        self.clear_wait_objects_on_wake();

        self.on_thread_descheduled(
            /*
             * Resumes the thread on this CPU:
             * jumps to the line marked 'resumes here' in Self::wait().
             */
            self.tcb.resume(),
        );
        self.trace("resume_in_kernel back", 0, 0);
    }

    fn resume_in_userspace(&self) {
        self.trace("thread::resume_in_userspace", 0, 0);
        let resume = {
            let mut status = self.status.lock(line!());
            match *status {
                ThreadStatus::Live(LiveThreadStatus::Preempted) => {
                    if self.owner().paused_debuggee.load(Ordering::Relaxed) {
                        *status = ThreadStatus::PausedDebuggee(LiveThreadStatus::Preempted);
                        false
                    } else {
                        *status = ThreadStatus::Live(LiveThreadStatus::Running);
                        true
                    }
                }
                ThreadStatus::Killed(_) => false,
                _ => panic!("Unexpected thread status {:?}.", *status),
            }
        };

        if resume {
            log::debug!("resume_in_userspace: {}", self.debug_name());
            self.on_thread_descheduled(self.tcb.resume_preempted_thread());
            self.trace("resume_in_userspace back", 0, 0);
        }
    }

    pub fn post_wake(&self, this_cpu: bool) {
        self.trace("thread::post_wake", 0, 0);
        log::debug!("{}: post wake", self.debug_name());
        self.wakes_queued.fetch_add(1, Ordering::Relaxed);
        let mut status = self.status.lock(line!());
        match *status {
            ThreadStatus::Live(LiveThreadStatus::InWait(nr, op)) => {
                *status = ThreadStatus::Live(LiveThreadStatus::Runnable(nr, op));
                self.post_wake_locked(this_cpu);
            }
            ThreadStatus::Created => {
                self.post_start(0);
            }
            _ => {
                log::debug!(
                    "{}: post_wake: not waking: {:?}",
                    self.debug_name(),
                    *status
                );
            }
        }
    }

    fn process_live_thread_status_locked(
        &self,
        live_status: LiveThreadStatus,
        thread_data: &mut moto_sys::stats::ThreadDataV1,
    ) {
        match live_status {
            LiveThreadStatus::Running => {
                thread_data.status = moto_sys::stats::ThreadStatus::LiveRunning
            }
            LiveThreadStatus::Preempted => {
                thread_data.status = moto_sys::stats::ThreadStatus::LivePreempted;
                thread_data.ip = self.tcb.rip();
                thread_data.rbp = self.tcb.rbp();
            }
            LiveThreadStatus::Runnable(s, o) => {
                thread_data.status = moto_sys::stats::ThreadStatus::LiveRunnable;
                thread_data.syscall_num = s;
                thread_data.syscall_op = o;
                thread_data.ip = self.tcb.rip();
                thread_data.rbp = self.tcb.rbp();
            }
            LiveThreadStatus::Syscall(s, o) => {
                thread_data.status = moto_sys::stats::ThreadStatus::LiveSyscall;
                thread_data.syscall_num = s;
                thread_data.syscall_op = o;
                thread_data.ip = self.tcb.rip();
                thread_data.rbp = self.tcb.rbp();
            }
            LiveThreadStatus::InWait(s, o) => {
                thread_data.status = moto_sys::stats::ThreadStatus::LiveInWait;
                thread_data.syscall_num = s;
                thread_data.syscall_op = o;
                thread_data.ip = self.tcb.rip();
                thread_data.rbp = self.tcb.rbp();
            }
        }
    }

    fn get_thread_data(&self) -> moto_sys::stats::ThreadDataV1 {
        let mut thread_data = moto_sys::stats::ThreadDataV1 {
            tid: self.tid.as_u64(),
            ..Default::default()
        };
        {
            let status = self.status.lock(line!());
            match *status {
                ThreadStatus::Created => {
                    thread_data.status = moto_sys::stats::ThreadStatus::Created
                }
                ThreadStatus::Live(live_status) => {
                    self.process_live_thread_status_locked(live_status, &mut thread_data);
                }

                ThreadStatus::PausedDebuggee(live_status) => {
                    self.process_live_thread_status_locked(live_status, &mut thread_data);
                    thread_data.paused_debuggee = 1;
                }
                ThreadStatus::Finished
                | ThreadStatus::Exited(_)
                | ThreadStatus::Error(_)
                | ThreadStatus::Killed(_) => {
                    thread_data.status = moto_sys::stats::ThreadStatus::Dead
                }
            }
        }

        let name = {
            if self.user_tcb_kernel_addr == 0 {
                ""
            } else {
                let utcb = unsafe {
                    (self.user_tcb_kernel_addr as usize as *mut UserThreadControlBlock)
                        .as_ref()
                        .unwrap_unchecked()
                };
                utcb.get_thread_name()
            }
        };
        let name_bytes = name.as_bytes();

        thread_data.name_len = name_bytes.len() as u8;
        if !name_bytes.is_empty() {
            thread_data.name_bytes[0..name_bytes.len()].copy_from_slice(name_bytes);
        }

        thread_data
    }

    pub fn wake_by_timeout(&self) {
        let mut status = self.status.lock(line!());
        match *status {
            ThreadStatus::Live(LiveThreadStatus::InWait(nr, op)) => {
                *status = ThreadStatus::Live(LiveThreadStatus::Runnable(nr, op));

                self.timed_out.store(true, Ordering::Release);

                self.trace("thread::wake_by_timeout", 0, 0);
                self.post_wake_locked(false);
            }
            _ => {
                self.trace("thread::wake_by_timeout: not waking", 0, 0);
                #[cfg(debug_assertions)]
                log::debug!(
                    "{}: wake_by_timeout: not waking: {:?}",
                    self.debug_name(),
                    *status
                );
            }
        }
    }

    fn post_wake_locked(&self, this_cpu: bool) {
        self.trace("thread::post_wake_locked", 0, 0);
        self.tcb.validate_rsp();
        if this_cpu {
            crate::sched::post(crate::sched::Job::new_on_current_cpu(
                Self::job_fn_resume_in_kernel,
                self,
            ));
        } else {
            crate::sched::post(crate::sched::Job::new(Self::job_fn_resume_in_kernel, self));
        }
    }

    pub fn wake_by_object(&self, handle: SysHandle, this_cpu: bool) {
        if self.tid().as_u64() == 2 {
            log::debug!("sys-io wake_by_object 0x{:x}", handle.as_u64());
        }
        let mut status = self.status.lock(line!());
        self.add_waker(handle);
        match *status {
            ThreadStatus::Live(LiveThreadStatus::InWait(nr, op)) => {
                *status = ThreadStatus::Live(LiveThreadStatus::Runnable(nr, op));
                self.trace("thread::wake_by_object", handle.as_u64(), 0);
                self.post_wake_locked(this_cpu);
            }
            _ => {
                /*
                log::debug!(
                    "Thread::wake_by_object: not waking: t {} {:?}",
                    self.tid.as_u64(),
                    *status
                );
                */
            }
        }
    }

    pub fn exit(&self, exit_status: u64) -> ! {
        self.trace("exit", exit_status, 0);
        {
            let mut status = self.status.lock(line!());
            match *status {
                ThreadStatus::Live(_) => {
                    *status = ThreadStatus::Exited(exit_status);
                }
                ThreadStatus::Error(_) | ThreadStatus::Killed(_) => {}
                _ => panic!("Thread::exit: unexpected thread status: {:?}", *status),
            }
        }
        self.tcb.exit()
    }

    pub fn finish(&self) -> ! {
        self.trace("finish", 0, 0);
        {
            let mut status = self.status.lock(line!());
            match *status {
                ThreadStatus::Live(_) => {
                    *status = ThreadStatus::Finished;
                }
                ThreadStatus::Error(_) | ThreadStatus::Killed(_) | ThreadStatus::Exited(_) => {}
                _ => panic!("Thread::exit: unexpected thread status: {:?}", *status),
            }
        }
        self.tcb.exit()
    }

    fn die(&self, why: ThreadKilledReason) -> ! {
        self.trace("die", 0, 0);
        // Note: must be called only by the currently running thread.
        match why {
            ThreadKilledReason::SegFault => self.tcb.die(TOCR_KILLED_SF, 0),
            ThreadKilledReason::MainThreadExited => self.tcb.die(TOCR_KILLED_OTHER, 0),
            ThreadKilledReason::ProcessKilled => self.tcb.die(TOCR_KILLED_OTHER, 0),
            _ => {
                panic!("Thread::die: unexpected reason: {:?}", why)
            }
        }
    }

    fn on_thread_exited(&self) {
        self.trace("exited", 0, 0);
        let thread_status = {
            let status = self.status.lock(line!());
            #[cfg(debug_assertions)]
            match *status {
                ThreadStatus::Finished => {
                    log::debug!("Thread 0x{:x} finished.", self.tid().as_u64());
                }
                ThreadStatus::Exited(exit_status) => {
                    log::debug!(
                        "Thread 0x{:x} exited with status 0x{:x}.",
                        self.tid().as_u64(),
                        exit_status
                    );
                }
                ThreadStatus::Killed(reason) => {
                    log::debug!("Thread 0x{:x} killed: {:?}.", self.tid().as_u64(), reason);
                }
                ThreadStatus::Error(err) => {
                    log::debug!("Thread 0x{:x} error: {:?}.", self.tid().as_u64(), err);
                }
                _ => {
                    panic!("unrecognized thread status: {:?}", *status)
                }
            }
            *status
        };

        #[cfg(debug_assertions)]
        log::debug!(
            "thread::on_thread_exited(): 0x{:x} status {:?}",
            self.tid.as_u64(),
            thread_status
        );

        let (self_object, self_handle) = {
            let (self_mut, _lock) = unsafe { self.get_mut() };
            let self_object = self_mut.self_object.take().unwrap();
            let self_handle = self_mut.self_handle;
            self_mut.self_handle = SysHandle::NONE;
            (self_object, self_handle)
        };

        core::mem::drop(self_object);

        let (join_object, join_handle) = {
            let (self_mut, _lock) = unsafe { self.get_mut() };
            let join_object = self_mut.join_object.take().unwrap();
            let join_handle = self_mut.join_handle;
            self_mut.join_handle = SysHandle::NONE;
            (join_object, join_handle)
        };

        log::debug!(
            "thread with join handle 0x{:x} exited",
            join_handle.as_u64()
        );
        SysObject::wake(&join_object, false);
        core::mem::drop(join_object);

        let owner = self.owner.upgrade().unwrap();

        // self and join handles are used to wait for the thread to complete and
        // to wake the thread. The userspace must not put() these handles,
        // because they did not get() them.
        //
        // We ignore the result because the userspace may call put()
        // on the handle, and we don't want to crash the kernel here.
        let _ = owner.put_object(&self_handle);
        let _ = owner.put_object(&join_handle);

        owner.on_thread_exited(self.tid, thread_status);
    }

    fn cleanup(&self) {
        self.owner()
            .address_space
            .drop_stacks(&self.user_stack, &self.kernel_stack_segment);
    }

    fn print_backtrace(&self) {
        let backtrace = self
            .owner()
            .address_space
            .get_backtrace(self.tcb.rip(), self.tcb.rbp());
        crate::raw_log!("\n{}: backtrace:", self.debug_name());
        for val in backtrace {
            crate::raw_log!("\t0x{:x} \\", val);
        }
    }

    fn on_pagefault(&self) {
        let (pf_addr, error_code) = self.tcb.pf_addr_error_code().unwrap();
        self.trace("thread pagefault", pf_addr, error_code);
        log::trace!("Thread #PF: 0x{:x}", pf_addr);
        let mut resume_in_userspace = false;
        let mut call_on_exited = false;

        {
            let mut status = self.status.lock(line!());
            match *status {
                ThreadStatus::Live(LiveThreadStatus::Running) => {
                    if self
                        .owner()
                        .address_space
                        .fix_pagefault(pf_addr, error_code)
                        .is_ok()
                    {
                        log::trace!("#PF fixed!");
                        if self.owner().paused_debuggee.load(Ordering::Relaxed) {
                            *status = ThreadStatus::PausedDebuggee(LiveThreadStatus::Preempted);
                        } else {
                            *status = ThreadStatus::Live(LiveThreadStatus::Preempted);
                            resume_in_userspace = true;
                        }
                    } else {
                        log::info!(
                            "#PF: thread {} killed: pf_addr: 0x{:x}\n\trip: 0x{:x} stack: 0x{:x?}",
                            self.debug_name(),
                            pf_addr,
                            self.tcb.rip(),
                            self.user_stack
                        );
                        self.print_backtrace();
                        *status = ThreadStatus::Killed(ThreadKilledReason::PageFault);
                        call_on_exited = true;
                    }
                }
                ThreadStatus::Killed(_) => {
                    call_on_exited = true;
                }
                _ => panic!("Unexpected thread status {:?}", *status),
            }
        }
        if resume_in_userspace {
            // Page faults should not lead to CPU migrations.
            crate::sched::post(crate::sched::Job::new_on_current_cpu(
                Self::job_fn_resume_in_userspace,
                self,
            ));
        } else if call_on_exited {
            self.on_thread_exited();
        }
    }

    fn on_thread_descheduled(&self, tocr: ThreadOffCpuReason) {
        crate::util::full_fence();
        self.trace("on_thread_descheduled", 0, 0);
        match tocr {
            ThreadOffCpuReason::Exited => self.on_thread_exited(),
            ThreadOffCpuReason::Paused => self.on_thread_paused(),
            ThreadOffCpuReason::Preempted => {
                if self.tcb.pf_addr_error_code().is_some() {
                    self.on_pagefault();
                } else {
                    self.trace("thread::on_thread_preempted", 0, 0);
                    log::debug!("thread {} preempted", self.debug_name());

                    let mut resume_in_userspace = false;
                    let mut call_on_exited = false;
                    {
                        let mut status = self.status.lock(line!());
                        match *status {
                            ThreadStatus::Live(LiveThreadStatus::Running) => {
                                if self.owner().paused_debuggee.load(Ordering::Relaxed) {
                                    *status =
                                        ThreadStatus::PausedDebuggee(LiveThreadStatus::Preempted);
                                } else {
                                    *status = ThreadStatus::Live(LiveThreadStatus::Preempted);
                                    resume_in_userspace = true;
                                }
                            }
                            ThreadStatus::Killed(_) => {
                                call_on_exited = true;
                            }
                            _ => panic!("Unexpected thread status {:?}", *status),
                        }
                    }
                    if resume_in_userspace {
                        crate::sched::post(crate::sched::Job::new(
                            Self::job_fn_resume_in_userspace,
                            self,
                        ));
                    } else if call_on_exited {
                        self.on_thread_exited();
                    }
                }
            }
            ThreadOffCpuReason::KilledPf(addr) => {
                {
                    let mut status = self.status.lock(line!());
                    if self.user_stack.is_overflow(addr) {
                        log::debug!(
                            "Thread killed: {:?}: #PF(0x{:x}): stack overflow.",
                            *status,
                            addr
                        );
                    } else if self.user_stack.is_underflow(addr) {
                        log::debug!(
                            "Thread killed: {:?}: #PF(0x{:x}): stack underflow.",
                            *status,
                            addr
                        );
                    } else {
                        log::debug!("Thread killed: {:?}: #PF(0x{:x})", *status, addr);
                    }

                    match *status {
                        ThreadStatus::Live(LiveThreadStatus::Running) => {
                            *status = ThreadStatus::Killed(ThreadKilledReason::PageFault)
                        }

                        ThreadStatus::Killed(ThreadKilledReason::ProcessKilled) => {}
                        _ => panic!("Unexpected thread status {:?}", *status),
                    }
                }
                self.on_thread_exited();
            }
            ThreadOffCpuReason::KilledGpf => {
                {
                    self.print_backtrace();
                    let mut status = self.status.lock(line!());
                    log::debug!("Thread killed (#GPF): {:?}", *status);
                    match *status {
                        ThreadStatus::Live(LiveThreadStatus::Running) => {
                            *status = ThreadStatus::Killed(ThreadKilledReason::GPF)
                        }
                        ThreadStatus::Killed(ThreadKilledReason::ProcessKilled) => {}
                        _ => panic!("Unexpected thread status {:?}", *status),
                    }
                }
                self.on_thread_exited();
            }
            ThreadOffCpuReason::KilledSf => {
                {
                    let mut status = self.status.lock(line!());
                    log::debug!("Thread killed: {:?}", *status);
                    if let ThreadStatus::Live(LiveThreadStatus::Syscall(_, _)) = *status {
                        *status = ThreadStatus::Killed(ThreadKilledReason::SegFault);
                    } else {
                        panic!("KilledSf: unexpected thread status: {:?}", *status);
                    }
                }
                self.on_thread_exited();
            }
            ThreadOffCpuReason::KilledOther => {
                {
                    let status = self.status.lock(line!());
                    log::debug!("Thread killed: {:?}", *status);
                    assert_matches!(*status, ThreadStatus::Killed(_));
                }
                self.on_thread_exited();
            }
        }
    }

    fn job_fn_resume_in_userspace(thread: Weak<Self>, _: u64) {
        crate::xray::tracing::trace("job_fn_resume_in_userspace", 0, 0, 0);
        crate::xray::tracing::trace(
            "job_fn_resume_in_userspace + weak",
            thread.weak_count() as u64,
            0,
            0,
        );
        crate::xray::tracing::trace(
            "job_fn_resume_in_userspace + strong + weak",
            thread.strong_count() as u64,
            thread.weak_count() as u64,
            0,
        );
        if let Some(thread) = thread.upgrade() {
            crate::xray::tracing::trace("job_fn_resume_in_userspace 10", 0, 0, 0);
            thread.resume_in_userspace();
        }
    }

    fn job_fn_resume_in_kernel(thread: Weak<Self>, _: u64) {
        crate::xray::tracing::trace("job_fn_resume_in_kernel", 0, 0, 0);
        if let Some(thread) = thread.upgrade() {
            thread.resume_in_kernel();
        }
    }

    fn job_fn_start(thread: Weak<Self>, arg: u64) {
        crate::xray::tracing::trace("job_fn_start", 0, 0, 0);
        if let Some(thread) = thread.upgrade() {
            thread.do_start(arg);
        }
    }

    fn job_fn_wake_by_timeout(thread: Weak<Self>, timer_id: u64) {
        crate::xray::tracing::trace("job_fn_wake_by_timeout", 0, 0, 0);
        if let Some(thread) = thread.upgrade() {
            if thread
                .timer_id
                .compare_exchange(timer_id, 0, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                thread.wake_by_timeout();
            }
        }
    }

    fn job_fn_on_thread_exited(thread: Weak<Self>, _: u64) {
        crate::xray::tracing::trace("job_fn_on_thread_exited", 0, 0, 0);
        if let Some(thread) = thread.upgrade() {
            thread.on_thread_exited();
        }
    }
}

pub fn post_kill_by_pid(pid: u64) {
    crate::sched::post(crate::sched::Job::new_with_arg(
        Process::job_fn_kill_by_pid,
        pid,
    ));
}
