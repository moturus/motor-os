// I/O manager/runtime. A single thread to avoid dealing with synchronization.
use core::intrinsics::{likely, unlikely};
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;

use moto_ipc::io_channel;
use moto_runtime::rt_api;
use moto_sys::syscalls::*;
use moto_sys::ErrorCode;

use super::IoSubsystem;
use super::PendingCompletion;

struct IoRuntime {
    net: Box<dyn IoSubsystem>,
    net_handles: HashSet<SysHandle>,

    listeners: HashMap<SysHandle, io_channel::ServerConnection>,
    connections: HashMap<SysHandle, Rc<io_channel::ServerConnection>>,

    all_handles: Vec<SysHandle>,

    pending_completions: VecDeque<PendingCompletion>,
    cached_wakee_connection: SysHandle,
}

impl IoRuntime {
    const MIN_LISTENERS: usize = 3;
    const MAX_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(6);

    fn drop_connection(&mut self, handle: SysHandle) {
        if let Some(conn) = self.connections.remove(&handle) {
            self.net.on_connection_drop(handle);
            assert_eq!(1, Rc::strong_count(&conn));

            self.update_handles();
            if self.cached_wakee_connection == handle {
                self.cached_wakee_connection = SysHandle::NONE;
            }

            log::debug!("dropping client 0x{:x}", handle.as_u64());

            // Ignore errors below because the target could be dead.
            let _ = moto_sys::syscalls::SysCpu::kill_remote(handle);
        } // else: we may have deferred completions for dead connections.
    }

    fn update_handles(&mut self) {
        self.all_handles.clear();
        let mut handles: Vec<SysHandle> = self.connections.keys().map(|h| *h).collect();
        for handle in &self.net_handles {
            handles.push(*handle);
        }

        let mut listener_handles: Vec<SysHandle> = self.listeners.keys().map(|h| *h).collect();
        handles.append(&mut listener_handles);

        core::mem::swap(&mut self.all_handles, &mut handles);
    }

    fn cache_wakee(&mut self, wakee_connection: SysHandle) -> bool {
        let mut had_work = false;

        if self.cached_wakee_connection != wakee_connection {
            if likely(!self.cached_wakee_connection.is_none()) {
                // #[cfg(debug_assertions)]
                // log::debug!(
                //     "waking connection 0x{:x}",
                //     self.cached_wakee_connection.as_u64()
                // );
                if SysCpu::wake(self.cached_wakee_connection).is_err() {
                    #[cfg(debug_assertions)]
                    log::debug!(
                        "dropping connection 0x{:x}",
                        self.cached_wakee_connection.as_u64()
                    );
                    self.drop_connection(self.cached_wakee_connection);
                }
                had_work = true;
            }

            self.cached_wakee_connection = wakee_connection;
        }

        had_work
    }

    fn spawn_listeners_if_needed(&mut self) {
        while self.listeners.len() < Self::MIN_LISTENERS {
            let listener = match io_channel::ServerConnection::create("sys-io") {
                Ok(server) => server,
                Err(err) => {
                    panic!("Failed to spawn a sys-io listener: {:?}", err);
                }
            };

            self.all_handles.push(listener.wait_handle());
            #[cfg(debug_assertions)]
            log::debug!(
                "new listener handle 0x{:x}",
                listener.wait_handle().as_u64()
            );
            self.listeners.insert(listener.wait_handle(), listener);
        }
    }

    fn poll_endpoint(&mut self, endpoint_handle: SysHandle, mut timeout_wakeup: bool) {
        let conn = if unlikely(timeout_wakeup) {
            if let Some(p) = self.connections.get_mut(&endpoint_handle) {
                p
            } else {
                return;
            }
        } else {
            self.connections.get_mut(&endpoint_handle).unwrap()
        };
        debug_assert_eq!(conn.status(), io_channel::ServerStatus::Connected);

        let mut wake_conn = false;

        #[cfg(debug_assertions)]
        if unlikely(timeout_wakeup) {
            conn.dump_state();
        }

        loop {
            let msg = match conn.recv() {
                Ok(sqe) => sqe,
                Err(err) => {
                    assert_eq!(err, ErrorCode::NotReady);
                    break;
                }
            };

            if unlikely(timeout_wakeup) {
                log::info!(
                    "timeout wakeup: got sqe 0x{:x} for conn 0x{:x}:{:x}",
                    msg.id,
                    conn.wait_handle().as_u64(),
                    msg.wake_handle
                );
                timeout_wakeup = false;
            }

            if msg.status() != ErrorCode::NotReady {
                log::info!(
                    "Dropping conn 0x{:x} due to bad sqe {} {:?}.",
                    endpoint_handle.as_u64(),
                    msg.command,
                    msg.status()
                );
                self.drop_connection(endpoint_handle);
                return;
            }

            match msg.command {
                io_channel::CMD_NOOP_OK => {
                    let mut cqe = msg;
                    if cqe.flags == io_channel::FLAG_CMD_NOOP_OK_TIMESTAMP {
                        cqe.payload.args_64_mut()[2] = moto_sys::time::Instant::now().as_u64();
                    }

                    cqe.status = ErrorCode::Ok.into();
                    if let Err(err) = conn.send(cqe) {
                        debug_assert_eq!(err, ErrorCode::NotReady);
                        self.pending_completions.push_back(PendingCompletion {
                            msg: cqe,
                            endpoint_handle,
                        });
                    }
                }
                rt_api::net::CMD_MIN..=rt_api::net::CMD_MAX => {
                    match self.net.process_sqe(conn, msg) {
                        Ok(res) => {
                            if let Some(cqe) = res {
                                debug_assert_ne!(cqe.status(), ErrorCode::NotReady);
                                if let Err(err) = conn.send(cqe) {
                                    debug_assert_eq!(err, ErrorCode::NotReady);
                                    self.pending_completions.push_back(PendingCompletion {
                                        msg: cqe,
                                        endpoint_handle,
                                    });
                                }
                            }
                        }
                        Err(_) => {
                            log::info!(
                                "Dropping conn 0x{:x} due to error in process_sqe.",
                                endpoint_handle.as_u64()
                            );
                            self.drop_connection(endpoint_handle);
                            return;
                        }
                    }
                }
                _ => {
                    log::info!(
                        "Dropping conn 0x{:x} due to bad sqe.",
                        endpoint_handle.as_u64()
                    );
                    self.drop_connection(endpoint_handle);
                    return;
                }
            }

            // TODO: we don't need to wake conn here; only if/when the incoming
            //       queue was full.
            wake_conn = true;
        }

        // Cannot cache wakee inline due to borrow checker rules, which is correct here:
        // cache_wakee may drop the connection we are working with.
        if wake_conn {
            self.cache_wakee(endpoint_handle);
        }
    }

    fn process_wakeup(&mut self, handle: SysHandle, timeout_wakeup: bool) {
        if self.net_handles.contains(&handle) {
            self.net.process_wakeup(handle);
            return;
        }

        // It is unsafe to work with listeners without an explicit wakeup (accept will #PF).
        if likely(!timeout_wakeup) {
            if let Some(mut listener) = self.listeners.remove(&handle) {
                self.spawn_listeners_if_needed();
                if unsafe { listener.accept() }.is_err() {
                    #[cfg(debug_assertions)]
                    log::debug!("io_runtime: accept() failed.");
                    return;
                }
                #[cfg(debug_assertions)]
                log::debug!("io_runtime: new connection 0x{:x}.", handle.as_u64());
                self.connections.insert(handle, Rc::new(listener));
            }
        }

        self.poll_endpoint(handle, timeout_wakeup);
    }

    fn process_wakeups(&mut self, handles: Vec<SysHandle>, timeout_wakeup: bool) -> bool {
        let mut had_work = false;
        for handle in &handles {
            if *handle != SysHandle::NONE {
                self.process_wakeup(*handle, timeout_wakeup);
                had_work = true;
            }
        }

        had_work
    }

    fn process_completions(&mut self) -> bool {
        let mut had_work = false;
        let mut completions = VecDeque::new();
        core::mem::swap(&mut completions, &mut self.pending_completions);

        for completion in completions {
            had_work = true;
            let conn = match self.connections.get_mut(&completion.endpoint_handle) {
                Some(endpoint) => endpoint,
                None => continue, // Endpoint was dropped.
            };

            let wakee = completion.endpoint_handle;

            if let Err(err) = conn.send(completion.msg) {
                debug_assert_eq!(err, ErrorCode::NotReady);
                self.pending_completions.push_back(completion);
            }

            self.cache_wakee(wakee);
        }

        had_work
    }

    fn process_errors(&mut self, bad_handles: Vec<SysHandle>) {
        for bad_handle in bad_handles {
            if bad_handle != SysHandle::NONE {
                self.drop_connection(bad_handle);
            }
        }
    }

    fn start_io_thread() {
        let mut self_mut = Self {
            net: crate::net::init(),
            net_handles: HashSet::new(),

            listeners: HashMap::new(),
            connections: HashMap::new(),
            all_handles: Vec::new(),

            pending_completions: VecDeque::new(),
            cached_wakee_connection: SysHandle::NONE,
        };

        for handle in self_mut.net.wait_handles() {
            self_mut.net_handles.insert(handle);
        }

        self_mut.update_handles();

        SysCpu::affine_to_cpu(Some(0)).unwrap();
        std::thread::sleep(core::time::Duration::from_micros(10));
        self_mut.io_thread();
    }

    fn wait_timeout(&mut self) -> core::time::Duration {
        if let Some(timo) = self.net.wait_timeout() {
            if timo < Self::MAX_TIMEOUT {
                return timo;
            }
        }
        Self::MAX_TIMEOUT
    }

    fn io_thread(&mut self) -> ! {
        self.spawn_listeners_if_needed();

        super::STARTED.store(1, std::sync::atomic::Ordering::Release);
        moto_runtime::futex_wake(&super::STARTED);

        let mut busy_polling_iter = 0_u32;
        let mut debug_timed_out = false;
        loop {
            let mut had_work = false;

            let mut cnt = 0;
            loop {
                cnt += 1;
                if cnt > 32 {
                    // We don't want to starve things like outgoing connections,
                    // which require the wait() below.
                    break;
                }
                match self.net.poll() {
                    Some(p_c) => {
                        had_work = true;
                        if debug_timed_out {
                            log::debug!("net poll on timeout: {:?}", p_c.msg.status());
                        }
                        self.pending_completions.push_back(p_c);
                        self.process_completions();
                    }
                    None => break,
                }
            }
            debug_timed_out = false;

            had_work |= self.process_completions();

            // process_wakeups() below polls new SQEs and new client connections.
            //
            // Note: while it may seem useful to track which connections submitted SQEs
            // and then poll them (call process_wakeup()) directly instead of doing
            // SysCpu::wait() first, it is unsafe, as polling a disconnected client leads to #PF.
            // The #PF issue should probably be fixed, but it is present at the moment...
            //
            // In addition, tracking "active" clients seems to be no less expensive
            // than doing a non-blocking syscall (this is an I/O thread and is treated
            // specially in the kernel) if the number of clients is small.
            let mut handles = self.all_handles.clone();
            match SysCpu::wait(
                &mut handles[..],
                SysHandle::NONE,
                SysHandle::NONE,
                Some(moto_sys::time::Instant::nan()),
            ) {
                Ok(()) => {
                    if !handles.is_empty() {
                        // This polls for incoming SQEs.
                        had_work |= self.process_wakeups(handles, false);
                    }
                }
                Err(_) => {
                    self.process_errors(handles);
                    continue;
                }
            }

            had_work |= self.cache_wakee(SysHandle::NONE); // Trigger a pending wakeup, if any.

            if had_work {
                busy_polling_iter = 0;
                continue;
            } else {
                busy_polling_iter += 1;
                if busy_polling_iter < 16 {
                    continue;
                }
            }

            // Go to sleep.
            let mut handles = self.all_handles.clone();

            let timeout: core::time::Duration = self.wait_timeout();
            if timeout.is_zero() {
                continue;
            }

            let result = SysCpu::wait(
                &mut handles[..],
                SysHandle::NONE,
                SysHandle::NONE,
                Some(moto_sys::time::Instant::now() + timeout),
            );
            match result {
                Ok(()) => {
                    debug_timed_out = false;
                    self.process_wakeups(handles, false);
                }
                Err(err) => {
                    if err == ErrorCode::TimedOut {
                        if timeout >= core::time::Duration::from_secs(1) {
                            debug_timed_out = true;
                            // #[cfg(debug_assertions)]
                            // {
                            //     log::debug!("timeout wakeup");

                            //     let cpu_usage = moto_runtime::util::get_cpu_usage();
                            //     log::debug!("\tcpu usage: ");
                            //     let mut s = String::new();
                            //     for n in &cpu_usage {
                            //         s.push_str(std::format!("{: >5.1}% ", (*n) * 100.0).as_str());
                            //     }
                            //     log::debug!("{}", s);
                            // }

                            assert!(self.pending_completions.is_empty());
                            self.process_wakeups(self.all_handles.clone(), true);
                        } else {
                            debug_timed_out = false;
                            self.process_wakeups(handles, false);
                        }
                    } else {
                        debug_timed_out = false;
                        self.process_errors(handles);
                    }
                }
            }
        }
    }
}

pub(super) fn start() {
    let _ = std::thread::spawn(IoRuntime::start_io_thread);
}
