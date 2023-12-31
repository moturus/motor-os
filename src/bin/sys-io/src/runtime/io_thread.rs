// I/O manager/runtime. A single thread to avoid dealing with synchronization.
use core::intrinsics::{likely, unlikely};
use std::collections::{HashMap, HashSet, VecDeque};

use moto_ipc::io_channel;
use moto_runtime::rt_api;
use moto_sys::syscalls::*;
use moto_sys::{ErrorCode, SysHandle};

use super::process::Process;
use super::IoSubsystem;
use super::PendingCompletion;
use crate::moto_log;

struct IoRuntime {
    net: Box<dyn IoSubsystem>,
    net_handles: HashSet<SysHandle>,

    listeners: HashMap<SysHandle, io_channel::Server>,
    processes: HashMap<SysHandle, Process>,

    all_handles: Vec<SysHandle>,

    pending_completions: VecDeque<PendingCompletion>,
    cached_wakee: SysHandle,
}

impl IoRuntime {
    const MIN_LISTENERS: usize = 3;
    const MAX_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(5);

    fn drop_process(&mut self, handle: SysHandle) {
        if let Some(mut proc) = self.processes.remove(&handle) {
            self.net.on_process_drop(&mut proc);

            self.update_handles();

            #[cfg(debug_assertions)]
            crate::moto_log!(
                "{}:{} dropped process handle 0x{:x}",
                file!(),
                line!(),
                handle.as_u64()
            );
        } else {
            panic!("bad process handle 0x{:x}", handle.as_u64());
        }
    }

    fn update_handles(&mut self) {
        self.all_handles.clear();
        let mut handles: Vec<SysHandle> = self.processes.keys().map(|h| *h).collect();
        for handle in &self.net_handles {
            handles.push(*handle);
        }

        let mut listener_handles: Vec<SysHandle> = self.listeners.keys().map(|h| *h).collect();
        handles.append(&mut listener_handles);

        core::mem::swap(&mut self.all_handles, &mut handles);
    }

    fn cache_wakee(&mut self, wakee: SysHandle) -> bool {
        let mut had_work = false;

        if self.cached_wakee != wakee {
            if likely(!self.cached_wakee.is_none()) {
                if SysCpu::wake(self.cached_wakee).is_err() {
                    #[cfg(debug_assertions)]
                    moto_log!("dropping connection 0x{:x}", self.cached_wakee.as_u64());
                    self.drop_process(self.cached_wakee);
                }
                had_work = true;
            }

            self.cached_wakee = wakee;
        }

        had_work
    }

    fn spawn_listeners_if_needed(&mut self) {
        while self.listeners.len() < Self::MIN_LISTENERS {
            let listener = match io_channel::Server::create("sys-io") {
                Ok(server) => server,
                Err(err) => {
                    panic!("Failed to spawn a sys-io listener: {:?}", err);
                }
            };

            self.all_handles.push(listener.wait_handle());
            #[cfg(debug_assertions)]
            crate::moto_log!(
                "{}:{} new listener handle 0x{:x}",
                file!(),
                line!(),
                listener.wait_handle().as_u64()
            );
            self.listeners.insert(listener.wait_handle(), listener);
        }
    }

    fn poll_endpoint(&mut self, handle: SysHandle, mut timeout_wakeup: bool) {
        let proc = if unlikely(timeout_wakeup) {
            if let Some(p) = self.processes.get_mut(&handle) {
                p
            } else {
                return;
            }
        } else {
            self.processes.get_mut(&handle).unwrap()
        };
        debug_assert_eq!(proc.conn().status(), io_channel::ServerStatus::Connected);

        let mut wake_conn = false;

        loop {
            let mut sqe = match proc.conn().get_sqe() {
                Ok(sqe) => sqe,
                Err(err) => {
                    assert_eq!(err, ErrorCode::NotReady);
                    break;
                }
            };

            if unlikely(timeout_wakeup) {
                moto_log!(
                    "{}:{} timeout wakeup: got sqe 0x{:x} for proc 0x{:x}",
                    file!(),
                    line!(),
                    sqe.id,
                    proc.handle().as_u64()
                );
                timeout_wakeup = false;
            }

            if sqe.status() != ErrorCode::NotReady {
                sqe.status = ErrorCode::InvalidArgument.into();
                if let Err(err) = proc.conn().complete_sqe(sqe) {
                    debug_assert_eq!(err, ErrorCode::NotReady);
                    self.pending_completions.push_back(PendingCompletion {
                        cqe: sqe,
                        endpoint_handle: handle,
                    });
                }

                wake_conn = true;
                continue;
            }

            match sqe.command {
                rt_api::net::CMD_MIN..=rt_api::net::CMD_MAX => {
                    if let Some(cqe) = self.net.process_sqe(proc, sqe) {
                        debug_assert_ne!(cqe.status(), ErrorCode::NotReady);
                        if let Err(err) = proc.conn().complete_sqe(cqe) {
                            #[cfg(debug_assertions)]
                            moto_log!("complete_sqe() failed");
                            debug_assert_eq!(err, ErrorCode::NotReady);
                            self.pending_completions.push_back(PendingCompletion {
                                cqe: sqe,
                                endpoint_handle: handle,
                            });
                        }
                        wake_conn = true;
                    }
                }
                _ => {
                    sqe.status = ErrorCode::InvalidArgument.into();
                    if let Err(err) = proc.conn().complete_sqe(sqe) {
                        debug_assert_eq!(err, ErrorCode::NotReady);
                        self.pending_completions.push_back(PendingCompletion {
                            cqe: sqe,
                            endpoint_handle: handle,
                        });
                    }

                    wake_conn = true;
                }
            }
        }

        if wake_conn {
            self.cache_wakee(handle);
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
                    moto_log!("io_runtime: accept() failed.");
                    return;
                }
                self.processes.insert(handle, Process::from_conn(listener));
            }
        }

        self.poll_endpoint(handle, timeout_wakeup);
    }

    fn process_wakeups(&mut self, handles: Vec<SysHandle>, timeout_wakeup: bool) {
        for handle in handles {
            if handle != SysHandle::NONE {
                self.process_wakeup(handle, timeout_wakeup);
            }
        }
    }

    fn process_completions(&mut self) -> bool {
        let mut had_work = false;
        let mut completions = VecDeque::new();
        core::mem::swap(&mut completions, &mut self.pending_completions);

        for completion in completions {
            had_work = true;
            let proc = match self.processes.get_mut(&completion.endpoint_handle) {
                Some(endpoint) => endpoint,
                None => continue, // Endpoint was dropped.
            };

            let wakee = completion.endpoint_handle;

            if let Err(err) = proc.conn().complete_sqe(completion.cqe) {
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
                self.drop_process(bad_handle);
            }
        }
    }

    fn start_io_thread() {
        let mut self_mut = Self {
            net: crate::net::init(),
            net_handles: HashSet::new(),

            listeners: HashMap::new(),
            processes: HashMap::new(),
            all_handles: Vec::new(),

            pending_completions: VecDeque::new(),
            cached_wakee: SysHandle::NONE,
        };

        for handle in self_mut.net.wait_handles() {
            self_mut.net_handles.insert(handle);
        }

        self_mut.update_handles();

        #[cfg(debug_assertions)]
        crate::moto_log!("{}:{} affine the IO thread to CPU0", file!(), line!());

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

        loop {
            let mut had_work = false;
            loop {
                match self.net.poll() {
                    Some(p_c) => {
                        had_work = true;
                        self.pending_completions.push_back(p_c);
                    }
                    None => break,
                }
            }

            had_work |= self.process_completions();
            had_work |= self.cache_wakee(SysHandle::NONE); // Trigger a pending wakeup, if any.

            if !had_work {
                let mut handles = self.all_handles.clone();

                let timeout: core::time::Duration = self.wait_timeout();
                if timeout.is_zero() {
                    continue;
                }

                core::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
                core::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                let result = SysCpu::wait(
                    &mut handles[..],
                    SysHandle::NONE,
                    SysHandle::NONE,
                    Some(moto_sys::time::Instant::now() + timeout),
                );
                core::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
                core::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                match result {
                    Ok(()) => self.process_wakeups(handles, false),
                    Err(err) => {
                        if err == ErrorCode::TimedOut {
                            // #[cfg(debug_assertions)]
                            // crate::moto_log!("{}:{} timeout wakeup", file!(), line!());
                            // self.process_wakeups(self.all_handles.clone(), true);
                            self.process_wakeups(handles, true);
                        } else {
                            self.process_errors(handles);
                        }
                    }
                }
            }
        }
    }
}

pub(super) fn start() {
    let _ = std::thread::spawn(IoRuntime::start_io_thread);
}
