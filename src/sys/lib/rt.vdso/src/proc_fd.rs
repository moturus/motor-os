use crate::posix::PosixFile;
use crate::posix::{self, PosixKind};
use crate::{rt_process::ProcessData, rt_process::StdioData};
use alloc::sync::Arc;
use alloc::{boxed::Box, vec::Vec};
use core::any::Any;
use core::sync::atomic::*;
use moto_ipc::stdio_pipe::StdioPipe;
use moto_rt::poll::Interests;
use moto_rt::poll::Token;
use moto_rt::spinlock::SpinLock;
use moto_rt::{ErrorCode, RtFd, E_BAD_HANDLE, E_INVALID_ARGUMENT};
use moto_sys::SysHandle;

pub fn new_child_fd(handle: SysHandle) -> RtFd {
    posix::push_file(ChildFd::from_handle(handle))
}

/// FD from Child handle.
struct ChildFd {
    handle: SysHandle,
    event_source: Arc<super::runtime::EventSourceUnmanaged>,
}

impl ChildFd {
    fn from_handle(handle: SysHandle) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            handle,
            event_source: super::runtime::EventSourceUnmanaged::new(
                handle,
                me.clone() as _,
                moto_rt::poll::POLL_READABLE,
            ),
        })
    }
}

impl super::runtime::UnmanagedEventSourceHolder for ChildFd {
    fn check_interests(&self, interests: Interests) -> moto_rt::poll::EventBits {
        if interests != moto_rt::poll::POLL_READABLE {
            return 0;
        }

        if let Ok(Some(_)) = moto_sys::SysRay::process_status(self.handle) {
            moto_rt::poll::POLL_READABLE
        } else {
            0
        }
    }

    fn on_handle_error(&self) {
        self.event_source.on_closed_remotely(true);
    }
}

impl PosixFile for ChildFd {
    fn kind(&self) -> PosixKind {
        PosixKind::ChildProcess
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        if buf.len() != 8 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }

        let maybe_status = moto_sys::SysRay::process_status(self.handle)?;
        let Some(status) = maybe_status else {
            return Err(moto_rt::E_NOT_READY);
        };

        unsafe {
            core::ptr::copy_nonoverlapping(
                &status as *const u64 as usize as *const u8,
                buf.as_mut_ptr(),
                8,
            );
        }
        Ok(8)
    }

    fn write(&self, buf: &[u8]) -> Result<usize, ErrorCode> {
        Err(moto_rt::E_INVALID_ARGUMENT)
    }

    fn flush(&self) -> Result<(), ErrorCode> {
        Ok(())
    }

    fn close(&self, source_fd: RtFd) -> Result<(), ErrorCode> {
        self.event_source.on_closed_locally(source_fd);
        Ok(())
    }

    fn set_nonblocking(&self, val: bool) -> Result<(), ErrorCode> {
        if val {
            Ok(())
        } else {
            Err(moto_rt::E_INVALID_ARGUMENT)
        }
    }

    fn poll_add(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.event_source
            .add_interests(r_id, source_fd, token, interests)
    }

    fn poll_set(
        &self,
        r_id: u64,
        source_fd: RtFd,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.event_source
            .set_interests(r_id, source_fd, token, interests)
    }

    fn poll_del(&self, r_id: u64, source_fd: RtFd) -> Result<(), ErrorCode> {
        self.event_source.del_interests(r_id, source_fd)
    }
}
