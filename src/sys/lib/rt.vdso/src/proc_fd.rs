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
use moto_rt::{E_BAD_HANDLE, E_INVALID_ARGUMENT, ErrorCode, RtFd};
use moto_sys::SysHandle;

pub fn new_child_fd(handle: SysHandle) -> RtFd {
    posix::push_file(ChildFd::from_handle(handle))
}

/// FD from Child handle.
struct ChildFd {
    handle: SysHandle,
    completion_group: Option<Arc<crate::stdio_relay::CompletionGroup>>,
    event_source: Arc<super::runtime::EventSourceUnmanaged>,
}

impl ChildFd {
    fn from_handle(handle: SysHandle) -> Arc<Self> {
        let completion_group = crate::stdio_relay::completion_group(handle.as_u64());
        let child_group = completion_group.clone();
        let child = Arc::new_cyclic(|me| Self {
            handle,
            completion_group: child_group,
            event_source: super::runtime::EventSourceUnmanaged::new(
                handle,
                me.clone() as _,
                moto_rt::poll::POLL_READABLE,
            ),
        });
        if let Some(group) = completion_group {
            group.register_listener(&child.event_source);
        }
        child
    }

    fn is_finalized(&self) -> bool {
        self.completion_group
            .as_ref()
            .is_none_or(|group| group.is_complete())
    }
}

impl super::runtime::UnmanagedEventSourceHolder for ChildFd {
    fn check_interests(&self, interests: Interests) -> moto_rt::poll::EventBits {
        if interests != moto_rt::poll::POLL_READABLE {
            return 0;
        }

        if self.is_finalized()
            && let Ok(Some(_)) = moto_sys::SysRay::process_status(self.handle)
        {
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

    fn descriptor_attr(
        &self,
        object_id: core::num::NonZeroU64,
    ) -> Result<moto_rt::fs::FileAttr, ErrorCode> {
        Ok(posix::synthetic_attr(
            moto_rt::fs::FILETYPE_ANONYMOUS,
            object_id,
        ))
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, ErrorCode> {
        if buf.len() != 8 {
            return Err(moto_rt::E_INVALID_ARGUMENT);
        }
        if !self.is_finalized() {
            return Err(moto_rt::E_NOT_READY);
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

    fn poll_add(&self, registration: &Arc<crate::runtime::Registration>) -> Result<(), ErrorCode> {
        self.event_source.add_interests(registration)
    }

    fn poll_set(
        &self,
        registration: &Arc<crate::runtime::Registration>,
        token: Token,
        interests: Interests,
    ) -> Result<(), ErrorCode> {
        self.event_source
            .set_interests(registration, token, interests)
    }

    fn poll_del(&self, registration: &Arc<crate::runtime::Registration>) -> Result<(), ErrorCode> {
        self.event_source.del_interests(registration)
    }
}
