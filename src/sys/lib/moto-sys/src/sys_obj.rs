//! SysObj syscall.

#[cfg(feature = "userspace")]
use crate::syscalls::*;
#[cfg(feature = "userspace")]
use crate::ErrorCode;

/// SysObj syscall: various object-management-related operations.
pub struct SysObj;

impl SysObj {
    pub const OP_GET: u8 = 1;
    pub const OP_PUT: u8 = 2;
    pub const OP_CREATE: u8 = 3;
    pub const OP_QUERY_HANDLE: u8 = 4;

    pub const F_QUERY_PEER: u32 = 2;
    pub const F_QUERY_PID: u32 = 4;

    // When connecting to ("getting") a shared URL, wake the counterpart.
    pub const F_WAKE_PEER: u32 = 1;

    // URLS:
    //     - "address_space:$URL"
    //                  Creates a new address space that can be identified by the $URL;
    //     - "capabilities"
    //     - "irq_wait:$NUM"
    //     - "process:entry_point=$NUM;capabilities=$NUM"
    //     - "serial_console"
    //     - "shared:url=$URL;address=$addr;page_type=[small|mid];page_num=$num"
    //            - A "server" calls CREATE for a custom URL (can be duplicates). Then waits.
    //              may provide an unmapped page.
    //            - A "client" calls GET for the URL; page must be mapped; if there is a matching
    //              endpoint, the IPC channel is created and returned. Who then waits and who wakes
    //              is up to the userspace.
    //            - For now, only 1:1 connections are supported.
    //            - Later "multicast" connections will be added (server writes), multiple clients read.
    #[cfg(feature = "userspace")]
    pub fn create(parent: SysHandle, flags: u32, url: &str) -> Result<SysHandle, ErrorCode> {
        let bytes = url.as_bytes();

        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_CREATE, flags, 0),
            parent.as_u64(),
            bytes.as_ptr() as usize as u64,
            bytes.len() as u64,
            0,
            0,
            0,
        );
        if result.is_ok() {
            Ok(SysHandle::from(result.data[0]))
        } else {
            Err(result.error_code())
        }
    }

    // Create a pair of wait handles so that the userspace can wake/wait/swap on them.
    // Similar to shared, but while shared is more of a server/client setup,
    // the IPC pair is more of a direct connection (e.g. stdio).
    //
    // Returned handles are valid inside processes passed as parameters, not
    // the caller; the caller can pass SysHandle::SELF to have one (or both) of
    // the wait handles to belong to it.
    #[cfg(feature = "userspace")]
    pub fn create_ipc_pair(
        process1: SysHandle,
        process2: SysHandle,
        flags: u32,
    ) -> Result<(SysHandle, SysHandle), ErrorCode> {
        let bytes = "ipc_pair".as_bytes();
        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_CREATE, flags, 0),
            process1.as_u64(),
            bytes.as_ptr() as usize as u64,
            bytes.len() as u64,
            process2.as_u64(),
            0,
            0,
        );
        if result.is_ok() {
            Ok((
                SysHandle::from(result.data[0]),
                SysHandle::from(result.data[1]),
            ))
        } else {
            Err(result.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn get(parent: SysHandle, flags: u32, url: &str) -> Result<SysHandle, ErrorCode> {
        let res = Self::get_res1(parent, flags, url)?;
        Ok(res.0)
    }

    #[cfg(feature = "userspace")]
    pub fn get_res1(
        parent: SysHandle,
        flags: u32,
        url: &str,
    ) -> Result<(SysHandle, u64), ErrorCode> {
        let bytes = url.as_bytes();

        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_GET, flags, 0),
            parent.as_u64(),
            bytes.as_ptr() as usize as u64,
            bytes.len() as u64,
            0,
            0,
            0,
        );
        if result.is_ok() {
            Ok((SysHandle::from(result.data[0]), result.data[1]))
        } else {
            Err(result.error_code())
        }
    }

    #[cfg(feature = "userspace")]
    pub fn put(handle: SysHandle) -> Result<(), ErrorCode> {
        Self::put_1(handle, 0)
    }

    #[cfg(feature = "userspace")]
    pub fn put_1(handle: SysHandle, arg: u64) -> Result<(), ErrorCode> {
        Self::put_remote_1(SysHandle::SELF, handle, arg)
    }

    #[cfg(feature = "userspace")]
    pub fn put_remote(owner_process: SysHandle, handle: SysHandle) -> Result<(), ErrorCode> {
        Self::put_remote_1(owner_process, handle, 0)
    }

    #[cfg(feature = "userspace")]
    pub fn put_remote_1(
        owner_process: SysHandle,
        handle: SysHandle,
        arg: u64,
    ) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_PUT, 0, 0),
            owner_process.as_u64(),
            handle.as_u64(),
            arg,
            0,
            0,
            0,
        );
        if result.is_ok() {
            Ok(())
        } else {
            Err(result.error_code())
        }
    }

    // Returns OK if the handle can be waited on.
    #[cfg(feature = "userspace")]
    pub fn handle_status(handle: SysHandle) -> Result<(), ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_QUERY_HANDLE, 0, 0),
            handle.as_u64(),
            0,
            0,
            0,
            0,
            0,
        );

        if result.is_ok() {
            Ok(())
        } else {
            Err(result.error_code())
        }
    }

    // Checks if the shared object/handle has a peer.
    #[cfg(feature = "userspace")]
    pub fn is_connected(handle: SysHandle) -> Result<bool, ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_QUERY_HANDLE, Self::F_QUERY_PEER, 0),
            handle.as_u64(),
            0,
            0,
            0,
            0,
            0,
        );

        if result.is_ok() {
            Ok(true)
        } else {
            let err = result.error_code();
            if err == moto_rt::E_NOT_CONNECTED {
                Ok(false)
            } else {
                Err(err)
            }
        }
    }

    /// Returns the PID of the handle owner.
    #[cfg(feature = "userspace")]
    pub fn get_pid(handle: SysHandle) -> Result<u64, ErrorCode> {
        let result = do_syscall(
            pack_nr_ver(SYS_OBJ, Self::OP_QUERY_HANDLE, Self::F_QUERY_PID, 0),
            handle.as_u64(),
            0,
            0,
            0,
            0,
            0,
        );

        if result.is_ok() {
            Ok(result.data[0])
        } else {
            Err(result.error_code())
        }
    }
}
