//! Implementation of SysRay::dbg_* set of syscalls.

use core::sync::atomic::AtomicU64;

use alloc::sync::Arc;
use moto_sys::{syscalls::SyscallResult, ErrorCode, SysHandle, SysRay};

use crate::uspace::{
    syscall::{ResultBuilder, SyscallArgs},
    Process, SysObject,
};

/// Debuggee::debug_session will point at DebugSession; Debugger will have a wait object
/// pointing at SysObject with owner pointing at DebugSession.
pub struct DebugSession {
    id: u64, // Used for logging.
    debugger: Arc<Process>,
    debuggee: Arc<Process>,
}

impl core::fmt::Debug for DebugSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "DebugSession: {}:{}->{}",
            self.id,
            self.debugger.pid().as_u64(),
            self.debuggee.pid().as_u64()
        ))
    }
}

impl DebugSession {
    pub fn new(debugger: Arc<Process>, debuggee: Arc<Process>) -> Result<SysHandle, ErrorCode> {
        let session = {
            let mut ss = debuggee.debug_session.lock(line!());
            if ss.is_some() {
                return Err(ErrorCode::AlreadyInUse);
            }

            static NEXT_DEBUG_SESSION_ID: AtomicU64 = AtomicU64::new(1);
            let session = Arc::new(Self {
                id: NEXT_DEBUG_SESSION_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
                debugger: debugger.clone(),
                debuggee: debuggee.clone(),
            });
            *ss = Some(session.clone());
            session
        };
        log::info!("New debug session {:?}", session);

        let sys_object = SysObject::new_owned(
            Arc::new(alloc::format!(
                "debug session {} -> {}",
                debugger.pid().as_u64(),
                debuggee.pid().as_u64()
            )),
            session,
            Arc::downgrade(&debugger),
        );

        Ok(debugger.add_object(sys_object))
    }
}

fn sys_dbg_attach(thread: &crate::uspace::process::Thread, args: &SyscallArgs) -> SyscallResult {
    if args.version < 1 {
        return ResultBuilder::version_too_low();
    }
    if args.version > 1 {
        return ResultBuilder::version_too_high();
    }
    if args.args[1..] != [0; 5] {
        return ResultBuilder::invalid_argument();
    }

    let pid = args.args[0];
    if pid < 2 {
        // Cannot debug system processes.
        return ResultBuilder::result(ErrorCode::NotAllowed);
    }

    // Cannot debug self, or ancestors, e.g. because of stdio dependencies.
    let mut stats = crate::xray::stats::stats_from_pid(thread.owner().pid().as_u64());
    while let Some(parent) = stats {
        if parent.pid().as_u64() == pid {
            return ResultBuilder::result(ErrorCode::NotAllowed);
        }
        stats = parent.parent();
    }

    let debuggee = if let Some(p) = Process::from_pid(pid) {
        p
    } else {
        return ResultBuilder::result(moto_sys::ErrorCode::NotFound);
    };

    match DebugSession::new(thread.owner(), debuggee) {
        Ok(handle) => ResultBuilder::ok_1(handle.into()),
        Err(err) => ResultBuilder::result(err),
    }
}

fn get_session(
    debugger: &super::process::Process,
    debug_handle: SysHandle,
) -> Result<Arc<DebugSession>, ErrorCode> {
    let session = if let Some(obj) =
        super::sysobject::object_from_handle::<DebugSession>(&debugger, debug_handle)
    {
        obj
    } else {
        return Err(ErrorCode::BadHandle);
    };

    assert_eq!(debugger.pid(), session.debugger.pid());

    Ok(session)
}

fn sys_dbg_pause_process(
    debugger: Arc<super::process::Process>,
    args: &SyscallArgs,
) -> SyscallResult {
    if args.version < 1 {
        return ResultBuilder::version_too_low();
    }
    if args.version > 1 {
        return ResultBuilder::version_too_high();
    }
    if args.args[1..] != [0; 5] {
        return ResultBuilder::invalid_argument();
    }

    let dbg_handle = SysHandle::from_u64(args.args[0]);
    let session = match get_session(&debugger, dbg_handle) {
        Ok(s) => s,
        Err(err) => return ResultBuilder::result(err),
    };

    match session.debuggee.dbg_pause() {
        Ok(()) => ResultBuilder::ok(),
        Err(err) => ResultBuilder::result(err),
    }
}

fn sys_dbg_list_threads(
    debugger: Arc<super::process::Process>,
    args: &SyscallArgs,
) -> SyscallResult {
    if args.version < 1 {
        return ResultBuilder::version_too_low();
    }
    if args.version > 1 {
        return ResultBuilder::version_too_high();
    }
    if args.args[4..] != [0; 2] {
        return ResultBuilder::invalid_argument();
    }

    let dbg_handle = SysHandle::from_u64(args.args[0]);
    let session = match get_session(&debugger, dbg_handle) {
        Ok(s) => s,
        Err(err) => return ResultBuilder::result(err),
    };

    let start_tid = super::process::ThreadId::from_u64(args.args[1]);
    let buf_start = args.args[2];
    let buf_len = args.args[3];

    let mut tids = [0_u64; 32];
    let sz = tids.len().min(buf_len as usize);
    let copied_tids = session.debuggee.list_tids(&start_tid, &mut tids[0..sz]);

    for idx in 0..copied_tids {
        let tid = tids[idx];
        unsafe {
            let tid_bytes = core::slice::from_raw_parts(
                &tid as *const _ as usize as *const u8,
                core::mem::size_of::<u64>(),
            );
            if let Err(err) = debugger
                .address_space()
                .copy_to_user(tid_bytes, buf_start + (8 * idx as u64))
            {
                // TODO: maybe just kill the debugger?
                return ResultBuilder::result(err);
            }
        }
    }

    ResultBuilder::ok_1(copied_tids as u64)
}

fn sys_dbg_get_thread_data(
    debugger: Arc<super::process::Process>,
    args: &SyscallArgs,
) -> SyscallResult {
    use moto_sys::stats::ThreadDataV1;

    if args.version < 1 {
        return ResultBuilder::version_too_low();
    }
    if args.version > 1 {
        return ResultBuilder::version_too_high();
    }
    if args.args[3..] != [0; 3] {
        return ResultBuilder::invalid_argument();
    }

    let dbg_handle = SysHandle::from_u64(args.args[0]);
    let session = match get_session(&debugger, dbg_handle) {
        Ok(s) => s,
        Err(err) => return ResultBuilder::result(err),
    };

    let tid = args.args[1];
    if let Some(thread_data) = session.debuggee.get_thread_data(tid) {
        unsafe {
            let bytes = core::slice::from_raw_parts(
                &thread_data as *const _ as usize as *const u8,
                core::mem::size_of::<ThreadDataV1>(),
            );
            if let Err(err) = debugger.address_space().copy_to_user(bytes, args.args[2]) {
                // TODO: maybe just kill the debugger?
                return ResultBuilder::result(err);
            }
        }
        ResultBuilder::ok()
    } else {
        ResultBuilder::result(ErrorCode::NotFound)
    }
}

fn sys_dbg_resume_process(
    debugger: Arc<super::process::Process>,
    args: &SyscallArgs,
) -> SyscallResult {
    if args.version < 1 {
        return ResultBuilder::version_too_low();
    }
    if args.version > 1 {
        return ResultBuilder::version_too_high();
    }
    if args.args[1..] != [0; 5] {
        return ResultBuilder::invalid_argument();
    }

    let dbg_handle = SysHandle::from_u64(args.args[0]);
    let session = match get_session(&debugger, dbg_handle) {
        Ok(s) => s,
        Err(err) => return ResultBuilder::result(err),
    };

    match session.debuggee.dbg_resume() {
        Ok(()) => ResultBuilder::ok(),
        Err(err) => ResultBuilder::result(err),
    }
}

fn sys_dbg_resume_thread(
    debugger: Arc<super::process::Process>,
    args: &SyscallArgs,
) -> SyscallResult {
    if args.version < 1 {
        return ResultBuilder::version_too_low();
    }
    if args.version > 1 {
        return ResultBuilder::version_too_high();
    }
    if args.args[2..] != [0; 4] {
        return ResultBuilder::invalid_argument();
    }

    let dbg_handle = SysHandle::from_u64(args.args[0]);
    let session = match get_session(&debugger, dbg_handle) {
        Ok(s) => s,
        Err(err) => return ResultBuilder::result(err),
    };

    let tid = args.args[1];

    match session
        .debuggee
        .dbg_resume_thread(super::process::ThreadId::from_u64(tid))
    {
        Ok(()) => ResultBuilder::ok(),
        Err(err) => ResultBuilder::result(err),
    }
}

fn sys_dbg_detach(debugger: Arc<super::process::Process>, args: &SyscallArgs) -> SyscallResult {
    if args.version < 1 {
        return ResultBuilder::version_too_low();
    }
    if args.version > 1 {
        return ResultBuilder::version_too_high();
    }
    if args.args[1..] != [0; 5] {
        return ResultBuilder::invalid_argument();
    }

    let dbg_handle = SysHandle::from_u64(args.args[0]);
    let session = match get_session(&debugger, dbg_handle) {
        Ok(s) => s,
        Err(err) => return ResultBuilder::result(err),
    };

    *session.debuggee.debug_session.lock(line!()) = None;
    session.debugger.put_object(&dbg_handle).unwrap();

    ResultBuilder::ok()
}

fn sys_dbg_get_mem(debugger: Arc<super::process::Process>, args: &SyscallArgs) -> SyscallResult {
    if args.version < 1 {
        return ResultBuilder::version_too_low();
    }
    if args.version > 1 {
        return ResultBuilder::version_too_high();
    }
    if args.args[4..] != [0; 2] {
        return ResultBuilder::invalid_argument();
    }

    let dbg_handle = SysHandle::from_u64(args.args[0]);
    let session = match get_session(&debugger, dbg_handle) {
        Ok(s) => s,
        Err(err) => return ResultBuilder::result(err),
    };

    let start_addr = args.args[1];
    let buf_addr = args.args[2];
    let buf_len = args.args[3];

    // Read bytes from the debuggee memory.
    let bytes = match session
        .debuggee
        .address_space()
        .read_from_user(start_addr, buf_len)
    {
        Ok(v) => v,
        Err(err) => return ResultBuilder::result(err),
    };

    // Write bytes to the debugger memory.
    match debugger.address_space().copy_to_user(&bytes, buf_addr) {
        Ok(_) => ResultBuilder::ok_1(bytes.len() as u64),
        Err(err) => ResultBuilder::result(err),
    }
}

pub fn sys_ray_dbg_impl(
    thread: &crate::uspace::process::Thread,
    args: &SyscallArgs,
) -> SyscallResult {
    match args.flags {
        SysRay::F_DBG_ATTACH => sys_dbg_attach(thread, args),
        SysRay::F_DBG_GET_MEM => sys_dbg_get_mem(thread.owner(), args),
        SysRay::F_DBG_PAUSE_PROCESS => sys_dbg_pause_process(thread.owner(), args),
        SysRay::F_DBG_LIST_THREADS => sys_dbg_list_threads(thread.owner(), args),
        SysRay::F_DBG_GET_THREAD_DATA => sys_dbg_get_thread_data(thread.owner(), args),
        SysRay::F_DBG_RESUME_PROCESS => sys_dbg_resume_process(thread.owner(), args),
        SysRay::F_DBG_RESUME_THREAD => sys_dbg_resume_thread(thread.owner(), args),
        SysRay::F_DBG_DETACH => sys_dbg_detach(thread.owner(), args),
        _ => ResultBuilder::invalid_argument(),
    }
}
