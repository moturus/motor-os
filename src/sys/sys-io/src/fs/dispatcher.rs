//! FS dispatcher: a singleton (per VM) at FS_URL that clients ask for
//! driver URLs. Then they connect to the provided driver URL.
//! At the moment there is a single FS driver, so this indirection
//! dance is probably overengineering, but the idea is that in the
//! future there could be multiple instances of FS drivers running
//! (perhaps per mount point).
use moto_ipc::sync::*;
use moto_sys::SysHandle;
use moto_sys_io::api_fs::*;
use std::thread::{self, JoinHandle};

struct Dispatcher {
    ipc_server: LocalServer,
}

impl Dispatcher {
    /// access the static dispatcher to kick-off its processing loop
    /// and return whether initialization went fine
    fn start() -> Result<JoinHandle<Result<(), ErrorCode>>, ErrorCode> {
        Ok(thread::spawn(|| {
            let ipc_server = LocalServer::new(FS_URL, ChannelSize::Small, 10, 10)?;
            let mut dispatcher = Box::new(Dispatcher { ipc_server });
            dispatcher.run()
        }))
    }

    fn run(&mut self) -> Result<(), ErrorCode> {
        loop {
            if let Ok(wakers) = self.ipc_server.wait(SysHandle::NONE, &[]) {
                for waker in &wakers {
                    self.process_ipc(waker);
                }
            } // else: somebody disconnected.
        }
    }

    fn process_ipc(&mut self, waker: &SysHandle) {
        let conn = if let Some(conn) = self.ipc_server.get_connection(*waker) {
            conn
        } else {
            // A spurious wakeup by a dropped connection.
            return;
        };
        assert!(conn.connected());
        if !conn.have_req() {
            // TODO: this seems to be happening relatively often. Figure out why.
            return;
        }

        let req = conn.req::<GetServerUrlRequest>();
        if req.header.cmd != 1 || req.header.ver != 0 || req.header.flags != 0 {
            conn.disconnect();
            return;
        }

        let resp = conn.resp::<GetServerUrlResponse>();
        resp.header.result = 0;
        resp.header.ver = 0;
        resp.url_size = super::DRIVER_URL.len() as u16;
        unsafe {
            core::intrinsics::copy_nonoverlapping(
                super::DRIVER_URL.as_bytes().as_ptr(),
                resp.url.as_mut_ptr(),
                super::DRIVER_URL.len(),
            );
        }

        let _ = conn.finish_rpc();
    }
}

/// spawn dispatcher and the driver
/// # Return
/// (a) initialization error code or a pair of dispatcher and driver join handlers respectively
pub fn start() -> DispatcherInitResult {
    Ok((Dispatcher::start()?, super::driver::Driver::start()?))
}

type DispatcherInitResult = Result<
    (
        JoinHandle<Result<(), ErrorCode>>,
        JoinHandle<Result<(), ErrorCode>>,
    ),
    ErrorCode,
>;
