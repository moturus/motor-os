use core::sync::atomic::*;
use moto_ipc::sync::*;
use moto_sys::SysHandle;
use moto_sys_io::rt_fs::*;

struct Dispatcher {
    ipc_server: LocalServer,
}

static DISPATCHER_ADDRESS: AtomicUsize = AtomicUsize::new(0);

impl Dispatcher {
    fn start() -> Result<(), u16> {
        let ipc_server = LocalServer::new(FS_URL, ChannelSize::Small, 10, 10)?;
        let dispatcher = Box::leak(Box::new(Dispatcher { ipc_server }));

        let addr = dispatcher as *mut _ as usize;
        let prev = DISPATCHER_ADDRESS.swap(addr, Ordering::Relaxed);
        assert_eq!(prev, 0);

        std::thread::spawn(Self::run);
        Ok(())
    }

    fn get() -> &'static mut Dispatcher {
        unsafe {
            let addr = DISPATCHER_ADDRESS.load(Ordering::Relaxed);
            assert_ne!(addr, 0);
            (addr as *mut Dispatcher).as_mut().unwrap_unchecked()
        }
    }

    fn run() {
        let self_ = Self::get();
        loop {
            match self_.ipc_server.wait(SysHandle::NONE, &[]) {
                Ok(wakers) => {
                    for waker in &wakers {
                        self_.process_ipc(waker);
                    }
                }
                Err(wakers) => assert_eq!(wakers.len(), 0),
            }
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
        resp.url_size = super::DRIVER_URL.as_bytes().len() as u16;
        unsafe {
            core::intrinsics::copy_nonoverlapping(
                super::DRIVER_URL.as_bytes().as_ptr(),
                resp.url.as_mut_ptr(),
                super::DRIVER_URL.as_bytes().len(),
            );
        }

        let _ = conn.finish_rpc();
    }
}

pub fn start() -> Result<(), ErrorCode> {
    Dispatcher::start()?;
    super::driver::start()
}
