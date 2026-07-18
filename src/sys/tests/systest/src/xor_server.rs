use moto_ipc::sync::*;

pub struct XorRequest {
    pub _header: RequestHeader,
    pub data: u64,
}

pub struct XorResponse {
    pub header: ResponseHeader,
    pub data: u64,
}

fn thread_fn() {
    use moto_sys::SysHandle;
    let mut xor_server = LocalServer::new("xor-service", ChannelSize::Small, 2, 2).unwrap();

    // The reply wake of the last-served connection is deferred into the
    // next wait's swap_target (see finish_rpc_deferred): the kernel
    // performs the wake and hands this CPU to the client directly when
    // it is blocked on the reply.
    let mut client = SysHandle::NONE;
    loop {
        let wait_result = xor_server.wait(client, &[]);
        // The swap target has been consumed (woken or reported dead).
        client = SysHandle::NONE;
        let wakers = match wait_result {
            Ok(wakers) => wakers,
            Err(_) => {
                continue;
            }
        };

        for waker in &wakers {
            let conn = xor_server.get_connection(*waker).unwrap();
            assert!(conn.connected());
            if !conn.have_req() {
                continue;
            }
            let req = conn.req::<XorRequest>();
            let mut data = req.data;
            data ^= u64::MAX;

            let resp = conn.resp::<XorResponse>();
            resp.data = data;
            resp.header.result = 0;

            #[cfg(debug_assertions)]
            std::thread::sleep(std::time::Duration::from_micros(
                std::random::random::<u64>(..) % 100,
            ));

            if conn.finish_rpc_deferred().is_ok() {
                // Only one reply can ride the next wait's swap slot; wake
                // the previously deferred one eagerly.
                if client != SysHandle::NONE {
                    let _ = moto_sys::SysCpu::wake(client);
                }
                client = *waker;
            }
        }
    }
}

pub fn start() {
    std::thread::spawn(thread_fn);
}
