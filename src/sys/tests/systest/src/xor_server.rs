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

    let mut client = SysHandle::NONE;
    loop {
        let wait_result = xor_server.wait(client, &[]);
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
            let _ = conn.finish_rpc();
            client = *waker;
        }
    }
}

pub fn start() {
    std::thread::spawn(thread_fn);
}
