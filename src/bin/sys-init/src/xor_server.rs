fn thread_fn() {
    use moto_ipc::sync::*;
    use moto_sys::SysHandle;
    let mut xor_server = LocalServer::new("xor-service", ChannelSize::Small, 2, 2).unwrap();

    let mut swap_target = SysHandle::NONE;

    loop {
        let wait_result = xor_server.wait(swap_target, &[]);
        swap_target = SysHandle::NONE;
        let wakers = match wait_result {
            Ok(wakers) => wakers,
            Err(_) => {
                continue;
            }
        };

        for idx in 0..wakers.len() {
            let waker = wakers[idx];

            let conn = xor_server.get_connection(waker).unwrap();
            assert!(conn.connected());
            let data: &mut u64 =
                unsafe { (conn.data_mut().as_mut_ptr() as *mut u64).as_mut().unwrap() };
            *data ^= u64::MAX;

            if idx < wakers.len() - 1 {
                if conn.finish_rpc().is_err() {
                    log::debug!("xor-service: disconnected");
                }
            } else {
                swap_target = conn.handle();
            }
        }
    }
}

pub fn start() {
    std::thread::spawn(thread_fn);
}
