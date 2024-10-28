use moto_rt::error::*;

pub unsafe extern "C" fn dns_lookup(
    host_bytes: *const u8,
    host_bytes_sz: usize,
    port: u16,
    result_addr: *mut usize,
    result_len: *mut usize,
) -> ErrorCode {
    use core::net::Ipv4Addr;
    use core::net::SocketAddrV4;
    use core::str::FromStr;
    use moto_rt::netc;

    let host: &str = core::str::from_raw_parts(host_bytes, host_bytes_sz);

    let addr = if host == "localhost" {
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port)
    } else if let Ok(addr_v4) = Ipv4Addr::from_str(host) {
        SocketAddrV4::new(addr_v4, port)
    } else {
        crate::moto_log!("dns_lookup: {}:{}: not implemented", host, port);
        return E_NOT_IMPLEMENTED;
    };

    let res_addr = crate::rt_alloc::alloc(core::mem::size_of::<netc::sockaddr>() as u64, 16);
    let result: &mut [netc::sockaddr] =
        core::slice::from_raw_parts_mut(res_addr as usize as *mut netc::sockaddr, 1);

    let addr = netc::sockaddr { v4: addr.into() };
    result[0] = addr;
    *result_addr = res_addr as usize;
    *result_len = 1;
    E_OK
}
