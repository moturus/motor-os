pub const AF_INET: u8 = 0;
pub const AF_INET6: u8 = 1;
pub type sa_family_t = u8;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    #[allow(dead_code)]
    pub sin_family: sa_family_t,
    pub sin_port: u16,
    pub sin_addr: in_addr,
}

impl From<core::net::SocketAddrV4> for sockaddr_in {
    fn from(addr: core::net::SocketAddrV4) -> sockaddr_in {
        sockaddr_in {
            sin_family: AF_INET,
            sin_port: addr.port(),
            sin_addr: in_addr {
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            },
        }
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub s6_addr: [u8; 16],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in6 {
    #[allow(dead_code)]
    pub sin6_family: sa_family_t,
    pub sin6_port: u16,
    pub sin6_addr: in6_addr,
    pub sin6_flowinfo: u32,
    pub sin6_scope_id: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union sockaddr {
    pub v4: sockaddr_in,
    pub v6: sockaddr_in6,
}
