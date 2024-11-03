pub const AF_INET: u8 = 0;
pub const AF_INET6: u8 = 1;
pub type sa_family_t = u8;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: u32,
}

impl Into<core::net::Ipv4Addr> for in_addr {
    fn into(self: in_addr) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::from(self.s_addr.to_ne_bytes())
    }
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

impl Into<core::net::SocketAddrV4> for sockaddr_in {
    fn into(self: sockaddr_in) -> core::net::SocketAddrV4 {
        assert_eq!(self.sin_family, AF_INET);
        core::net::SocketAddrV4::new(self.sin_addr.into(), self.sin_port)
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub s6_addr: [u8; 16],
}

impl Into<core::net::Ipv6Addr> for in6_addr {
    fn into(self: in6_addr) -> core::net::Ipv6Addr {
        core::net::Ipv6Addr::from(self.s6_addr)
    }
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

impl From<core::net::SocketAddrV6> for sockaddr_in6 {
    fn from(_addr: core::net::SocketAddrV6) -> sockaddr_in6 {
        todo!()
    }
}

impl Into<core::net::SocketAddrV6> for sockaddr_in6 {
    fn into(self: sockaddr_in6) -> core::net::SocketAddrV6 {
        assert_eq!(self.sin6_family, AF_INET6);
        core::net::SocketAddrV6::new(
            self.sin6_addr.into(),
            self.sin6_port,
            self.sin6_flowinfo,
            self.sin6_scope_id,
        )
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union sockaddr {
    pub v4: sockaddr_in,
    pub v6: sockaddr_in6,
}

impl From<core::net::SocketAddr> for sockaddr {
    fn from(addr: core::net::SocketAddr) -> sockaddr {
        match addr {
            core::net::SocketAddr::V4(addr) => sockaddr {
                v4: sockaddr_in::from(addr),
            },
            core::net::SocketAddr::V6(addr) => sockaddr {
                v6: sockaddr_in6::from(addr),
            },
        }
    }
}

impl Into<core::net::SocketAddr> for sockaddr {
    fn into(self: sockaddr) -> core::net::SocketAddr {
        unsafe {
            match self.v4.sin_family {
                AF_INET => core::net::SocketAddr::V4(self.v4.into()),
                AF_INET6 => core::net::SocketAddr::V6(self.v6.into()),
                _ => panic!(),
            }
        }
    }
}
