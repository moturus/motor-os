pub const AF_INET: u8 = 0;
pub const AF_INET6: u8 = 1;
pub type sa_family_t = u8;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: u32,
}

impl From<in_addr> for core::net::Ipv4Addr {
    fn from(addr: in_addr) -> Self {
        core::net::Ipv4Addr::from(addr.s_addr.to_ne_bytes())
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
            sin_port: addr.port().to_be(),
            sin_addr: in_addr {
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            },
        }
    }
}

impl From<sockaddr_in> for core::net::SocketAddrV4 {
    fn from(addr: sockaddr_in) -> core::net::SocketAddrV4 {
        assert_eq!(addr.sin_family, AF_INET);
        core::net::SocketAddrV4::new(addr.sin_addr.into(), u16::from_be(addr.sin_port))
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub s6_addr: [u8; 16],
}

impl From<in6_addr> for core::net::Ipv6Addr {
    fn from(addr: in6_addr) -> core::net::Ipv6Addr {
        core::net::Ipv6Addr::from(addr.s6_addr)
    }
}

impl From<core::net::Ipv6Addr> for in6_addr {
    fn from(addr: core::net::Ipv6Addr) -> in6_addr {
        in6_addr {
            s6_addr: addr.octets(),
        }
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
    fn from(addr: core::net::SocketAddrV6) -> sockaddr_in6 {
        sockaddr_in6 {
            sin6_family: AF_INET6 as sa_family_t,
            sin6_port: addr.port().to_be(),
            sin6_addr: (*addr.ip()).into(),
            sin6_flowinfo: addr.flowinfo(),
            sin6_scope_id: addr.scope_id(),
        }
    }
}

impl From<sockaddr_in6> for core::net::SocketAddrV6 {
    fn from(addr: sockaddr_in6) -> core::net::SocketAddrV6 {
        assert_eq!(addr.sin6_family, AF_INET6);
        core::net::SocketAddrV6::new(
            addr.sin6_addr.into(),
            u16::from_be(addr.sin6_port),
            addr.sin6_flowinfo,
            addr.sin6_scope_id,
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

impl From<sockaddr> for core::net::SocketAddr {
    fn from(addr: sockaddr) -> core::net::SocketAddr {
        unsafe {
            match addr.v4.sin_family {
                AF_INET => core::net::SocketAddr::V4(addr.v4.into()),
                AF_INET6 => core::net::SocketAddr::V6(addr.v6.into()),
                _ => panic!(),
            }
        }
    }
}
