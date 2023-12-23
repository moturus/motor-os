use smoltcp::wire::IpEndpoint;
use std::net::{IpAddr, SocketAddr};

pub fn socket_addr_from_endpoint(endpoint: IpEndpoint) -> SocketAddr {
    let addr: IpAddr = endpoint.addr.into();
    SocketAddr::new(addr, endpoint.port)
}
