/*! Network interface logic.

The `iface` module deals with the *network interfaces*. It filters incoming frames,
provides lookup and caching of hardware addresses, and handles management packets.
*/

mod fragmentation;
mod interface;
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
mod neighbor;
mod route;
#[cfg(feature = "proto-rpl")]
mod rpl;
#[cfg(feature = "proto-ipv6-slaac")]
mod slaac;
mod socket_meta;
mod socket_set;

mod packet;

#[cfg(feature = "multicast")]
pub use self::interface::multicast::MulticastError;
pub use self::interface::{
    Config, Interface, InterfaceInner as Context, IpPacketStats, PollIngressSingleResult,
    PollResult,
};
#[cfg(feature = "socket-tcp")]
pub use self::interface::{MAX_COOKIE_RESTORES, MAX_SYN_COOKIE_LISTENERS, TcpSynCookieConfig};

pub use self::route::{Route, Routes};
#[cfg(feature = "proto-ipv6-slaac")]
pub use self::slaac::Slaac;
pub use self::socket_set::{SocketHandle, SocketSet};
