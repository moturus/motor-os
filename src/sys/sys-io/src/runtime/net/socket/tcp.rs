use std::io::ErrorKind;
use std::rc::Weak;
use std::{cell::RefCell, net::SocketAddr, rc::Rc, task::Poll};

use moto_sys::SysHandle;
use moto_sys_io::api_net;

use super::super::EphemeralTcpPort;
use super::super::NetRuntime;
use super::MotoSocket;
use super::SocketBase;
use super::SocketState;

pub struct TcpState {
    ephemeral_port: Option<Rc<EphemeralTcpPort>>,
}
