use smoltcp::socket::tcp::Socket;
use smoltcp::socket::tcp::SocketBuffer;
use std::sync::atomic::*;

struct StatusServer {
    incoming: spin::Mutex<Vec<u8>>,
}

static STATUS_SERVER: AtomicPtr<StatusServer> = AtomicPtr::new(core::ptr::null_mut());

impl StatusServer {
    const PORT: u16 = 5542; // Just a random number.

    fn inst() -> &'static Self {
        unsafe { STATUS_SERVER.load(Ordering::Relaxed).as_ref().unwrap() }
    }

    fn start() -> Result<(), ()> {
        let rx_buffer = SocketBuffer::new(vec![0; 64]);
        let tx_buffer = SocketBuffer::new(vec![0; 1024]);
        let socket = Socket::new(rx_buffer, tx_buffer);
        let handler = super::TcpRecvHandler {
            user_data: 0,
            can_recv_fn: Self::can_recv,
        };
        let _handle = super::netdev::add_tcp_socket(socket, Self::PORT, handler);

        let p_server = Box::into_raw(Box::new(StatusServer {
            incoming: spin::Mutex::new(vec![]),
        }));
        let prev = STATUS_SERVER.swap(p_server, Ordering::AcqRel);
        assert!(prev.is_null());

        Ok(())
    }

    fn can_recv(_: usize, socket: &mut smoltcp::socket::tcp::Socket) {
        let received = socket
            .recv(|buffer| {
                let recvd_len = buffer.len();
                let data = buffer.to_owned();
                (recvd_len, data)
            })
            .unwrap();

        if received.len() > 0 {
            Self::inst().on_new_bytes(received, socket);
        }
    }

    fn on_new_bytes(&self, mut bytes: Vec<u8>, socket: &mut smoltcp::socket::tcp::Socket) {
        let mut incoming = self.incoming.lock();

        incoming.append(&mut bytes);

        if incoming.as_slice() == b"get" {
            crate::moto_log!("Status Server: get!");
            socket.send_slice(b"pong\n").unwrap();
        } else {
            crate::moto_log!(
                "Status Server: unrecognized command \n\r{:?}",
                incoming.as_slice()
            );
        }
    }
}

pub(super) fn start() -> Result<(), ()> {
    StatusServer::start()
}
