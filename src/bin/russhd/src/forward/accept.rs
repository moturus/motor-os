//! Accept errors and the pause belonging to one listening socket.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::time::Sleep;

pub const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ErrorAction {
    Continue,
    Pause,
    Retire,
}

pub(crate) fn classify(error: &io::Error) -> ErrorAction {
    // Motor's std/sys/io/error/motor.rs maps E_CONNECTION_RESET,
    // E_OUT_OF_MEMORY and E_NOT_CONNECTED to their corresponding kinds.
    // SDK TcpListener::on_accept_response queues individual errors, whereas
    // on_channel_failed makes NotConnected sticky: that socket must retire.
    match error.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::Interrupted => return ErrorAction::Continue,
        io::ErrorKind::OutOfMemory => return ErrorAction::Pause,
        _ => {}
    }
    #[cfg(unix)]
    if matches!(
        error.raw_os_error(),
        Some(libc::ENOBUFS | libc::EMFILE | libc::ENFILE)
    ) {
        return ErrorAction::Pause;
    }
    // Linux also returns pending errors from the incoming connection:
    // https://man7.org/linux/man-pages/man2/accept.2.html
    #[cfg(target_os = "linux")]
    if let Some(
        libc::ENETDOWN
        | libc::EPROTO
        | libc::ENOPROTOOPT
        | libc::EHOSTDOWN
        | libc::ENONET
        | libc::EHOSTUNREACH
        | libc::EOPNOTSUPP
        | libc::ENETUNREACH,
    ) = error.raw_os_error()
    {
        return ErrorAction::Continue;
    }
    ErrorAction::Retire
}

pub(crate) struct AcceptSocket {
    listener: TcpListener,
    pause: Option<Pin<Box<Sleep>>>,
    #[cfg(all(test, unix))]
    injected: Option<tokio::sync::mpsc::UnboundedReceiver<io::Error>>,
}

impl AcceptSocket {
    pub fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            pause: None,
            #[cfg(all(test, unix))]
            injected: None,
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn pause(&mut self) {
        self.pause = Some(Box::pin(tokio::time::sleep(ACCEPT_PAUSE)));
    }

    pub fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        // The deadline survives cancellation of the enclosing accept future.
        if let Some(pause) = &mut self.pause {
            std::task::ready!(pause.as_mut().poll(cx));
            self.pause = None;
        }
        #[cfg(all(test, unix))]
        if let Some(injected) = &mut self.injected {
            match injected.poll_recv(cx) {
                Poll::Ready(Some(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(None) => self.injected = None,
                Poll::Pending => {}
            }
        }
        self.listener.poll_accept(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_errors_distinguish_connections_exhaustion_and_retired_sockets() {
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::Interrupted,
        ] {
            assert_eq!(classify(&kind.into()), ErrorAction::Continue);
        }
        assert_eq!(
            classify(&io::ErrorKind::OutOfMemory.into()),
            ErrorAction::Pause
        );
        for kind in [
            io::ErrorKind::NotConnected,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Other,
            io::ErrorKind::WouldBlock,
        ] {
            assert_eq!(classify(&kind.into()), ErrorAction::Retire);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_accept_classification_uses_the_host_errno_namespace() {
        for code in [
            libc::ECONNABORTED,
            libc::ECONNRESET,
            libc::EINTR,
            libc::ENETDOWN,
            libc::EPROTO,
            libc::ENOPROTOOPT,
            libc::EHOSTDOWN,
            libc::ENONET,
            libc::EHOSTUNREACH,
            libc::EOPNOTSUPP,
            libc::ENETUNREACH,
        ] {
            assert_eq!(
                classify(&io::Error::from_raw_os_error(code)),
                ErrorAction::Continue,
                "errno {code}"
            );
        }
        for code in [
            libc::EBADF,
            libc::EINVAL,
            libc::ENOTSOCK,
            libc::EPERM,
            libc::ENOTCONN,
        ] {
            assert_eq!(
                classify(&io::Error::from_raw_os_error(code)),
                ErrorAction::Retire,
                "errno {code}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_memory_buffer_and_descriptor_exhaustion_pause_the_socket() {
        for code in [libc::ENOMEM, libc::ENOBUFS, libc::EMFILE, libc::ENFILE] {
            assert_eq!(
                classify(&io::Error::from_raw_os_error(code)),
                ErrorAction::Pause,
                "errno {code}"
            );
        }
    }
}
