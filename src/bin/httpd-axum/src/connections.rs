use axum_server::accept::Accept;
use std::future::{ready, Ready};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
pub struct ConnectionLimit(Arc<Semaphore>);

impl ConnectionLimit {
    pub fn new(limit: u32) -> Self {
        Self(Arc::new(Semaphore::new(limit as usize)))
    }
}

impl<S> Accept<TcpStream, S> for ConnectionLimit {
    type Stream = Connection;
    type Service = S;
    type Future = Ready<io::Result<(Connection, S)>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        ready((|| {
            // Admission happens before TLS handshaking. No waiter queue retains
            // excess connections, and the permit follows the stream's lifetime.
            let permit = self
                .0
                .clone()
                .try_acquire_owned()
                .map_err(|_| io::Error::other("active connection limit reached"))?;
            stream.set_nodelay(true)?;
            Ok((
                Connection {
                    permit: Some(permit),
                    stream,
                },
                service,
            ))
        })())
    }
}

pub struct Connection {
    // Release admission before dropping the TCP stream and sending its FIN.
    permit: Option<OwnedSemaphorePermit>,
    stream: TcpStream,
}

impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.permit.take();
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }
}
