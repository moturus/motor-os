use axum_server::accept::Accept;
use std::future::{ready, Future, Ready};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
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
                    preface: None,
                    stream,
                },
                service,
            ))
        })())
    }
}

pub struct Connection<T = TcpStream> {
    // Release admission before dropping the TCP stream and sending its FIN.
    permit: Option<OwnedSemaphorePermit>,
    stream: T,
    preface: Option<Preface>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Connection<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(preface) = &mut self.preface {
            if preface.timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "HTTP protocol detection timed out",
                )));
            }
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        if let Some(preface) = &mut self.preface {
            if preface.detected(&buf.filled()[before..]) {
                self.preface = None;
            }
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Connection<T> {
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

struct Preface {
    timer: Pin<Box<tokio::time::Sleep>>,
    matched: usize,
}

impl Preface {
    fn detected(&mut self, bytes: &[u8]) -> bool {
        const HTTP2: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        for byte in bytes {
            if *byte != HTTP2[self.matched] {
                return true;
            }
            self.matched += 1;
            if self.matched == HTTP2.len() {
                return true;
            }
        }
        false
    }
}

#[derive(Clone)]
pub struct HeaderDeadline<A> {
    inner: A,
    duration: Duration,
}

impl<A> HeaderDeadline<A> {
    pub fn new(inner: A, duration: Duration) -> Self {
        Self { inner, duration }
    }
}

impl<A, S> Accept<TcpStream, S> for HeaderDeadline<A>
where
    A: Accept<TcpStream, S>,
    A::Future: Send + 'static,
    A::Stream: Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = Connection<A::Stream>;
    type Service = A::Service;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let future = self.inner.accept(stream, service);
        let duration = self.duration;
        Box::pin(async move {
            let (stream, service) = future.await?;
            // Hyper's header timer starts after protocol detection. Cover idle
            // clients and partial HTTP/2 prefaces here, after any TLS handshake.
            Ok((
                Connection {
                    permit: None,
                    stream,
                    preface: Some(Preface {
                        timer: Box::pin(tokio::time::sleep(duration)),
                        matched: 0,
                    }),
                },
                service,
            ))
        })
    }
}
