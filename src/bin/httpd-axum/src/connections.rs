use axum_server::accept::Accept;
use std::future::{ready, Future, Ready};
use std::io;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::Service;

#[derive(Clone)]
pub struct ConnectionLimit {
    permits: Arc<Semaphore>,
    rejections: Arc<Mutex<crate::rejections::Rejections>>,
    listener: &'static str,
    limit: u32,
}

impl ConnectionLimit {
    pub fn new(limit: u32, listener: &'static str) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit as usize)),
            rejections: Arc::default(),
            listener,
            limit,
        }
    }
}

impl<S> Accept<TcpStream, S> for ConnectionLimit {
    type Stream = Admitted;
    type Service = S;
    type Future = Ready<io::Result<(Admitted, S)>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        ready((|| {
            // Admission happens before TLS handshaking. No waiter queue retains
            // excess connections, and the permit follows the stream's lifetime.
            let permit = self.permits.clone().try_acquire_owned().map_err(|_| {
                let report = self.rejections.lock().unwrap().record(Instant::now());
                if let Some((refused, total_refused)) = report {
                    tracing::warn!(
                        listener = self.listener,
                        limit = self.limit,
                        refused,
                        total_refused,
                        "active connection limit reached"
                    );
                }
                io::Error::other("active connection limit reached")
            })?;
            stream.set_nodelay(true)?;
            Ok((
                Admitted {
                    permit: Some(permit),
                    stream,
                },
                service,
            ))
        })())
    }
}

pub struct Admitted {
    // Release admission before dropping the TCP stream and sending its FIN.
    permit: Option<OwnedSemaphorePermit>,
    stream: TcpStream,
}

impl AsyncRead for Admitted {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Admitted {
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
    type Stream = Deadline<A::Stream>;
    type Service = FirstRequest<A::Service>;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let future = self.inner.accept(stream, service);
        let duration = self.duration;
        Box::pin(async move {
            let (stream, inner) = future.await?;
            // Start after any TLS handshake. Only a parsed request head can
            // disarm this timer; protocol detection and control frames cannot.
            let received = Arc::new(AtomicBool::new(false));
            Ok((
                Deadline {
                    stream,
                    timer: Box::pin(tokio::time::sleep(duration)),
                    received: received.clone(),
                },
                FirstRequest { inner, received },
            ))
        })
    }
}

#[derive(Clone)]
pub struct FirstRequest<S> {
    inner: S,
    received: Arc<AtomicBool>,
}

impl<S: Service<R>, R> Service<R> for FirstRequest<S> {
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: R) -> Self::Future {
        self.received.store(true, Ordering::Relaxed);
        self.inner.call(request)
    }
}

pub struct Deadline<T> {
    stream: T,
    timer: Pin<Box<tokio::time::Sleep>>,
    received: Arc<AtomicBool>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Deadline<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.received.load(Ordering::Relaxed) && self.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "first HTTP request head timed out",
            )));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Deadline<T> {
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
