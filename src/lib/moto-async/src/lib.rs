#![feature(io_error_more)]
use std::io::Write;

use futures::{AsyncRead, AsyncWrite};

pub struct TcpListener {
    inner: moto_runtime::net::TcpListener,
}

impl TcpListener {
    pub async fn bind<A: std::net::ToSocketAddrs>(addrs: A) -> std::io::Result<TcpListener> {
        let addresses: Vec<std::net::SocketAddr> = addrs.to_socket_addrs().unwrap().collect();
        if addresses.len() != 1 {
            eprintln!("At the moment, only a single listening address is supported.");
            std::process::exit(1)
        }
        let addr = addresses[0];

        let inner = moto_runtime::net::TcpListener::bind(&addr).map_err(map_moturus_error)?;
        inner.set_nonblocking(true).unwrap();
        Ok(TcpListener { inner })
    }

    pub async fn accept(&self) -> std::io::Result<(TcpStream, std::net::SocketAddr)> {
        todo!()
    }
}

pub struct TcpStream {
    inner: std::sync::Mutex<std::net::TcpStream>,
}

impl TcpStream {
    pub fn new(stream: std::net::TcpStream) -> Self {
        stream.set_nonblocking(true).unwrap();
        Self {
            inner: std::sync::Mutex::new(stream),
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = self.inner.lock().unwrap().write(buf);
        match result {
            Ok(sz) => std::task::Poll::Ready(Ok(sz)),
            Err(err) => match err.kind() {
                std::io::ErrorKind::WouldBlock => std::task::Poll::Pending,
                _ => {
                    println!("poll_write: got err {:?}", err);
                    std::task::Poll::Ready(Err(err))
                }
            },
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let result = self.inner.lock().unwrap().flush();
        match result {
            Ok(_) => std::task::Poll::Ready(Ok(())),
            Err(err) => match err.kind() {
                std::io::ErrorKind::WouldBlock => std::task::Poll::Pending,
                _ => {
                    println!("poll_flush: got err {:?}", err);
                    std::task::Poll::Ready(Err(err))
                }
            },
        }
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::io::Read;

        let result = self.inner.lock().unwrap().read(buf);
        match result {
            Ok(sz) => std::task::Poll::Ready(Ok(sz)),
            Err(err) => match err.kind() {
                std::io::ErrorKind::WouldBlock => std::task::Poll::Pending,
                _ => {
                    println!("poll_read: got err {:?}", err);
                    std::task::Poll::Ready(Err(err))
                }
            },
        }
    }
}

// TODO: this is duplicated from std::src::sys::pal::moturus::mod.rs
pub fn map_moturus_error(err: moto_sys::ErrorCode) -> std::io::Error {
    use moto_sys::ErrorCode;
    use std::io::ErrorKind;

    let kind: ErrorKind = match err {
        ErrorCode::AlreadyInUse => ErrorKind::AlreadyExists,
        ErrorCode::InvalidFilename => ErrorKind::InvalidFilename,
        ErrorCode::NotFound => ErrorKind::NotFound,
        ErrorCode::TimedOut => ErrorKind::TimedOut,
        ErrorCode::NotImplemented => ErrorKind::Unsupported,
        ErrorCode::FileTooLarge => ErrorKind::FileTooLarge,
        ErrorCode::UnexpectedEof => ErrorKind::UnexpectedEof,
        err => {
            eprintln!("{}:{} unknown err {:?}", file!(), line!(), err);
            ErrorKind::Other
        }
    };

    std::io::Error::from(kind)
}
