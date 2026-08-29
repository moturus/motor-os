use std::borrow::Cow;
use std::future::Future;
use std::net::{TcpStream, ToSocketAddrs};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use russh::client;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::args::{ConnectionOptions, Destination, HostKeyPolicy};
use super::known_hosts;
use super::prompt;

#[derive(Clone)]
struct Deadline {
    sleep: Arc<Mutex<Option<Pin<Box<tokio::time::Sleep>>>>>,
}

impl Deadline {
    fn new(deadline: Option<Instant>) -> Self {
        let sleep = deadline.map(|deadline| {
            Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
                deadline,
            )))
        });
        Self {
            sleep: Arc::new(Mutex::new(sleep)),
        }
    }

    fn clear(&self) {
        self.sleep.lock().unwrap().take();
    }

    fn poll(&self, cx: &mut Context<'_>) -> std::io::Result<()> {
        let mut guard = self.sleep.lock().unwrap();
        if guard
            .as_mut()
            .is_some_and(|sleep| sleep.as_mut().poll(cx).is_ready())
        {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        Ok(())
    }
}

struct DeadlineStream {
    stream: tokio::net::TcpStream,
    deadline: Deadline,
}

impl AsyncRead for DeadlineStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.deadline.poll(cx)?;
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for DeadlineStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.deadline.poll(cx)?;
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.deadline.poll(cx)?;
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

pub struct Handler {
    deadline: Deadline,
    destination: Destination,
    port: u16,
    known_hosts: std::path::PathBuf,
    policy: HostKeyPolicy,
    batch_mode: bool,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        self.deadline.clear();
        let state = known_hosts::check(
            &self.known_hosts,
            &self.destination.host,
            self.port,
            server_public_key,
        )?;
        match state {
            known_hosts::KeyState::Matching => Ok(true),
            known_hosts::KeyState::Changed => Ok(false),
            known_hosts::KeyState::Unknown if self.policy == HostKeyPolicy::Yes => Ok(false),
            known_hosts::KeyState::Unknown if self.policy == HostKeyPolicy::AcceptNew => {
                Ok(known_hosts::record(
                    &self.known_hosts,
                    &known_hosts::host_token(&self.destination.host, self.port),
                    server_public_key,
                )?)
            }
            known_hosts::KeyState::Unknown if self.batch_mode => Ok(false),
            known_hosts::KeyState::Unknown => {
                let message = format!(
                    "The authenticity of host '{}' cannot be established.\n{} fingerprint is {}.\nContinue connecting (yes/no)? ",
                    self.destination.host,
                    server_public_key.algorithm(),
                    server_public_key.fingerprint(Default::default())
                );
                let accepted = tokio::task::spawn_blocking(move || prompt::line(&message))
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))??
                    .trim()
                    == "yes";
                if !accepted {
                    return Ok(false);
                }
                Ok(known_hosts::record(
                    &self.known_hosts,
                    &known_hosts::host_token(&self.destination.host, self.port),
                    server_public_key,
                )?)
            }
        }
    }
}

pub async fn connect(
    options: &ConnectionOptions,
    destination: &Destination,
) -> Result<client::Handle<Handler>, russh::Error> {
    let known_hosts = options.known_hosts.clone().ok_or_else(|| {
        russh::Error::InvalidConfig("UserKnownHostsFile is required on this platform".to_owned())
    })?;
    let mut preferred = russh::Preferred::default();
    preferred.key = Cow::Owned(known_hosts::prefer_algorithms(
        &known_hosts,
        &destination.host,
        options.port,
        &preferred.key,
    )?);
    let (stream, setup_deadline) = connect_tcp(options, destination)?;
    stream.set_nonblocking(true)?;
    let stream = tokio::net::TcpStream::from_std(stream)?;
    let deadline = Deadline::new(setup_deadline);
    let stream = DeadlineStream {
        stream,
        deadline: deadline.clone(),
    };
    let config = client::Config {
        preferred,
        keepalive_interval: options.server_alive_interval,
        keepalive_max: usize::try_from(options.server_alive_count_max)
            .map_err(|_| russh::Error::InvalidConfig("ServerAliveCountMax is too large".into()))?,
        ..Default::default()
    };
    let handler = Handler {
        deadline,
        destination: destination.clone(),
        port: options.port,
        known_hosts,
        policy: options.host_key_policy,
        batch_mode: options.batch_mode,
    };
    client::connect_stream(Arc::new(config), stream, handler).await
}

fn connect_tcp(
    options: &ConnectionOptions,
    destination: &Destination,
) -> std::io::Result<(TcpStream, Option<Instant>)> {
    let addresses: Vec<_> = (destination.host.as_str(), options.port)
        .to_socket_addrs()?
        .collect();
    attempt_addresses(addresses, options.connect_timeout, |address, timeout| {
        if let Some(timeout) = timeout {
            TcpStream::connect_timeout(&address, timeout)
        } else {
            TcpStream::connect(address)
        }
    })
}

fn attempt_addresses<T>(
    addresses: impl IntoIterator<Item = std::net::SocketAddr>,
    timeout: Option<std::time::Duration>,
    mut connect: impl FnMut(std::net::SocketAddr, Option<std::time::Duration>) -> std::io::Result<T>,
) -> std::io::Result<(T, Option<Instant>)> {
    let mut last_error = None;
    for address in addresses {
        let deadline = if let Some(timeout) = timeout {
            let deadline = Instant::now()
                .checked_add(timeout)
                .ok_or_else(|| std::io::Error::other("ConnectTimeout is too large"))?;
            Some(deadline)
        } else {
            None
        };
        match connect(address, timeout) {
            Ok(stream) => return Ok((stream, deadline)),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "host resolved no addresses",
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_timeout_uses_no_setup_deadline() {
        let address = "127.0.0.1:22".parse().unwrap();
        let (_, deadline) = attempt_addresses([address], None, |_, timeout| {
            assert!(timeout.is_none());
            Ok(())
        })
        .unwrap();
        assert!(deadline.is_none());
    }

    #[test]
    fn every_address_gets_a_fresh_timeout_and_success_keeps_its_deadline() {
        let addresses = [
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
        ];
        let timeout = std::time::Duration::from_secs(2);
        let mut attempts = 0;
        let before = Instant::now();
        let (_, deadline) = attempt_addresses(addresses, Some(timeout), |_, supplied| {
            attempts += 1;
            assert_eq!(supplied, Some(timeout));
            if attempts == 1 {
                Err(std::io::ErrorKind::TimedOut.into())
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(attempts, 2);
        assert!(deadline.unwrap() >= before + std::time::Duration::from_secs(1));
    }
}
