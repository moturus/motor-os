//! Authorize incoming remote forwards against successful, locally defined requests.

use std::sync::{Arc, Mutex};

use russh::{Channel, ChannelOpenFailure, ReceiveCredit, client};
use tokio::sync::watch;

use super::forward_args::{RemoteForward, TargetAddress};
use crate::forward::{self, Reservation, Tasks};

struct Accepted {
    address: String,
    port: u16,
    target: TargetAddress,
}

struct State {
    accepting: bool,
    complete: bool,
    accepted: Vec<Accepted>,
}

pub struct Forwards {
    state: Mutex<State>,
    ready: watch::Sender<()>,
    tasks: Arc<Tasks>,
    window: usize,
}

impl Forwards {
    pub fn new(tasks: Arc<Tasks>, window: usize) -> Self {
        Self {
            state: Mutex::new(State {
                accepting: true,
                complete: false,
                accepted: Vec::new(),
            }),
            ready: watch::channel(()).0,
            tasks,
            window,
        }
    }

    /// Only the setup owner records replies; the peer never supplies a target.
    pub fn record(&self, request: &RemoteForward, reply: u32) -> Result<u16, russh::Error> {
        let invalid = |message: &str| russh::Error::InvalidConfig(message.to_owned());
        let port = if request.listen.port == 0 {
            u16::try_from(reply)
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| invalid("invalid allocated remote forwarding port"))?
        } else {
            request.listen.port
        };
        let address = request.bind_address();
        let mut state = self.state.lock().unwrap();
        if !state.accepting || state.complete {
            return Err(invalid("remote forwarding setup has ended"));
        }
        if state
            .accepted
            .iter()
            .any(|entry| entry.address == address && entry.port == port)
        {
            return Err(invalid("duplicate accepted remote forwarding address"));
        }
        state.accepted.push(Accepted {
            address: address.to_owned(),
            port,
            target: request.target.clone(),
        });
        Ok(port)
    }

    pub fn finish_setup(&self) {
        self.state.lock().unwrap().complete = true;
        self.ready.send_replace(());
    }

    pub fn stop_accepting(&self) {
        self.state.lock().unwrap().accepting = false;
    }

    pub fn cancel(&self) {
        self.stop_accepting();
        self.tasks.cancel();
    }

    pub fn reserve(&self, pressure: bool) -> Result<Reservation, ChannelOpenFailure> {
        let state = self.state.lock().unwrap();
        if !state.accepting {
            return Err(ChannelOpenFailure::AdministrativelyProhibited);
        }
        self.tasks
            .reserve(pressure)
            .ok_or(ChannelOpenFailure::ResourceShortage)
    }

    pub async fn target(&self, address: &str, port: u32) -> Option<TargetAddress> {
        let port = u16::try_from(port).ok()?;
        let mut ready = self.ready.subscribe();
        loop {
            {
                let state = self.state.lock().unwrap();
                if state.complete {
                    return state
                        .accepted
                        .iter()
                        .find(|entry| entry.address == address && entry.port == port)
                        .map(|entry| entry.target.clone());
                }
            }
            ready.changed().await.ok()?;
        }
    }

    pub async fn incoming(
        self: &Arc<Self>,
        channel: Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        credit: ReceiveCredit,
        address: &str,
        port: u32,
    ) {
        if address.len() > 255 || !(1..=65535).contains(&port) {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return;
        }
        let job = match self.reserve(forward::memory_pressure()) {
            Ok(job) => job,
            Err(reason) => {
                reply.reject(reason).await;
                return;
            }
        };
        let context = self.clone();
        let address = address.to_owned();
        let window = self.window;
        job.spawn(async move {
            let target = context.target(&address, port).await;
            drop(context);
            let Some(target) = target else {
                reply
                    .reject(ChannelOpenFailure::AdministrativelyProhibited)
                    .await;
                return Ok(());
            };
            let socket = match forward::connect_target(&target.host, target.port).await {
                Ok(socket) => socket,
                Err(error) => {
                    eprintln!(
                        "ssh: remote forward to {}:{}: {error}",
                        target.host, target.port
                    );
                    reply.reject(ChannelOpenFailure::ConnectFailed).await;
                    return Ok(());
                }
            };
            credit.defer_close();
            reply.accept().await;
            forward::relay(channel, socket, credit, window, forward::memory_pressure).await
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forwards() -> Arc<Forwards> {
        Arc::new(Forwards::new(Arc::new(Tasks::default()), 8192))
    }

    #[tokio::test]
    async fn only_accepted_exact_bind_keys_choose_locally_defined_targets() {
        let forwards = forwards();
        let allocated = RemoteForward::parse("0:local:80").unwrap();
        for port in [0, 65536, u32::MAX] {
            assert!(forwards.record(&allocated, port).is_err());
        }
        assert_eq!(forwards.record(&allocated, 9000).unwrap(), 9000);
        assert!(
            forwards
                .record(&RemoteForward::parse("0:other:81").unwrap(), 9000)
                .is_err()
        );
        forwards
            .record(
                &RemoteForward::parse("[::1]:9000:ipv6-local:82").unwrap(),
                0,
            )
            .unwrap();
        forwards.finish_setup();
        assert_eq!(
            forwards.target("localhost", 9000).await,
            Some(allocated.target)
        );
        assert_eq!(
            forwards.target("::1", 9000).await.unwrap().host,
            "ipv6-local"
        );
        for (address, port) in [
            ("127.0.0.1", 9000),
            ("[::1]", 9000),
            ("localhost", 0),
            ("localhost", 65536),
            ("localhost", 9001),
        ] {
            assert!(forwards.target(address, port).await.is_none());
        }
        assert!(
            forwards
                .record(&RemoteForward::parse("9001:late:83").unwrap(), 0)
                .is_err()
        );
    }

    #[tokio::test]
    async fn incoming_lookups_wait_until_all_setup_replies_have_been_recorded() {
        let forwards = forwards();
        let mut lookup = Box::pin(forwards.target("localhost", 9000));
        tokio::select! {
            biased;
            _ = lookup.as_mut() => panic!("lookup completed before setup"),
            () = std::future::ready(()) => {}
        }
        forwards
            .record(&RemoteForward::parse("0:target:80").unwrap(), 9000)
            .unwrap();
        tokio::select! {
            biased;
            _ = lookup.as_mut() => panic!("lookup completed before setup finished"),
            () = std::future::ready(()) => {}
        }
        forwards.finish_setup();
        assert_eq!(lookup.await.unwrap().host, "target");
        assert!(forwards.target("localhost", 9001).await.is_none());
    }

    #[tokio::test]
    async fn stopping_admission_preserves_already_admitted_work() {
        let forwards = forwards();
        assert!(matches!(
            forwards.reserve(true),
            Err(ChannelOpenFailure::ResourceShortage)
        ));
        let job = forwards.reserve(false).unwrap();
        forwards.stop_accepting();
        assert!(matches!(
            forwards.reserve(false),
            Err(ChannelOpenFailure::AdministrativelyProhibited)
        ));
        let (sent, received) = tokio::sync::oneshot::channel();
        job.spawn(async move {
            sent.send(()).unwrap();
            Ok(())
        });
        received.await.unwrap();
        forwards.tasks.wait_idle().await;
    }

    #[tokio::test]
    async fn cancellation_drops_even_an_unpolled_admitted_job() {
        let forwards = forwards();
        let job = forwards.reserve(false).unwrap();
        let (sent, received) = tokio::sync::oneshot::channel();
        forwards.cancel();
        job.spawn(async move {
            sent.send(()).unwrap();
            Ok(())
        });
        assert!(received.await.is_err());
        forwards.tasks.wait_idle().await;
    }
}
