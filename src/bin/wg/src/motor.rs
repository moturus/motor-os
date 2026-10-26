//! Native packet-device and physical UDP transport, driven on one runtime.
use crate::config::{Config, Result};
use crate::crypto::MTU;
use crate::schedule::{Io, Scheduler};
use moto_sdk::async_runtime::{self, LocalRuntime};
use moto_sdk::io::ip_device::{IpDevice, PacketReceiver};
use moto_sdk::io::net::readiness::{NetEventListener, Readiness};
use moto_sdk::io::net::{NetClient, udp::UdpSocket};
use moto_sdk::sys_io::api_ip_device::{Cidr, Registration};
use std::cell::RefCell;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Instant;

#[path = "motor_queue.rs"]
mod queue;

#[derive(Default)]
struct Ready(Mutex<Option<Waker>>);

impl NetEventListener for Ready {
    fn on_readiness(&self, _: Readiness) {
        let waker = self.0.lock().unwrap().clone();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct MotorIo<'a> {
    outer: Vec<Arc<UdpSocket>>,
    cursor: usize,
    inner: PacketReceiver<'a>,
    output: Rc<RefCell<queue::Queue>>,
}

impl Io for MotorIo<'_> {
    type Error = &'static str;

    fn receive_outer(
        &mut self,
        _: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<Result<(usize, SocketAddr)>> {
        for offset in 0..self.outer.len() {
            let index = (self.cursor + offset) % self.outer.len();
            match self.outer[index].try_recv_from(buffer, false) {
                Ok(packet) => {
                    self.cursor = (index + 1) % self.outer.len();
                    return Poll::Ready(Ok(packet));
                }
                Err(moto_sdk::rt::E_NOT_READY) => (),
                Err(_) => return Poll::Ready(Err("physical UDP binding failed")),
            }
        }
        Poll::Pending
    }

    fn receive_inner(&mut self, cx: &mut Context<'_>, buffer: &mut [u8]) -> Poll<Result<usize>> {
        self.inner
            .poll_receive(cx, buffer)
            .map(|result| result.map_err(|_| "packet-device connection failed"))
    }

    fn send_outer(
        &mut self,
        _: &mut Context<'_>,
        packet: &[u8],
        destination: SocketAddr,
    ) -> Poll<Result<()>> {
        let Some(socket) = self
            .outer
            .iter()
            .find(|socket| socket.local_addr().is_ipv4() == destination.is_ipv4())
        else {
            return Poll::Ready(Err("endpoint family has no physical transport"));
        };
        match socket.try_send_to(packet, &destination) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(moto_sdk::rt::E_NOT_READY) => Poll::Pending,
            Err(_) => Poll::Ready(Err("physical UDP binding failed")),
        }
    }

    fn submit_inner(&mut self, packet: &[u8]) -> bool {
        self.output.borrow_mut().submit(packet)
    }
}

pub fn run(config: &Config) -> Result<()> {
    LocalRuntime::new().block_on(async {
        let (client, driver) = moto_sdk::io::net::connect()
            .await
            .map_err(|_| "cannot connect to sys-io")?;
        let anchor = client
            .try_reserve()
            .map_err(|_| "cannot reserve transport channel")?;
        let driver = LocalRuntime::spawn(driver.run());
        let result = activate(config, &client).await;
        drop(anchor);
        driver.await;
        result
    })
}

async fn activate(config: &Config, client: &NetClient) -> Result<()> {
    // Reserve private buffers and validate every physical binding before
    // registration publishes any route or local tunnel address.
    let scheduler = Scheduler::new(config, Instant::now())?;
    let output = queue::Queue::new()?;
    let ready = Arc::new(Ready::default());
    let mut outer = Vec::with_capacity(config.transport_addresses.len());
    for address in &config.transport_addresses {
        outer.push(
            UdpSocket::bind_physical_reserved(
                client
                    .try_reserve()
                    .map_err(|_| "cannot reserve physical UDP socket")?,
                &SocketAddr::new(*address, config.listen_port),
                Some(ready.clone()),
            )
            .await
            .map_err(|_| "cannot bind physical UDP transport")?,
        );
    }
    let registration = Registration {
        name: config.name.clone(),
        mtu: MTU as u16,
        addresses: config
            .cidrs
            .iter()
            .map(|cidr| Cidr {
                address: cidr.ip(),
                prefix_len: cidr.prefix(),
            })
            .collect(),
        routes: config
            .peers
            .iter()
            .flat_map(|peer| &peer.allowed_ips)
            .map(|prefix| Cidr {
                address: prefix.network(),
                prefix_len: prefix.prefix(),
            })
            .collect(),
    };
    let device = IpDevice::register(&registration)
        .await
        .map_err(|_| "cannot register IP device")?;
    println!(
        "{}: active (pid={})",
        config.name,
        moto_sdk::sys::current_pid()
    );
    forward(device, scheduler, outer, output, ready).await
}

async fn forward(
    mut device: IpDevice,
    mut scheduler: Scheduler,
    outer: Vec<Arc<UdpSocket>>,
    output: Rc<RefCell<queue::Queue>>,
    ready: Arc<Ready>,
) -> Result<()> {
    let result = {
        let (sender, receiver) = device.split();
        let mut writer = std::pin::pin!(queue::Queue::write(output.clone(), sender));
        let mut io = MotorIo {
            outer,
            cursor: 0,
            inner: receiver,
            output,
        };
        drive(&mut scheduler, &mut io, writer.as_mut(), &ready).await
    };
    // Channel closure retires the interface. Fatal exit must not wait for
    // unrelated applications to receive their terminal socket notifications.
    drop(device);
    result
}

async fn drive(
    scheduler: &mut Scheduler,
    io: &mut MotorIo<'_>,
    mut writer: Pin<&mut impl Future<Output = Result<()>>>,
    ready: &Ready,
) -> Result<()> {
    let mut timer = None;
    loop {
        let deadline = scheduler.deadline();
        if timer.as_ref().is_none_or(|(armed, _)| *armed != deadline) {
            timer = Some((
                deadline,
                async_runtime::sleep(deadline.saturating_duration_since(Instant::now())),
            ));
        }
        std::future::poll_fn(|cx| {
            *ready.0.lock().unwrap() = Some(cx.waker().clone());
            if let Poll::Ready(result) = writer.as_mut().poll(cx) {
                return Poll::Ready(result);
            }
            let before = scheduler.counters.batches;
            if let Poll::Ready(result) = scheduler.poll(cx, io, Instant::now()) {
                return Poll::Ready(result);
            }
            if scheduler.counters.batches != before || scheduler.deadline() != deadline {
                return Poll::Ready(Ok(()));
            }
            if Pin::new(&mut timer.as_mut().unwrap().1).poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await?;
        // Only this loop requests an I/O turn, once per bounded batch.
        async_runtime::yield_to_io().await;
    }
}
