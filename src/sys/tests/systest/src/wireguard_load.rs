//! Keep physical traffic and filesystem work moving during bidirectional VPN load.
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

fn timer_ticks(pid: u64) -> u64 {
    use moto_sdk::stats::Collector;
    let provider = Collector::provider_by_name(&format!("wg:{pid}")).unwrap();
    let metric = Collector::describe(&provider)
        .unwrap()
        .into_iter()
        .find(|metric| metric.name == "wg.timer_ticks")
        .unwrap();
    Collector::read(&provider, metric.id, 0).unwrap()
}

pub fn run(pid: &str) {
    let pid = pid.parse().unwrap();
    let destination: SocketAddr = "[fd50:20::1]:7001".parse().unwrap();
    let socket = UdpSocket::bind("[fd50:20::2]:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let receiver = socket.try_clone().unwrap();
    let mut echo = moto_sdk::sys_io::icmp::IcmpEchoClient::connect().unwrap();
    let path = std::env::temp_dir().join(format!("wg-load-{}", moto_sys::current_pid()));
    let ticks = timer_ticks(pid);
    let ready = std::sync::Barrier::new(3);
    let deadline = Instant::now() + Duration::from_secs(2);
    let (sent, received, operations) = std::thread::scope(|scope| {
        let send = scope.spawn(|| {
            ready.wait();
            let mut sent = 0;
            while Instant::now() < deadline {
                match socket.send_to(&[0x5a; 1372], destination) {
                    Ok(1372) => sent += 1,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => std::thread::yield_now(),
                    result => panic!("load send: {result:?}"),
                }
            }
            sent
        });
        let receive = scope.spawn(|| {
            let mut buffer = [0; 1420];
            ready.wait();
            let mut received = 0;
            while Instant::now() < deadline {
                match receiver.recv_from(&mut buffer) {
                    Ok((length, source)) => {
                        assert_eq!(source, destination);
                        assert_eq!(length, 1372);
                        assert!(buffer[..length].iter().all(|byte| *byte == 0x5a));
                        received += 1;
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => std::thread::yield_now(),
                    result => panic!("load receive: {result:?}"),
                }
            }
            received
        });
        ready.wait();
        let mut operations = 0;
        while Instant::now() < deadline {
            let started = Instant::now();
            std::fs::write(&path, [0x37; 4096]).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), [0x37; 4096]);
            let physical: std::net::IpAddr = "192.168.4.1".parse().unwrap();
            let reply = echo
                .echo(physical, operations, 32, Duration::from_secs(1))
                .unwrap();
            assert_eq!(reply.source, physical);
            assert!(started.elapsed() < Duration::from_secs(1));
            operations += 1;
        }
        (send.join().unwrap(), receive.join().unwrap(), operations)
    });
    std::fs::remove_file(path).unwrap();
    assert!(sent > 0 && received > 0 && operations > 0);
    let ticks = timer_ticks(pid) - ticks;
    assert!(ticks >= 4, "WireGuard timers starved under load: {ticks}");
    for name in ["net.ip_device.rx_high_water", "net.ip_device.tx_high_water"] {
        assert!(crate::tcp::read_sys_io_metric(name) <= 64);
    }
    println!(
        "wireguard concurrent progress PASS: sent={sent} received={received} \
         physical/fs operations={operations} timer_ticks={ticks}"
    );
}
