use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::os::fd::FromRawFd;
use std::time::Duration;

pub fn permissions(paths: &[String]) {
    use moto_sdk::io::fs::{AccessPermissions, EntryKind, FsClient};
    assert_eq!(paths.len(), 2);
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let fs = FsClient::connect().unwrap();
        for path in paths {
            let (entry, kind) = fs.stat(path).await.unwrap();
            assert_eq!(kind, EntryKind::File);
            let permissions = fs.metadata(entry).await.unwrap().permissions().unwrap();
            assert_eq!(permissions.none, AccessPermissions::None);
        }
    });
    println!("wireguard permissions PASS");
}

pub fn exchange(remote: &str, local: &str) {
    let remote: IpAddr = remote.parse().unwrap();
    let local: IpAddr = local.parse().unwrap();
    let deadline = Duration::from_secs(3);
    let mut tcp = TcpStream::connect_timeout(&SocketAddr::new(remote, 7000), deadline).unwrap();
    assert_eq!(tcp.local_addr().unwrap().ip(), local);
    tcp.set_read_timeout(Some(deadline)).unwrap();
    tcp.set_write_timeout(Some(deadline)).unwrap();
    for size in [1, 1420, 16384] {
        let payload: Vec<u8> = (0..size).map(|index| (index * 37) as u8).collect();
        tcp.write_all(&payload).unwrap();
        let mut received = vec![0; size];
        tcp.read_exact(&mut received).unwrap();
        assert_eq!(received, payload);
    }
    let remote = SocketAddr::new(remote, 7001);
    let fd = moto_rt::net::udp_bind_for_remote(&remote.into()).unwrap();
    // The route-selected descriptor is newly allocated and owned by this socket.
    let udp = unsafe { UdpSocket::from_raw_fd(fd) };
    assert_eq!(udp.local_addr().unwrap().ip(), local);
    udp.set_read_timeout(Some(deadline)).unwrap();
    let mut received = [0; 1420];
    for size in [0, 1, if local.is_ipv4() { 1392 } else { 1372 }] {
        let payload: Vec<u8> = (0..size).map(|index| (index * 43) as u8).collect();
        assert_eq!(udp.send_to(&payload, remote).unwrap(), size);
        let (length, source) = udp.recv_from(&mut received).unwrap();
        assert_eq!(source, remote);
        assert_eq!(&received[..length], payload);
    }
    println!("wireguard exchange {local} -> {} PASS", remote.ip());
}

pub fn cleanup() {
    crate::tcp::wait_for_sys_io_metric("net.ip_device.devices", |value| value == 0);
    crate::tcp::wait_for_sys_io_metric("net.ip_device.buffer_bytes", |value| value == 0);
    for (remote, local) in [("10.250.20.1", "10.250.20.2"), ("fd50:20::1", "fd50:20::2")] {
        let local: IpAddr = local.parse().unwrap();
        assert!(UdpSocket::bind(SocketAddr::new(local, 0)).is_err());
        let remote = SocketAddr::new(remote.parse().unwrap(), 7001);
        let fd = moto_rt::net::udp_bind_for_remote(&remote.into()).unwrap();
        let udp = unsafe { UdpSocket::from_raw_fd(fd) };
        assert_ne!(udp.local_addr().unwrap().ip(), local);
    }
    println!("wireguard cleanup PASS");
}
