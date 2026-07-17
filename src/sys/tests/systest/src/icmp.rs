use std::net::IpAddr;
use std::time::Duration;

use moto_sys_io::icmp::IcmpEchoClient;

pub fn run_all_tests() {
    let mut client = IcmpEchoClient::connect().unwrap();

    for (sequence, destination) in ["127.0.0.1", "::1"].into_iter().enumerate() {
        let destination: IpAddr = destination.parse().unwrap();
        let reply = client
            .echo(destination, sequence as u16, 32, Duration::from_secs(1))
            .unwrap();
        assert_eq!(reply.source, destination);
        assert_eq!(reply.icmp_bytes, 40);
        assert!(reply.rtt <= Duration::from_secs(1));
    }

    println!("ICMP echo tests PASS");
}
