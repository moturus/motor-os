//! Real IPC backpressure: neither a full reply ring nor a full packet queue
//! may stop input-page reclamation or unrelated sys-io work.
use crate::net_harness::bounded_output;
use moto_sdk::ipc::io_channel::{self, IoPage};
use moto_sdk::sys_io::{api_ip_device as api, api_net::NetCmd};

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn request(sequence: u16) -> [u8; 36] {
    let mut bytes = [0; 36];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&36_u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&[10, 242, 8, 2]);
    bytes[16..20].copy_from_slice(&[10, 242, 8, 1]);
    let sum = checksum(&bytes[..20]);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    bytes[20] = 8;
    bytes[24..26].copy_from_slice(&0x5751_u16.to_be_bytes());
    bytes[26..28].copy_from_slice(&sequence.to_be_bytes());
    bytes[28..].fill(0xab);
    let sum = checksum(&bytes[20..]);
    bytes[22..24].copy_from_slice(&sum.to_be_bytes());
    bytes
}

async fn send(sender: &io_channel::Sender, bytes: &[u8]) {
    let page = bounded_output(sender.alloc_page(u64::MAX), 2)
        .await
        .unwrap()
        .unwrap();
    page.bytes_mut()[..bytes.len()].copy_from_slice(bytes);
    let page = IoPage::into_u16(page);
    let message = api::page_message(NetCmd::IpDevicePacket, page, bytes.len()).unwrap();
    bounded_output(sender.send_with_owned_page(message, page), 2)
        .await
        .unwrap()
        .unwrap();
}

async fn reply(receiver: &mut io_channel::Receiver) -> u16 {
    let message = bounded_output(receiver.recv(), 2).await.unwrap().unwrap();
    assert_eq!(message.command, NetCmd::IpDevicePacket.as_u16());
    let length = api::page_length(&message).unwrap();
    let page = receiver
        .get_remote_page(message.payload.shared_pages()[11])
        .unwrap();
    let bytes = &page.bytes()[..length];
    assert_eq!(length, 36);
    assert_eq!(&bytes[12..20], &[10, 242, 8, 1, 10, 242, 8, 2]);
    assert_eq!(checksum(&bytes[..20]), 0);
    assert_eq!(checksum(&bytes[20..]), 0);
    assert_eq!(bytes[20], 0);
    assert_eq!(&bytes[28..], &[0xab; 8]);
    u16::from_be_bytes([bytes[26], bytes[27]])
}

pub fn test_full_queues_recover() {
    use crate::tcp::{read_sys_io_metric as metric, wait_for_sys_io_metric as wait};
    let dropped = metric("net.ip_device.rx_dropped");
    let buffers = metric("net.ip_device.buffer_bytes");
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let (sender, mut receiver) = io_channel::connect("sys-io").unwrap();
        let config = super::ip_device_live::config(8);
        let page = sender.alloc_page(u64::MAX).await.unwrap();
        let length = config.encode(page.bytes_mut()).unwrap();
        let page = IoPage::into_u16(page);
        sender
            .send_with_owned_page(
                api::page_message(NetCmd::IpDeviceRegister, page, length).unwrap(),
                page,
            )
            .await
            .unwrap();
        assert_eq!(
            bounded_output(receiver.recv(), 2)
                .await
                .unwrap()
                .unwrap()
                .status(),
            Ok(())
        );

        // Leave the reply ring unread. Its 64 pages fill first, followed by
        // the bounded TX and RX pools. Later input is dropped and counted.
        for sequence in 0..512 {
            send(&sender, &request(sequence)).await;
        }
        // Owning every client page proves that sys-io has processed every
        // input message. This is a completion barrier, not a scheduler delay.
        let pages = bounded_output(sender.alloc_pages(64, u64::MAX), 2)
            .await
            .unwrap()
            .unwrap();
        let drops = metric("net.ip_device.rx_dropped") - dropped;
        assert!(drops > 0 && drops < 512, "unexpected drop count {drops}");
        assert_eq!(metric("net.ip_device.rx_high_water"), 64);
        assert_eq!(metric("net.ip_device.tx_high_water"), 64);
        assert!(std::fs::metadata("/user").unwrap().is_dir());
        drop(pages);
        let mut seen = [false; 512];
        for _ in 0..512 - drops {
            let sequence = reply(&mut receiver).await as usize;
            assert!(sequence < seen.len() && !seen[sequence]);
            seen[sequence] = true;
        }
        // Every accepted packet has now drained. A fresh probe proves that
        // freeing shared pages and queue tokens resumed both directions.
        send(&sender, &request(8192)).await;
        assert_eq!(reply(&mut receiver).await, 8192);
        sender.send(api::unregister_request()).await.unwrap();
        let message = bounded_output(receiver.recv(), 2).await.unwrap().unwrap();
        assert_eq!(message.command, NetCmd::IpDeviceUnregister.as_u16());
        assert_eq!(message.status(), Ok(()));
    });
    wait("net.ip_device.buffer_bytes", |bytes| bytes == buffers);
    println!("ip_device::test_full_queues_recover PASS");
}
