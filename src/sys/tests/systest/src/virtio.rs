pub fn run_tests() {
    virtio_async::test_descriptor_waiters();
    test_vsock_discovery_features();
    test_vsock_wire();
    for kind in ["block", "network"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("test-virtio-premature-drop")
            .arg(kind)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr
                .contains("virtio completion dropped while the device still owns its DMA buffers"),
            "unexpected premature-drop failure: {stderr}"
        );
    }
    for (case, message) in [
        ("get-buffer-size", "virtio header buffer too small"),
        ("read-header-size", "virtio header buffer too small"),
        ("alignment", "virtio header buffer is misaligned"),
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("test-virtio-header-layout")
            .arg(case)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(message),
            "unexpected header-layout failure: {stderr}"
        );
    }
    for case in ["queue-size", "u16-wrap", "u32-max"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("test-virtio-used-id")
            .arg(case)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("virtio used descriptor ID out of range"),
            "unexpected used-ID failure: {stderr}"
        );
    }
    println!("virtio descriptor tests PASS");
}

fn test_vsock_discovery_features() {
    use virtio_async::VirtioDeviceKind;
    use virtio_async::vsock_test_support::{classify_device_id, select_features};

    assert!(matches!(classify_device_id(0x1041), VirtioDeviceKind::Net));
    assert!(matches!(
        classify_device_id(0x1042),
        VirtioDeviceKind::Block
    ));
    assert!(matches!(
        classify_device_id(0x1053),
        VirtioDeviceKind::Vsock
    ));
    assert!(matches!(
        classify_device_id(0x1001),
        VirtioDeviceKind::Unknown(0x1001)
    ));
    assert!(matches!(
        classify_device_id(0x1052),
        VirtioDeviceKind::Unknown(0x1052)
    ));

    const VERSION_1: u64 = 1 << 32;
    const EVENT_IDX: u64 = 1 << 29;
    assert_eq!(select_features(VERSION_1).unwrap(), VERSION_1);
    assert_eq!(select_features(u64::MAX).unwrap(), VERSION_1 | EVENT_IDX);
    assert_eq!(
        select_features(VERSION_1 | EVENT_IDX).unwrap(),
        VERSION_1 | EVENT_IDX
    );
    assert_eq!(
        select_features(VERSION_1 | EVENT_IDX | (1 << 28) | 3 | (1 << 63)).unwrap(),
        VERSION_1 | EVENT_IDX
    );
    assert_eq!(
        select_features(!VERSION_1).unwrap_err().kind(),
        std::io::ErrorKind::Unsupported
    );
}

fn test_vsock_wire() {
    use virtio_async::vsock_test_support::*;

    let packet = [
        2, 0, 0, 0, 0, 0, 0, 0, // src CID
        0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, // dst CID
        1, 2, 3, 4, 5, 6, 7, 8, // ports
        3, 0, 0, 0, 1, 0, 5, 0, // length, type, operation
        0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, // flags, buffer allocation
        0x55, 0x66, 0x77, 0x88, // forwarded count
    ];
    assert_eq!(HEADER_LEN, 44);
    assert_eq!(EVENT_LEN, 4);
    assert_eq!(decode_event(&[0, 0, 0, 0], 4), Ok(Event::TransportReset));
    assert_eq!(decode_event(&[1, 0, 0, 0], 4), Err(EventError::Unknown(1)));
    assert_eq!(decode_event(&[0, 0, 0], 3), Err(EventError::InvalidLength));
    assert_eq!(decode_event(&[0, 0, 0], 4), Err(EventError::InvalidLength));
    assert_eq!(
        decode_event(&[0, 0, 0, 0], 5),
        Err(EventError::InvalidLength)
    );

    assert_eq!(
        decode_packet(&packet, 47, 3),
        Ok(PacketHeader {
            src_cid: 2,
            dst_cid: 0x7856_3412,
            src_port: 0x0403_0201,
            dst_port: 0x0807_0605,
            len: 3,
            socket_type: SocketType::Stream,
            operation: Operation::ReadWrite,
            flags: 0,
            buf_alloc: 0x4433_2211,
            fwd_cnt: 0x8877_6655,
        })
    );
    let error = |packet: &[u8], used_len, capacity| {
        decode_packet(packet, used_len, capacity).unwrap_err().kind
    };
    let decoded = decode_packet(&packet, 43, 3).unwrap_err();
    assert_eq!(decoded.kind, DecodeErrorKind::ShortHeader);
    assert_eq!(decoded.raw, None);
    assert_eq!(error(&packet[..43], 47, 3), DecodeErrorKind::ShortHeader);
    assert_eq!(error(&packet, 46, 3), DecodeErrorKind::TruncatedPayload);
    assert_eq!(
        error(&packet, 48, 3),
        DecodeErrorKind::UsedLengthExceedsCapacity
    );
    assert_eq!(
        error(&packet, 46, 2),
        DecodeErrorKind::PayloadExceedsCapacity
    );
    assert_eq!(error(&packet, 48, 4), DecodeErrorKind::TrailingPayload);

    let mut invalid = packet;
    invalid[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        error(&invalid, 44, usize::MAX),
        DecodeErrorKind::LengthOverflow
    );
    invalid = packet;
    invalid[8..16].copy_from_slice(&(1_u64 << 32).to_le_bytes());
    let decoded = decode_packet(&invalid, 47, 3).unwrap_err();
    assert_eq!(decoded.kind, DecodeErrorKind::CidTooWide);
    assert_eq!(decoded.raw.unwrap().dst_port, 0x0807_0605);
    invalid = packet;
    invalid[..8].copy_from_slice(&(1_u64 << 32).to_le_bytes());
    assert_eq!(error(&invalid, 47, 3), DecodeErrorKind::CidTooWide);

    invalid = packet;
    invalid[28..30].copy_from_slice(&2_u16.to_le_bytes());
    let decoded = decode_packet(&invalid, 47, 3).unwrap_err();
    assert_eq!(decoded.kind, DecodeErrorKind::UnknownSocketType);
    assert_eq!(decoded.raw.unwrap().socket_type, 2);
    invalid = packet;
    invalid[30..32].copy_from_slice(&8_u16.to_le_bytes());
    assert_eq!(error(&invalid, 47, 3), DecodeErrorKind::UnknownOperation);
    invalid = packet;
    invalid[32..36].copy_from_slice(&1_u32.to_le_bytes());
    assert_eq!(error(&invalid, 47, 3), DecodeErrorKind::InvalidFlags);

    invalid = packet;
    invalid[24..28].fill(0);
    for (tag, operation) in [
        (1_u16, Operation::Request),
        (2, Operation::Response),
        (3, Operation::Reset),
        (4, Operation::Shutdown),
        (5, Operation::ReadWrite),
        (6, Operation::CreditUpdate),
        (7, Operation::CreditRequest),
    ] {
        invalid[30..32].copy_from_slice(&tag.to_le_bytes());
        assert_eq!(decode_packet(&invalid, 44, 0).unwrap().operation, operation);
    }
    invalid[30..32].copy_from_slice(&4_u16.to_le_bytes());
    for flags in 0_u32..=3 {
        invalid[32..36].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(decode_packet(&invalid, 44, 0).unwrap().flags, flags);
    }
    invalid[32..36].copy_from_slice(&4_u32.to_le_bytes());
    assert_eq!(error(&invalid, 44, 0), DecodeErrorKind::InvalidFlags);
    invalid[24..28].copy_from_slice(&1_u32.to_le_bytes());
    invalid[32..36].fill(0);
    assert_eq!(error(&invalid, 45, 1), DecodeErrorKind::ControlPayload);
}
