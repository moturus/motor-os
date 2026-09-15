pub fn run_tests() {
    virtio_async::test_descriptor_waiters();
    test_virtio_cap_metadata();
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
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("test-virtio-rx-pool-drop")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("virtio completion dropped while the device still owns its DMA buffers"),
        "unexpected RX-pool-drop failure: {stderr}"
    );
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
    for (case, message) in [
        ("duplicate", "ordered completion consumer already claimed"),
        ("busy", "ordered completion consumer requires an idle queue"),
        (
            "device-overrun",
            "ordered completion cursor exceeded by device",
        ),
        (
            "reclaimer-overrun",
            "ordered completion cursor exceeded by reclaimer",
        ),
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("test-virtio-ordered-completion")
            .arg(case)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(message),
            "unexpected ordered-completion failure: {stderr}"
        );
    }
    println!("virtio descriptor tests PASS");
}

fn test_virtio_cap_metadata() {
    use virtio_async::virtio_test_support::{
        checked_virtio_notify_offset, msix_region_lengths, supported_virtio_cap,
        valid_msix_cap_offset, valid_virtio_cap_access, valid_virtio_cap_bar,
    };

    let header =
        |cap_len: u8, cfg_type: u8| 9u32 | (u32::from(cap_len) << 16) | (u32::from(cfg_type) << 24);
    for (offset, cap_len, cfg_type) in [
        (0x40, 16, 1),
        (0xf0, 16, 1),
        (0xf0, 0xff, 4),
        (0xec, 20, 2),
        (0xec, 0xff, 2),
    ] {
        assert_eq!(
            supported_virtio_cap(offset, header(cap_len, cfg_type)),
            Some(cfg_type)
        );
    }
    for (offset, cap_len, cfg_type) in [
        (0x40, 15, 1),
        (0x40, 19, 2),
        (0xf4, 0xff, 1),
        (0xf0, 0xff, 2),
        (0x40, 0xff, 0),
        (0x40, 0xff, 3),
        (0x40, 0xff, 5),
        (0x40, 0xff, 0xff),
    ] {
        assert_eq!(
            supported_virtio_cap(offset, header(cap_len, cfg_type)),
            None
        );
    }
    for bar in [0, 5] {
        assert!(valid_virtio_cap_bar(bar));
    }
    for bar in [6, 0xff] {
        assert!(!valid_virtio_cap_bar(bar));
    }

    for offset in [0x40, 0xf4] {
        assert!(valid_msix_cap_offset(offset));
    }
    for offset in [0xf8, 0xfc] {
        assert!(!valid_msix_cap_offset(offset));
    }
    for (vectors, table_length, pba_length) in [
        (1, 16, 8),
        (64, 1024, 8),
        (65, 1040, 16),
        (2048, 32768, 256),
    ] {
        assert_eq!(
            msix_region_lengths(vectors),
            Some((table_length, pba_length))
        );
        assert!(valid_virtio_cap_access(
            0x100 + table_length,
            0x100,
            table_length,
            0,
            table_length,
            8
        ));
        assert!(!valid_virtio_cap_access(
            0xff + table_length,
            0x100,
            table_length,
            0,
            table_length,
            8
        ));
        assert!(valid_virtio_cap_access(
            0x200 + pba_length,
            0x200,
            pba_length,
            0,
            pba_length,
            8
        ));
        assert!(!valid_virtio_cap_access(
            0x1ff + pba_length,
            0x200,
            pba_length,
            0,
            pba_length,
            8
        ));
    }
    for vectors in [0, 2049, u16::MAX] {
        assert_eq!(msix_region_lengths(vectors), None);
    }

    assert!(valid_virtio_cap_access(0x106, 0x100, 6, 0, 6, 4));
    assert!(valid_virtio_cap_access(0x138, 0x100, 56, 0, 56, 4));
    for cap_length in [8, u64::from(u32::MAX)] {
        assert!(valid_virtio_cap_access(0x108, 0x100, cap_length, 0, 8, 4));
    }
    for access in [
        (0x108, 0x100, 0, 0, 8, 4),
        (0x108, 0x100, 7, 0, 8, 4),
        (0x107, 0x100, 8, 0, 8, 4),
        (0x108, 0x102, 8, 0, 6, 4),
        (0x108, 0x100, 8, 4, 6, 4),
        (0x108, 0x100, 8, 0, 0, 4),
        (0x108, 0x100, 8, 0, 8, 0),
        (0x108, 0x100, 8, 0, 8, 3),
        (u64::MAX, 0, u64::MAX, u64::MAX, 1, 1),
        (u64::MAX, u64::MAX, 2, 1, 1, 1),
        (u64::MAX, u64::MAX - 1, 2, 0, 2, 1),
    ] {
        assert!(!valid_virtio_cap_access(
            access.0, access.1, access.2, access.3, access.4, access.5
        ));
    }

    assert_eq!(checked_virtio_notify_offset(4, 2, 2, 0, 0), Some(2));
    assert_eq!(
        checked_virtio_notify_offset(0x110, 0x100, 0x10, 2, 7),
        Some(0x10e)
    );
    assert_eq!(
        checked_virtio_notify_offset(0x102, 0x100, u32::MAX, 0, 0),
        Some(0x100)
    );
    for notify in [
        (4, 2, 1, 0, 0),
        (0x112, 0x100, 0x10, 2, 8),
        (8, 2, 4, 1, 1),
        (8, 1, 4, 1, 1),
        (0x101, 0x100, 2, 0, 0),
        (u64::MAX, 0, u32::MAX, u32::MAX, u16::MAX),
    ] {
        assert_eq!(
            checked_virtio_notify_offset(notify.0, notify.1, notify.2, notify.3, notify.4),
            None
        );
    }
}

fn test_vsock_discovery_features() {
    use virtio_async::VirtioDeviceKind;
    use virtio_async::vsock_test_support::{
        classify_device_id, select_features, validate_guest_cid,
    };

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

    for cid in [3, 42, 0xffff_fffe] {
        assert_eq!(validate_guest_cid(cid.into()).unwrap(), cid);
    }
    for cid in [
        0,
        1,
        2,
        0xffff_ffff,
        0x1_0000_0000,
        0x1_0000_0003,
        0x1_ffff_fffe,
        u64::MAX,
    ] {
        assert_eq!(
            validate_guest_cid(cid).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }
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
