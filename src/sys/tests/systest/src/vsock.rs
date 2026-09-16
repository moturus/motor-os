use moto_sys_io::api_net::{self, NetCmd};
use moto_sys_io::api_vsock::{self, VsockAddr};

pub fn run_wire_tests() {
    test_command_values();
    test_connect_codec();
    test_connect_response_codec();
    test_listener_bind_codec();
    test_listener_accept_codec();
    test_control_codec();
    test_state_change_codec();
    test_page_codec();
    println!("vsock::run_wire_tests PASS");
}

fn test_command_values() {
    assert_eq!(NetCmd::VsockAvailability as u16, 0x1115);
    assert_eq!(NetCmd::VsockStreamConnect as u16, 0x1116);
    assert_eq!(NetCmd::VsockStreamTx as u16, 0x1117);
    assert_eq!(NetCmd::VsockStreamRx as u16, 0x1118);
    assert_eq!(NetCmd::VsockStreamShutdown as u16, 0x1119);
    assert_eq!(NetCmd::VsockStreamClose as u16, 0x111a);
    assert_eq!(NetCmd::EvtVsockStreamStateChanged as u16, 0x111b);
    assert_eq!(NetCmd::VsockListenerBind as u16, 0x111c);
    assert_eq!(NetCmd::VsockListenerAccept as u16, 0x111d);
    assert_eq!(NetCmd::VsockListenerDrop as u16, 0x111e);
    assert_eq!(moto_sys_io::api_net::CMD_MAX, 0x111f);
    assert_eq!(NetCmd::try_from(0x111e), Ok(NetCmd::VsockListenerDrop));
}

fn test_connect_codec() {
    let peer = VsockAddr {
        cid: 3,
        port: 70_000,
    };
    let request = api_vsock::connect_request(peer, 3).unwrap();
    let mut expected = [0_u8; 24];
    expected[..4].copy_from_slice(&3_u32.to_le_bytes());
    expected[4..8].copy_from_slice(&70_000_u32.to_le_bytes());
    expected[23] = 3;
    assert_eq!(request.command, NetCmd::VsockStreamConnect as u16);
    assert_eq!(request.handle, 0);
    assert_eq!(request.flags, 0);
    assert_eq!(request.payload.args_8(), &expected);
    assert_eq!(
        api_vsock::decode_connect_request(&request).unwrap(),
        api_vsock::ConnectRequest {
            peer,
            subchannel_mask: 0xffff_0000_0000_0000,
        }
    );

    for cid in [2, 4, 0xffff_fffe] {
        let peer = VsockAddr { cid, port: 80_000 };
        let request = api_vsock::connect_request(peer, 0).unwrap();
        assert_eq!(
            api_vsock::decode_connect_request(&request).unwrap().peer,
            peer
        );
    }
    for cid in [0, 1, u32::MAX] {
        assert_eq!(
            api_vsock::connect_request(VsockAddr { cid, port: 1 }, 0).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
    }
    for port in [0, u32::MAX] {
        assert_eq!(
            api_vsock::connect_request(VsockAddr { cid: 2, port }, 0).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
    }
    assert_eq!(
        api_vsock::connect_request(peer, 4).err(),
        Some(moto_rt::Error::InvalidArgument)
    );

    let mut bad = [request; 9];
    bad[0].command = NetCmd::VsockStreamClose as u16;
    bad[1].handle = 1;
    bad[2].flags = 1;
    bad[3].payload.args_8_mut()[8] = 1;
    bad[4].payload.args_8_mut()[23] = api_net::IO_SUBCHANNELS;
    bad[5].payload.args_8_mut()[23] = u8::MAX;
    bad[6].payload.args_32_mut()[0] = 1;
    bad[7].payload.args_32_mut()[1] = 0;
    bad[8].payload.args_32_mut()[1] = u32::MAX;
    for request in bad {
        assert_eq!(
            api_vsock::decode_connect_request(&request).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
    }
}

fn test_connect_response_codec() {
    let mut request = api_vsock::connect_request(
        VsockAddr {
            cid: 2,
            port: 70_001,
        },
        1,
    )
    .unwrap();
    request.id = 0x1234;
    request.wake_handle = 0x5678;
    let local = VsockAddr {
        cid: 0xffff_fffe,
        port: 90_000,
    };
    let response = api_vsock::encode_connect_response(&request, 0xa5, local).unwrap();
    assert_eq!(response.id, request.id);
    assert_eq!(response.wake_handle, request.wake_handle);
    assert_eq!(response.command, request.command);
    assert_eq!(response.status, moto_rt::E_OK);
    assert_eq!(response.flags, 0);
    let mut expected = [0_u8; 24];
    expected[..4].copy_from_slice(&local.cid.to_le_bytes());
    expected[4..8].copy_from_slice(&local.port.to_le_bytes());
    assert_eq!(response.payload.args_8(), &expected);
    assert_eq!(
        api_vsock::decode_connect_response(&response).unwrap(),
        api_vsock::ConnectResponse {
            handle: 0xa5,
            local,
        }
    );

    let mut error = response;
    error.status = moto_rt::E_NOT_IMPLEMENTED;
    error.handle = 0;
    error.payload.args_32_mut()[0] = 0;
    assert_eq!(
        api_vsock::decode_connect_response(&error).err(),
        Some(moto_rt::Error::NotImplemented)
    );
    let mut bad = [response; 4];
    bad[0].handle = 0;
    bad[1].flags = 1;
    bad[2].payload.args_8_mut()[8] = 1;
    bad[3].payload.args_32_mut()[0] = 2;
    for response in bad {
        assert_eq!(
            api_vsock::decode_connect_response(&response).err(),
            Some(moto_rt::Error::InvalidData)
        );
    }
    assert_eq!(
        api_vsock::encode_connect_response(&request, 0, local).err(),
        Some(moto_rt::Error::InvalidArgument)
    );
    for local in [
        VsockAddr { cid: 2, port: 1 },
        VsockAddr { cid: 3, port: 0 },
        VsockAddr {
            cid: u32::MAX,
            port: 1,
        },
    ] {
        assert_eq!(
            api_vsock::encode_connect_response(&request, 1, local).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
    }
}

fn test_listener_bind_codec() {
    let mut bind = api_vsock::listener_bind_request(70_000).unwrap();
    bind.id = 0x111;
    bind.wake_handle = 0x222;
    let mut expected = [0_u8; 24];
    expected[..4].copy_from_slice(&70_000_u32.to_le_bytes());
    assert_eq!(bind.command, NetCmd::VsockListenerBind as u16);
    assert_eq!(bind.handle, 0);
    assert_eq!(bind.flags, 0);
    assert_eq!(bind.payload.args_8(), &expected);
    assert_eq!(api_vsock::decode_listener_bind_request(&bind), Ok(70_000));
    assert_eq!(
        api_vsock::decode_listener_bind_request(&api_vsock::listener_bind_request(0).unwrap()),
        Ok(0)
    );
    assert_eq!(
        api_vsock::listener_bind_request(u32::MAX).err(),
        Some(moto_rt::Error::InvalidArgument)
    );
    let mut bad_bind = [bind; 5];
    bad_bind[0].command = NetCmd::VsockListenerAccept as u16;
    bad_bind[1].handle = 1;
    bad_bind[2].flags = 1;
    bad_bind[3].payload.args_8_mut()[4] = 1;
    bad_bind[4].payload.args_32_mut()[0] = u32::MAX;
    for request in bad_bind {
        assert_eq!(
            api_vsock::decode_listener_bind_request(&request).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
    }

    let local = VsockAddr {
        cid: 3,
        port: 70_000,
    };
    let bind_response = api_vsock::encode_listener_bind_response(&bind, 0x51, local).unwrap();
    assert_eq!(bind_response.id, bind.id);
    assert_eq!(bind_response.wake_handle, bind.wake_handle);
    assert_eq!(bind_response.command, bind.command);
    assert_eq!(bind_response.status, moto_rt::E_OK);
    assert_eq!(bind_response.flags, 0);
    expected = [0; 24];
    expected[..4].copy_from_slice(&local.cid.to_le_bytes());
    expected[4..8].copy_from_slice(&local.port.to_le_bytes());
    assert_eq!(bind_response.payload.args_8(), &expected);
    assert_eq!(
        api_vsock::decode_listener_bind_response(&bind_response).unwrap(),
        api_vsock::ListenerBindResponse {
            handle: 0x51,
            local,
        }
    );
    let mut error = bind_response;
    error.status = moto_rt::E_ALREADY_IN_USE;
    error.handle = 0;
    error.payload.args_64_mut()[0] = 0;
    assert_eq!(
        api_vsock::decode_listener_bind_response(&error).err(),
        Some(moto_rt::Error::AlreadyInUse)
    );
    let mut bad_response = [bind_response; 4];
    bad_response[0].handle = 0;
    bad_response[1].flags = 1;
    bad_response[2].payload.args_32_mut()[0] = 2;
    bad_response[3].payload.args_8_mut()[8] = 1;
    for response in bad_response {
        assert_eq!(
            api_vsock::decode_listener_bind_response(&response).err(),
            Some(moto_rt::Error::InvalidData)
        );
    }

    let drop_request = api_vsock::listener_drop_request(0x51);
    assert_eq!(drop_request.command, NetCmd::VsockListenerDrop as u16);
    assert_eq!(drop_request.handle, 0x51);
    assert_eq!(drop_request.flags, 0);
    assert_eq!(drop_request.payload.args_64(), &[0; 3]);
    assert_eq!(
        api_vsock::decode_listener_drop_request(&drop_request),
        Ok(())
    );
    let mut bad_drop = [drop_request; 3];
    bad_drop[0].command = NetCmd::VsockListenerAccept as u16;
    bad_drop[1].flags = 1;
    bad_drop[2].payload.args_8_mut()[0] = 1;
    for request in bad_drop {
        assert_eq!(
            api_vsock::decode_listener_drop_request(&request).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
    }
}

fn test_listener_accept_codec() {
    let local = VsockAddr {
        cid: 3,
        port: 70_000,
    };
    let mut accept = api_vsock::listener_accept_request(0x51, 3).unwrap();
    accept.id = 0x333;
    accept.wake_handle = 0x444;
    let mut expected = [0; 24];
    expected[23] = 3;
    assert_eq!(accept.command, NetCmd::VsockListenerAccept as u16);
    assert_eq!(accept.handle, 0x51);
    assert_eq!(accept.flags, 0);
    assert_eq!(accept.payload.args_8(), &expected);
    assert_eq!(
        api_vsock::decode_listener_accept_request(&accept).unwrap(),
        api_vsock::AcceptRequest {
            subchannel_mask: 0xffff_0000_0000_0000,
        }
    );
    assert_eq!(
        api_vsock::listener_accept_request(1, api_net::IO_SUBCHANNELS).err(),
        Some(moto_rt::Error::InvalidArgument)
    );
    let mut bad_accept = [accept; 5];
    bad_accept[0].command = NetCmd::VsockListenerBind as u16;
    bad_accept[1].flags = 1;
    bad_accept[2].payload.args_8_mut()[0] = 1;
    bad_accept[3].payload.args_8_mut()[23] = api_net::IO_SUBCHANNELS;
    bad_accept[4].payload.args_8_mut()[23] = u8::MAX;
    for request in bad_accept {
        assert_eq!(
            api_vsock::decode_listener_accept_request(&request).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
    }

    let peer = VsockAddr {
        cid: 2,
        port: 80_000,
    };
    let response = api_vsock::encode_listener_accept_response(&accept, 0x52, local, peer).unwrap();
    expected = [0; 24];
    expected[..4].copy_from_slice(&local.cid.to_le_bytes());
    expected[4..8].copy_from_slice(&local.port.to_le_bytes());
    expected[8..12].copy_from_slice(&peer.cid.to_le_bytes());
    expected[12..16].copy_from_slice(&peer.port.to_le_bytes());
    assert_eq!(response.id, accept.id);
    assert_eq!(response.wake_handle, accept.wake_handle);
    assert_eq!(response.command, accept.command);
    assert_eq!(response.payload.args_8(), &expected);
    assert_eq!(
        api_vsock::decode_listener_accept_response(&response).unwrap(),
        api_vsock::AcceptResponse {
            handle: 0x52,
            local,
            peer,
        }
    );
    for port in [0, u32::MAX] {
        let peer = VsockAddr { cid: 2, port };
        let response =
            api_vsock::encode_listener_accept_response(&accept, 0x52, local, peer).unwrap();
        assert_eq!(
            api_vsock::decode_listener_accept_response(&response)
                .unwrap()
                .peer,
            peer
        );
        assert_eq!(
            api_vsock::connect_request(peer, 0).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
    }
    let mut error = response;
    error.status = moto_rt::E_NOT_CONNECTED;
    error.handle = 0;
    error.payload.args_64_mut()[0] = 0;
    assert_eq!(
        api_vsock::decode_listener_accept_response(&error).err(),
        Some(moto_rt::Error::NotConnected)
    );
    let mut bad_response = [response; 4];
    bad_response[0].handle = 0;
    bad_response[1].flags = 1;
    bad_response[2].payload.args_32_mut()[2] = 1;
    bad_response[3].payload.args_8_mut()[16] = 1;
    for response in bad_response {
        assert_eq!(
            api_vsock::decode_listener_accept_response(&response).err(),
            Some(moto_rt::Error::InvalidData)
        );
    }
}

fn test_control_codec() {
    for flags in [
        api_vsock::SHUTDOWN_RECEIVE,
        api_vsock::SHUTDOWN_SEND,
        api_vsock::SHUTDOWN_RECEIVE | api_vsock::SHUTDOWN_SEND,
    ] {
        let request = api_vsock::shutdown_request(0x99, flags).unwrap();
        assert_eq!(request.command, NetCmd::VsockStreamShutdown as u16);
        assert_eq!(request.handle, 0x99);
        assert_eq!(request.flags, flags);
        assert_eq!(request.payload.args_64(), &[0; 3]);
        assert_eq!(api_vsock::decode_shutdown_request(&request), Ok(flags));
    }
    for flags in [0, 4, u32::MAX] {
        assert_eq!(
            api_vsock::shutdown_request(1, flags).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
    }
    let shutdown = api_vsock::shutdown_request(0, api_vsock::SHUTDOWN_RECEIVE).unwrap();
    let mut bad = [shutdown; 3];
    bad[0].command = NetCmd::VsockStreamClose as u16;
    bad[1].flags = 4;
    bad[2].payload.args_8_mut()[23] = 1;
    for request in bad {
        assert_eq!(
            api_vsock::decode_shutdown_request(&request).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
    }

    let close = api_vsock::close_request(0x123);
    assert_eq!(close.command, NetCmd::VsockStreamClose as u16);
    assert_eq!(close.handle, 0x123);
    assert_eq!(close.flags, 0);
    assert_eq!(close.payload.args_64(), &[0; 3]);
    assert_eq!(api_vsock::decode_close_request(&close), Ok(()));
    let mut bad = [close; 3];
    bad[0].command = NetCmd::VsockStreamShutdown as u16;
    bad[1].flags = 1;
    bad[2].payload.args_8_mut()[0] = 1;
    for request in bad {
        assert_eq!(
            api_vsock::decode_close_request(&request).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
    }
}

fn test_state_change_codec() {
    let cases = [
        (api_vsock::STATE_READ_CLOSED, None),
        (api_vsock::STATE_TERMINAL, None),
        (
            api_vsock::STATE_READ_CLOSED | api_vsock::STATE_TERMINAL,
            Some(moto_rt::Error::ConnectionReset),
        ),
        (
            api_vsock::STATE_READ_CLOSED
                | api_vsock::STATE_WRITE_CLOSED
                | api_vsock::STATE_TERMINAL,
            Some(moto_rt::Error::InternalError),
        ),
    ];
    for (flags, cause) in cases {
        let event = api_vsock::state_changed(0x44, flags, cause).unwrap();
        assert_eq!(event.command, NetCmd::EvtVsockStreamStateChanged as u16);
        assert_eq!(event.handle, 0x44);
        assert_eq!(event.status, moto_rt::E_OK);
        assert_eq!(event.flags, flags);
        let mut expected = [0_u8; 24];
        expected[..4].copy_from_slice(&cause.map_or(0, |err| err as u32).to_le_bytes());
        assert_eq!(event.payload.args_8(), &expected);
        assert_eq!(
            api_vsock::decode_state_changed(&event).unwrap(),
            api_vsock::StreamStateChange {
                handle: 0x44,
                flags,
                cause,
            }
        );
    }

    assert_eq!(
        api_vsock::state_changed(1, 0, Some(moto_rt::Error::ConnectionReset)).err(),
        Some(moto_rt::Error::InvalidArgument)
    );
    assert_eq!(
        api_vsock::state_changed(1, api_vsock::STATE_TERMINAL, Some(moto_rt::Error::TimedOut))
            .err(),
        Some(moto_rt::Error::InvalidArgument)
    );
    let event = api_vsock::state_changed(1, api_vsock::STATE_TERMINAL, None).unwrap();
    let mut bad = [event; 4];
    bad[0].flags = 8;
    bad[1].payload.args_32_mut()[0] = moto_rt::E_CONNECTION_RESET as u32;
    bad[1].flags = 0;
    bad[2].payload.args_32_mut()[0] = moto_rt::E_TIMED_OUT as u32;
    bad[3].payload.args_8_mut()[4] = 1;
    for event in bad {
        assert_eq!(
            api_vsock::decode_state_changed(&event).err(),
            Some(moto_rt::Error::InvalidData)
        );
    }

    let mut error = event;
    error.status = moto_rt::E_CONNECTION_RESET;
    error.flags = u32::MAX;
    assert_eq!(
        api_vsock::decode_state_changed(&error).err(),
        Some(moto_rt::Error::ConnectionReset)
    );
}

fn test_page_codec() {
    use moto_ipc::io_channel::{IoPage, PAGE_SIZE};

    moto_async::LocalRuntime::new().block_on(async {
        let (sender, _receiver) = moto_ipc::io_channel::connect("sys-io").unwrap();

        let page = sender.alloc_page(u64::MAX).await.unwrap();
        page.bytes_mut()[..4].copy_from_slice(b"tx-1");
        let tx = api_vsock::stream_tx_msg(0x22, page, 4, 0x1234);
        assert_eq!(tx.command, NetCmd::VsockStreamTx as u16);
        assert_eq!(tx.handle, 0x22);
        assert_eq!(tx.flags, 0);
        assert_eq!(tx.payload.args_64()[1], 4);
        assert_eq!(tx.payload.args_64()[2], 0x1234);
        let page_id = tx.payload.shared_pages()[0];
        let page = sender.get_page(page_id).unwrap();
        assert_eq!(&page.bytes()[..4], b"tx-1");
        drop(page);

        let page = sender.alloc_page(u64::MAX).await.unwrap();
        page.bytes_mut()[0] = 0x5a;
        let rx = api_vsock::stream_rx_msg(0x33, page, 1, 0x5678);
        assert_eq!(rx.command, NetCmd::VsockStreamRx as u16);
        assert_eq!(rx.handle, 0x33);
        assert_eq!(rx.flags, 0);
        assert_eq!(rx.payload.args_64()[1], 1);
        assert_eq!(rx.payload.args_64()[2], 0x5678);
        let page = sender.get_page(rx.payload.shared_pages()[0]).unwrap();
        assert_eq!(page.bytes()[0], 0x5a);
        drop(page);

        assert_eq!(api_vsock::STREAM_TX_MAX_PAGES, 8);
        assert_eq!(api_vsock::STREAM_TX_MAX_BYTES, 8 * PAGE_SIZE);
        let pages = sender.alloc_pages(2, u64::MAX).await.unwrap();
        pages[0].bytes_mut()[0] = 0xa1;
        pages[1].bytes_mut()[0] = 0xb2;
        let page_ids = pages.into_iter().map(IoPage::into_u16).collect::<Vec<_>>();
        let total_len = (PAGE_SIZE + 17) as u32;
        let multi =
            api_vsock::stream_tx_multi_msg(0x44, &page_ids, total_len, 0x8877_6655_4433_2211);
        assert_eq!(multi.command, NetCmd::VsockStreamTx as u16);
        assert_eq!(multi.handle, 0x44);
        assert_eq!(multi.flags, total_len);
        assert_eq!(&multi.payload.shared_pages()[..2], page_ids.as_slice());
        assert!(multi.payload.shared_pages()[2..8].iter().all(|id| *id == 0));
        assert_eq!(multi.payload.args_64()[2], 0x8877_6655_4433_2211);

        let mut invalid = multi;
        invalid.command = NetCmd::TcpStreamTx as u16;
        assert_eq!(
            api_vsock::stream_tx_multi_decode(&invalid, &sender).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
        invalid.command = NetCmd::VsockStreamTx as u16;
        invalid.flags = 0;
        assert_eq!(
            api_vsock::stream_tx_multi_decode(&invalid, &sender).err(),
            Some(moto_rt::Error::InvalidArgument)
        );
        invalid.flags = api_vsock::STREAM_TX_MAX_BYTES as u32 + 1;
        assert_eq!(
            api_vsock::stream_tx_multi_decode(&invalid, &sender).err(),
            Some(moto_rt::Error::InvalidArgument)
        );

        let (pages, decoded_len) = api_vsock::stream_tx_multi_decode(&multi, &sender).unwrap();
        assert_eq!(decoded_len, total_len);
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].bytes()[0], 0xa1);
        assert_eq!(pages[1].bytes()[0], 0xb2);
    });
}
