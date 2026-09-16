use moto_sys_io::api_net::{self, NetCmd};
use moto_sys_io::api_vsock::{self, VsockAddr};

pub fn run_wire_tests() {
    test_command_values();
    test_connect_codec();
    test_connect_response_codec();
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
    assert_eq!(moto_sys_io::api_net::CMD_MAX, 0x111c);
    assert_eq!(
        NetCmd::try_from(0x111b),
        Ok(NetCmd::EvtVsockStreamStateChanged)
    );
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
