//! Exercise the provider protocol through real sys-io channels.
use crate::net_harness::bounded_output;
use futures::FutureExt;
use moto_sdk::io::ip_device::IpDevice;
use moto_sdk::ipc::io_channel::{self, IoPage};
use moto_sdk::sys_io::{api_ip_device as api, api_net::NetCmd};

const CHILD: &str = "ip-device-admission-child";

pub fn run_child(args: &[String]) -> bool {
    if args.len() != 3 || args[1] != CHILD {
        return false;
    }
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        if args[2] == "provider" {
            use std::io::Write;
            let mut device = IpDevice::register(&super::ip_device_live::config(2))
                .await
                .unwrap();
            println!("0"); // Parent may start requests once registration is active.
            std::io::stdout().flush().unwrap();
            let (_, mut rx) = device.split();
            let mut bytes = [0; 4096];
            loop {
                rx.receive(&mut bytes).await.unwrap();
                println!(
                    "{}",
                    if bytes[0] >> 4 == 4 {
                        bytes[9]
                    } else {
                        bytes[6]
                    }
                );
                std::io::stdout().flush().unwrap();
            }
        }
        let config = super::ip_device_live::config(7);
        if args[2] == "no-role" || args[2] == "no-net" {
            let result = bounded_output(IpDevice::register(&config), 2)
                .await
                .unwrap();
            let error = result.err().expect("unauthorized device was registered");
            assert_eq!(
                error,
                if args[2] == "no-role" {
                    moto_rt::Error::NotAllowed
                } else {
                    moto_rt::Error::NotConnected
                }
            );
            return;
        }
        let (sender, mut receiver) = io_channel::connect("sys-io").unwrap();
        let page = sender.alloc_page(u64::MAX).await.unwrap();
        let length = config.encode(page.bytes_mut()).unwrap();
        let page = IoPage::into_u16(page);
        let mut message = api::page_message(NetCmd::IpDeviceRegister, page, length).unwrap();
        match args[2].as_str() {
            "wrong-pool" => message.payload.shared_pages_mut()[11] |= 1 << 15,
            "bad-index" => message.payload.shared_pages_mut()[11] = 64,
            "bad-length" => message.payload.args_16_mut()[0] = 4097,
            "bad-reserved" => message.flags = 1,
            _ => panic!("unknown provider test mode"),
        }
        // Deliberately transfer invalid metadata; the server must terminate
        // this child, so neither a normal response nor a timeout is success.
        let _ = sender.send(message).await;
        let _ = bounded_output(receiver.recv(), 2).await;
        std::process::exit(77);
    });
    true
}

pub fn test_admission_and_terminal_channel() {
    use moto_sys::caps::{CAP_INTERACTIVE, CAP_NET, MOTOR_OS_CAPS_ENV_KEY};
    let baseline = crate::tcp::read_sys_io_metric("net.num_devices");
    let malformed = crate::tcp::read_sys_io_metric("net.ip_device.malformed");
    for (mode, caps, exit) in [
        ("no-role", CAP_NET, 0),
        ("no-net", CAP_INTERACTIVE, 0),
        ("wrong-pool", CAP_INTERACTIVE | CAP_NET, -1),
        ("bad-index", CAP_INTERACTIVE | CAP_NET, -1),
        ("bad-length", CAP_INTERACTIVE | CAP_NET, -1),
        ("bad-reserved", CAP_INTERACTIVE | CAP_NET, -1),
    ] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([CHILD, mode])
            .env(MOTOR_OS_CAPS_ENV_KEY, format!("0x{caps:x}"))
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(exit), "{mode}");
    }
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        // Bad config is a recoverable admission error and consumes no device.
        let config = super::ip_device_live::config(7);
        let (sender, mut receiver) = io_channel::connect("sys-io").unwrap();
        let page = sender.alloc_page(u64::MAX).await.unwrap();
        let length = config.encode(page.bytes_mut()).unwrap();
        page.bytes_mut()[8] = b'/';
        let page = IoPage::into_u16(page);
        let message = api::page_message(NetCmd::IpDeviceRegister, page, length).unwrap();
        sender.send_with_owned_page(message, page).await.unwrap();
        let reply = bounded_output(receiver.recv(), 2).await.unwrap().unwrap();
        assert_eq!(reply.status(), Err(moto_rt::Error::InvalidArgument));
        assert!(bounded_output(receiver.recv(), 2).await.unwrap().is_err());
        drop((sender, receiver));

        // Explicit unregister is terminal, even if another command is
        // queued behind it before the peer has observed channel closure.
        let (sender, mut receiver) = io_channel::connect("sys-io").unwrap();
        let page = sender.alloc_page(u64::MAX).await.unwrap();
        let length = config.encode(page.bytes_mut()).unwrap();
        let page = IoPage::into_u16(page);
        let register = api::page_message(NetCmd::IpDeviceRegister, page, length).unwrap();
        sender.send_with_owned_page(register, page).await.unwrap();
        assert_eq!(
            bounded_output(receiver.recv(), 2)
                .await
                .unwrap()
                .unwrap()
                .status(),
            Ok(())
        );
        let unregister = api::unregister_request();
        sender.send(unregister).await.unwrap();
        // A second unregister is also invalid after the first terminal command.
        let _ = sender.send(unregister).await;
        let reply = bounded_output(receiver.recv(), 2).await.unwrap().unwrap();
        assert_eq!(reply.command, NetCmd::IpDeviceUnregister.as_u16());
        assert_eq!(reply.status(), Ok(()));
        assert!(bounded_output(receiver.recv(), 2).await.unwrap().is_err());
        drop((sender, receiver));

        // Bad IP framing and packets above the registered MTU are ordinary
        // data drops. Valid IPC metadata must keep the channel alive.
        let (sender, mut receiver) = io_channel::connect("sys-io").unwrap();
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
        for (version, length) in [(0, 1), (0x45, 20), (0x60, 40), (0x45, 1421)] {
            let page = sender.alloc_page(u64::MAX).await.unwrap();
            let bytes = &mut page.bytes_mut()[..length];
            bytes.fill(0);
            bytes[0] = version;
            if version == 0x45 {
                let total: u16 = if length == 20 { 21 } else { length as u16 };
                bytes[2..4].copy_from_slice(&total.to_be_bytes());
            } else if version == 0x60 {
                bytes[5] = 1;
            }
            let page = IoPage::into_u16(page);
            sender
                .send_with_owned_page(
                    api::page_message(NetCmd::IpDevicePacket, page, length).unwrap(),
                    page,
                )
                .await
                .unwrap();
        }
        sender.send(api::unregister_request()).await.unwrap();
        let reply = bounded_output(receiver.recv(), 2).await.unwrap().unwrap();
        assert_eq!(reply.command, NetCmd::IpDeviceUnregister.as_u16());
        assert_eq!(reply.status(), Ok(()));
    });
    // Abandon registration after its first poll. Both a pending future and
    // an immediately completed owner must close their dedicated channel.
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        drop(IpDevice::register(&super::ip_device_live::config(6)).now_or_never());
        moto_sdk::async_runtime::yield_to_io().await;
    });
    crate::tcp::wait_for_sys_io_metric("net.num_devices", |n| n == baseline);
    moto_sdk::async_runtime::LocalRuntime::new().block_on(async {
        let device = bounded_output(IpDevice::register(&super::ip_device_live::config(6)), 2)
            .await
            .unwrap()
            .unwrap();
        bounded_output(device.unregister(), 2)
            .await
            .unwrap()
            .unwrap();
    });
    assert_eq!(
        crate::tcp::read_sys_io_metric("net.ip_device.malformed"),
        malformed + 4
    );
    crate::tcp::wait_for_sys_io_metric("net.num_devices", |n| n == baseline);
    println!("ip_device::test_admission_and_terminal_channel PASS");
}
