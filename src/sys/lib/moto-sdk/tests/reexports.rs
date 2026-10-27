//! `moto_sdk::rt` and `moto_sdk::sys`, present with `std` on Motor OS, are
//! the moto-rt and moto-sys that the SDK's own APIs use.
#![cfg(all(target_os = "motor", feature = "std"))]

use moto_sdk::{async_runtime, io, ipc, rt, sys};
use std::any::TypeId;
use std::rc::Rc;

#[test]
fn rt_and_sys_are_the_sdk_dependencies() {
    assert_eq!(TypeId::of::<rt::Error>(), TypeId::of::<moto_rt::Error>());
    assert_eq!(
        TypeId::of::<sys::SysHandle>(),
        TypeId::of::<moto_sys::SysHandle>()
    );

    // SDK signatures spelled with the re-exports: each coerces only if the
    // types are the same.
    let _: fn() -> rt::Result<Rc<io::fs::FsClient>> = io::fs::FsClient::connect;
    let _: fn(&str) -> rt::Result<(ipc::io_channel::Sender, ipc::io_channel::Receiver)> =
        ipc::io_channel::connect;
    let _: fn(ipc::sync::ChannelSize) -> Result<ipc::sync::ClientConnection, sys::ErrorCode> =
        ipc::sync::ClientConnection::new;
    let _: fn(sys::SysHandle) -> async_runtime::SysHandleFuture =
        async_runtime::SysHandleFuture::new_disarmed;
}
