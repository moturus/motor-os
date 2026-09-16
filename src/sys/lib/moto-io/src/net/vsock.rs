//! Virtio-vsock discovery through a native networking channel.

use super::NetClient;

/// Query whether sys-io discovered a vsock device.
///
/// The caller must drive the client's [`super::NetDriver`]. This reserves no
/// socket and does not initialize the device, queues, or guest CID.
/// Returns [`moto_rt::Error::NotAllowed`] when the caller lacks CAP_VSOCK and
/// [`moto_rt::Error::NotFound`] when no device was discovered. Native errors
/// from capability lookup and channel operation are preserved.
pub async fn availability(client: &NetClient) -> Result<(), moto_rt::Error> {
    let response = client
        .rpc(moto_sys_io::api_vsock::availability_request())
        .await;
    moto_sys_io::api_vsock::availability_response(&response)
}
