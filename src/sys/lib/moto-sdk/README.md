# Motor OS userspace SDK

The userspace SDK for [Motor OS](https://github.com/moturus/motor-os) services
and applications: IPC, async I/O, networking, filesystems, logging and metrics.

Applications depend on `moto-sdk = "0.2"`. On Motor OS, the default `std`
feature provides `moto_sdk::rt` and `moto_sdk::sys` re-exports of the runtime
and system crates used by the SDK. A subset of the filesystem and buffer
APIs is also available on Unix for host tools and tests.

Version 0.2 requires `moto-sys 0.4` and the matching current Motor OS kernel
and sys-io service. It includes the new free-page API, IP-device support and
TCP protocol-state statistics. Code using the old system admission APIs
must migrate to the free-page API.
