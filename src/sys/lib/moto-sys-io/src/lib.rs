//! IO subsystem (sys-io) API.

#![no_std]

pub mod api_fs;
pub mod api_net;
pub mod api_vsock;

#[cfg(feature = "std")]
pub mod icmp;

#[cfg(feature = "std")]
pub mod stats;
