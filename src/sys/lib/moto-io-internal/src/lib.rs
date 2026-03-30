//! Internal helper libraries for sys-io & vdso.
#![no_std]
#![feature(async_trait_bounds)]
#![feature(trait_alias)]

pub mod udp_queues;

extern crate alloc;
