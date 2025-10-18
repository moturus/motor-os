# Changelog

All notable changes to this project will be documented in this file.

## 2025-10-17

Motor OS is now a [Tier-3 target in Rust](https://doc.rust-lang.org/nightly/rustc/platform-support/motor.html)!

## 2025-05-26

* Tokio process feature works (async child, async stdio);
* SSH server (russhd) works:
  * password and pubkey authentication
  * interactive shell
  * TODO: exec

## 2025-04-22

- UDP is working, excl. multicast/broadcst (both std::net and mio/tokio).

## 2025-04-08

- Tokio runtime and tokio/mio async TCP APIs are working.
- Motor OS rebased on top of Rust 2025-04-05 rustlang nightly version.

## 2025-02-17

Rust Motor OS target rebased onto Rust 2025-02-16 nightly version.
Two main changes:
- all Motor OS binaries are now position independent;
- rt.vdso is now using Motor OS target rather than a custom json target.

## 2025-01-20

Tokio Mio is more or less ported (excl UDP).

## 2024-11-12

The migration from moto-runtime to moto-rt/rt.vdso (see below) is complete.

## 2024-09-02

Motor OS Runtime Library
[moto-rt](https://github.com/moturus/motor-os/blob/9cdafd7309dc60ff73ccc5f1306bd5215b56b05b/src/sys/lib/moto-rt/src/lib.rs)
and [rt.vdso](https://github.com/moturus/motor-os/tree/9cdafd7309dc60ff73ccc5f1306bd5215b56b05b/src/sys/lib/rt.vdso)
are now "live" and already do memory allocations for Rust stdlib.

The plan is to move everything from moto-runtime into moto-rt/rt.vdso to make
Rust stdlib integration stable. And having a runtime VDSO object enables
a lot of interesting features on the OS side.

## 2024-07-06

Motor OS [web site](https://motor-os.org) is now served from inside
a couple of Motor OS VMs (proxied via Cloudflare).

## 2024-07-04

TLS/HTTPS serving implemented.

## 2024-06-30

`ss` command implemented.

## 2024-05-08

The serving side of TCP stack seems to be robust now: rnetbench
multithreaded host-guest test with the guest serving has been running
for a week now.

Throughput is also quite decent (about 10Gbps in alioth and CHV,
a bit less in qemu).

## 2024-04-30

`top` command implemented.

## 2024-04-13

The throughput of a single TCP stream is now about 300 MiB/sec
(an approximately ~20x improvement from what it was in January 2024).
