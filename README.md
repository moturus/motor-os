# Motor OS

Motor OS is a simple, fast, and secure operating system built for the cloud.
It targets virtualized workloads such as web serving, serverless computing,
and edge caching, and avoids the overhead a general-purpose OS carries when
it runs inside a VM.

It is written entirely in Rust, from the kernel to the shell, and its system
interface is Rust, not C. It runs as an x86-64 KVM guest under QEMU, Cloud
Hypervisor, and Firecracker.

This README is a summary. The details are on the website,
[motor-os.org](https://motor-os.org): the architecture, the process model,
the filesystem, networking, terminals, the commands and programs, the
toolchains, and how to develop for Motor OS in Rust and in C/C++.

## Why

At the moment, most virtualized production workloads run Linux. Linux has
many advanced features that in many situations make it the only reasonable
choice, but several things make it less than ideal, in theory, for some
virtualized workloads:

* Linux is optimized for bare metal, which leads to duplicated work when it
  runs inside a VM on a Linux host: duplicate block caches, duplicate page
  table walks, and a host scheduler that can preempt a vCPU while it holds a
  spinlock in the guest kernel.
* Linux is difficult to use: Docker, NixOS, "serverless" platforms, and
  similar projects all exist because of Linux's complexity.
* Linux has, historically, not been very secure.

A new operating system built from the ground up with a focus on virtualized
workloads can be made much simpler and more secure than Linux, while matching
or exceeding its performance and efficiency.

What Motor OS does differently:

* **Only VirtIO.** Motor OS runs inside a VM, so it needs drivers for VirtIO
  block and network devices and nothing else.
* **A microkernel.** The kernel manages memory, threads, and IPC, and never
  blocks. Drivers, the filesystem, and the network stack are one userspace
  process; if that process dies, the machine halts with a clear log rather
  than limping on.
* **Rust all the way down.** Memory safety in the kernel, the runtime, and the
  services; a Rust system interface instead of a C one; no dynamic linking.
* **A small process model.** No `fork`, no signals, no pseudo-terminals, no
  users. Processes carry an immutable capability word, and three roles derived
  from it (System, Interactive, None) drive filesystem permissions.
* **Configuration is part of the image.** Services, networking, and
  permissions are declared in a few files and a declarative image policy.
* **Boot time matters.** Motor OS boots in about 200 ms.

## What

Motor OS is a microkernel-based operating system. The kernel, about 18,600
lines of `no_std` Rust with four syscalls, manages address spaces, threads,
scheduling, capabilities, and wait/wake objects. Everything else runs in
userspace: `sys-io` owns the VirtIO block and network devices, the journaling
filesystem (Motor FS), and the networking stack (moto-netstack); `sys-init`
starts services; `sys-tty` drives the serial console; `strobe` collects logs
and metrics; `dns-resolver` resolves names; `russhd` serves SSH. A per-process
runtime object, `rt.vdso`, implements the system interface that Rust's
standard library calls through the small `moto-rt` crate.

What works today:

* **Boot and kernel**: MBR (QEMU) or PVH (Cloud Hypervisor, Firecracker) boot
  in about 200 ms; cooperative in-kernel scheduling with preemptive userspace;
  SMP up to 16 vCPUs; guarded lazy stacks; admission control that keeps the
  machine out of physical memory exhaustion instead of an OOM killer.
* **I/O in userspace**: VirtIO block and network drivers with checksum and TSO
  offload; Motor FS with per-role permissions and advisory locks; moto-netstack
  with IPv4 and IPv6, DHCPv4, TCP with CUBIC, SACK, RACK-TLP, timestamps, and
  SYN cookies, UDP, and ICMP echo, at about 10 Gbps host-to-guest; a DNS
  resolver service.
* **Rust**: the standard library is ported (`x86_64-unknown-motor` is a Tier-3
  Rust target); Tokio and mio, rustls, hyper, axum, and russh work.
* **C and C++**: a C library (mlibc), the LLVM C++ runtime, and a Clang target
  for Motor OS; Rust is preferred, C and C++ are fully supported; Lua runs.
* **Programs**: the rush shell, the rmux terminal multiplexer, the red and
  kibim editors, an SSH server with SFTP, two static web servers with TLS,
  the usual commands (ls, ps, top, ss, ping, free, ...), and ripgrep.
* **A self-hosting developer image**: native Clang/LLVM, native rustc, and
  Lorry, a Cargo-compatible package builder designed for security-sensitive
  environments (offline builds; every dependency fetched once, checked, and
  approved before it is built), plus Gears, curl, mdbg, and the test suites.

## Status

Motor OS is beta quality. It is under active development, and in 2026 it went
through weeks of systematic review and hardening, of the networking stack
above all. Networking is considered ready for production use within its
supported feature set; the rest of the system is exercised daily by the full
test suite, by long soak runs, and by the website, which is served from Motor
OS VMs. There has been no independent security audit yet.

## Building, running, developing

See [docs/build.md](docs/build.md) for the current build instructions (the
way the toolchains are built is being reworked), [docs/tools.md](docs/tools.md)
for the VM scripts and the tools inside the VM, and
[docs/recipes/index.md](docs/recipes/index.md) for examples. The website
covers all of this in more detail, including the toolchains and Lorry.
