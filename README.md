# Motor OS

[Motūrus](https://moturus.com) project (Motor OS) is a simple,
fast, and secure operating system built for the cloud.
Designed specifically for virtualized workloads such as web serving, serverless computing,
and edge caching, it addresses inefficiencies found in traditional operating systems
like Linux when running in virtual environments.

[Motor OS](https://motor-os.org) is built entirely in Rust. It supports x64 KVM-based virtual machines
and can run on Qemu, Cloud Hypervisor, or Alioth VMMs. The system, including
its libraries and syscalls, is implemented in Rust and optimized for Rust-based client applications.

## Why?

At the moment, most virtualized production workloads run Linux.
While Linux has many advanced features that in many
situations mean it is the only reasonable OS choice, there are
several complications that make it not ideal, in theory,
for some virtualized workloads:

* Linux is optimized for baremetal, which leads to inefficiencies
when it is used inside a VM that is running on a Linux host:
  * duplicate block caches
  * duplicate page table walks
  * the host scheduler can preempt the VCPU holding a spinlock in the VM's kernel
* Linux is difficult to use:
  * Docker, Nix OS, "serverless", etc. all exist because of Linux's complexity
* Linux has, historically, not been very secure

A new operating system built from ground-up with the focus
on virtualized workloads can be made much simpler and more
secure than Linux, while matching or exceeding its 
performance and/or efficiency.

## What?

Motor OS is a microkernel-based operating system, built in Rust, that targets virtualized workloads exclusively.
It currently supports x64 KVM-based virtual machines, and can run in Qemu, Cloud Hypervisor, or Alioth VMMs.

Rust is the language of Motor OS: not only it is implemented in Rust, it also exposes its ABI in Rust, not C.

### What works

Motor OS is under active development, and should not be used for sensitive workloads.
It is, however, ready for trials/experiments/research. In fact, Motor OS
[web site](https://motor-os.org) is served from inside a couple of Motor OS VMs (proxied via Cloudflare).</p>

More specifically, these things work:

* boots via MBR (Qemu) or PVH (Alioth, Cloud Hypervisor) in 100ms (Alioth) or 200ms (CHV, Qemu)
* himem micro-kernel
* scheduling:
  * a simple multi-processor round robin (SMP)
  * in-kernel scheduling is cooperative:
  * the kernel is very small and does not block, so does not need to be preemptible
  * the userspace is preemptible
* memory management:
  * only 4K pages at the moment
  * * stacks are guarded
  * * page faults in the userspace work and are properly handled (only stack memory allocations are currently lazy)
* I/O subsystem (in the userspace)
  * VirtIO-BLK and VirtIO-NET <a href="https://github.com/moturus/motor-os/tree/main/src/sys/lib/virtio">drivers</a>
  * two simple filesystems (<a href="https://crates.io/crates/srfs">srfs</a> and <a href="https://crates.io/crates/flatfs">flatfs</a>)
  * <a href="https://crates.io/crates/smoltcp">smoltcp</a>-based networking
    * max host-guest TCP throughput is about 10Gbps at the moment
* the userspace:
  * multiple processes, with preemption
  * threads, thread local storage
  * Rust's standard library mostly ported
    * Rust programs that use Rust standard library and do not depend, directly or indirectly, on Unix or Windows FFI,
      will cross-compile for Motor OS and run, subject to "what does not work" below
  * Tokio runtime and tokio/mio async TCP/UDP APIs are working
  * <a href="https://github.com/moturus/motor-os/tree/main/src/bin/russhd">SSH server</a>
  * a simple TLS-enabled <a href="https://github.com/moturus/motor-os/tree/main/src/bin/httpd">httpd</a> is provided
  * an axum/tokio-based TLS-enabled <a href="https://github.com/moturus/motor-os/tree/main/src/bin/httpd-axum">httpd-axum</a> s also provided
  * a simple <a href="https://github.com/moturus/rush">unix-like</a> shell in the serial console
  * a simple <a href="https://github.com/moturus/motor-os/tree/main/src/bin/kibim">text editor</a>
  * basic commands like free, ps, ls, top, cat, ss, etc. (do `ls bin` to list all commands)

### What does not work

Most pieces are not yet ready for production use. No security audit has been made.
More specifically:

* Filesystem: most Rust std::fs APIs have been implemented as proof-of-concept,
but are slow (synchronous) and will have to be reimplemented using Motor OS async I/O
* Networking:
  * DHCP not implemented: static IP addresses only at the moment
  * DNS lookup not implemented yet
  * UDP broadcast/multicast not implemented (yet?)
* The ecosystem outside Rust std:
  * "sans-io" crates and crates like rand or rustls can be compiled and used with minor tweaks
  * async Rust: Tokio is only partially ported, so most crates won't work without some refactoring
  * crates that are wrappers around native Linux or Windows APIs will not work, obviously

## How can I build/run it?

See [docs/build.md](docs/build.md).

## Examples and recipes

see [docs/recipes/index.md](docs/recipes/index.md).
