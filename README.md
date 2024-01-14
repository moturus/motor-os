# Motūrus OS

Motūrus project builds a simple, fast, and secure operating system (Motūrus OS) for the cloud.

In more specific terms, Motūrus OS (sometimes called Motor OS),
is a new operating system targeting virtual machine-based workloads such as web serving, "serverless", edge caching, etc.

[Screenshot](docs/screenshot.md)

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

Motūrus OS is a microkernel-based operating system, built in
Rust, that targets virtualized workloads exclusively. It
currently supports x64 KVM-based virtual machines, and can
run in either Qemu or Cloud Hypervisor.

Rust is _the_ language of Motūrus OS: not only it is
implemented in Rust, it also exposes its ABI in Rust, not C.

### What works

While at the moment most of the subsystems are working in only
POC/MVP mode, they **are** working, and you can run, say, a web
server.

More specifically, these things work:

* boots via MBR (Qemu) or PVH (Cloud Hypervisor) in about 200ms
* himem micro-kernel
* scheduling:
  * a simple multi-processor round robin (SMP)
  * in-kernel scheduling is cooperative
    * the kernel is very small and does not block, so does not need to be preemptible
  * the userspace is preemptible
* memory management:
  * only 4K pages at the moment
  * stacks are guarded
  * page faults in the userspace work and are properly handled (only stack memory allocations are currently lazy)
* I/O subsystem (in the userspace)
  * VirtIO-BLK and VirtIO-NET [drivers](https://github.com/moturus/motor-os/tree/main/src/lib/virtio)
  * two simple filesystems
  ([srfs](https://crates.io/crates/srfs) and
  [flatfs](https://crates.io/crates/flatfs))
  * [smoltcp](https://crates.io/crates/smoltcp)-based networking (TCP only at the moment)
    * a simple [httpd](https://github.com/moturus/motor-os/tree/main/src/bin/httpd) is provided
* the userspace:
  * multiple processes, with preemption
  * threads, TLS
  * Rust's standard library [mostly ported](https://github.com/moturus/rust/tree/moturus-2023-12-16)
    * Rust programs that use Rust standard library and do not
    depend, directly or indirectly, on Unix or Windows FFI,
    will cross-compile for Motūrus OS and run, subject to
    "what does not work" below
  * a simple [unix-like shell](https://github.com/moturus/rush) in the serial console
  * a simple [httpd](https://github.com/moturus/motor-os/tree/main/src/bin/httpd)
  * a simle [text editor](https://github.com/moturus/motor-os/tree/main/src/bin/kibim)

### What does not work

Most pieces are not yet ready for production use. No security
audit has been made. It is very easy to hit a "not implemented"
panic in sys-io (the userspace I/O subsystem).

More specifically:

* Filesystem: most Rust std::fs APIs have been implemented as 
  proof-of-concept, but are slow (synchronous) and will
  have to be reimplemented using Motūrus async I/O
* Networking:
  * std::net::TcpStream is mostly implemented, but there are
  todo! panics
  * other protocols are not implemented yet
  * performance can (and will) be better
* The ecosystem outside Rust std:
  * crates like rand or rustls can be compiled and used
    with minor tweaks
  * crates depending on async runtimes (e.g.
  [Tokio](https://tokio.rs/)) will not compile at the moment
    * [Tokio Mio](https://github.com/tokio-rs/mio) should be
    not too difficult to port
  * crates that are wrappers around native Linux or Windows APIs
    will not work, obviously

## How can I build/run it? 

See [docs/build.md](docs/build.md).

## Examples and recipes.

see [docs/recipes/index.md](docs/recipes/index.md).

## Thanks

Big thanks to Philipp Oppermann for his great [Writing an OS in Rust](https://os.phil-opp.com/) blog series - it has inspired a lot of people to experiment in this space.
