/*******************

This is a small runtime for stdlib I/O.

Q: Why do we need it? Rust claims it does not have a runtime by default.
A: "By default", the OS kernel provides I/O runtime. For example, when writing
   to a file, write() blocks until the operation is completed in some sense
   (there is flush() to make sure it indeed completes). But in Moturus OS,
   the kernel does not do I/O, a user-space process/driver (sys-io) does it;
   so there are two alternatives:

   1. the I/O of Moturus OS in the userspace can mimic the syncrhonous
      I/O of traditional OSes, where normal processes don't have runtime
      by default, and synchronous I/O is part of OS API/ABI.
      - Asynchronous I/O API/ABI will still have to be provided to enable Rust's
        async capabilities, as supporting Tokio is a must in Rust's "ecosystem".
   2. I/O API/ABI of Motorus OS in the userspace is asynchronous, and
      processes can either directly tap into it (e.g. by implementing event loops
      and such), or use an async runtime of their choice (provided it is ported
      to Moturus OS).
      - Rust's stdlib exposes synchronous I/O, so the stdlib's port to Moturus OS
        needs an async runtime to bridge with the async I/O API/ABI.

Pro of Option 1: ability to have a "no runtime" pure Rust programs.
Con of Option 1: both sync and async I/O API/ABI have to be provided/supported.

Pro of Option 2: a single async I/O API/ABI is provided/supported.
Con of Option 2: all Rust programs need a "runtime" do to I/O.

Given that Moturus OS targets VMs, with web servers, databases, etc. as main
use cases, option 2 has been chosen, as scalable web servers, databases, etc.
usually have "runtimes" anyway.

So what is a "runtime" in this context? Basically, one or more background
threads that keep I/O "flowing".

Why is it needed? Why not use Tokio, for example? Because Tokio cannot
be used as rustc-dep-of-std: it heavily depends on std and there are no plans
to make it no-std. So Rust programs that use std-provided I/O will use
this small runtime, which is lazily created on first use.

Rust programs that don't use std-provided I/O won't have the runtime
initialized/running at all.

This runtime is intentionally made very small and simple, to cover only stdlib needs.
In the future Tokio/Mio will be ported to Moturus OS, and maybe other
runtimes, so there are no plans to make this runtime more fully-functional.

********************/

/*
A typical async runtime has:
- tasks
- wakers
- I/O integration with the above (see MIO/token/poll/interest/etc.).
- a runtime that polls woken tasks

BUT: as this runtime is only ever used to wrap async I/O as part of
     sync I/O, all we need is block_on<F>(). So the runtime/executor
     is completely hidden, and only block_on<> is exposed.

     In the background, we do have a small (single-threaded) runtime
     that accepts wait handle registrations and wakes the registered
     waiters upon wait handle wakeups.

     So there are two wakeup categories:

     1. block_on() creates a wakeup for itself that it passes
        in the context to the future it polls
     2. futures waiting for their io_channel::ClientConnection
        register their connection wait_handles with the "runtime",
        and the runtime, upon receiving a wakeup on a wait_handle,
        then wake the waker passed with the registration, so that
        block_on() will then poll the future again.

    The futures themselves do not wake their servers, only the
    runtime does it (to minimize the number of wakeup syscalls).

*/

/*
Q: But why do we need a runtime at all? Why not use io_channel
   directly, without async/await fluff?
A: We need a runtime, because we share channels across multiple
   sockets (tcp streams), and server messages (e.g. reads) have
   to be routed to their appropriate destinations (sockets and
   threads that wait on them).

BUT, it seems that actually all of this is NOT needed for stdlib.
*/
