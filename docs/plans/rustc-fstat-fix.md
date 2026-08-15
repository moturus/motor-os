# Correct `fstat` for Motor descriptors and native toolchains

Designed 2026-08-08. Implementation authorized and completed locally on
2026-08-09; the changes remain uncommitted.

Inspected baseline: Motor OS `lorry` at `461412fb` (with `main` at
`5c9cea13`), mlibc `motor-os-rustc` at `df01b728`, and LLVM
`motor-os-rustc` at `88ea5aa2`. Recheck named call sites if those baselines
move before implementation.

Implementation followed the four-patch shape below. The adjacent header
version correction was approved: `MOTO_RT_VERSION` is now 17 and a build
script checks the Rust and C declarations mechanically. No RT ABI version or
`FileAttr` layout change was needed.

One additional bootstrap fact emerged during implementation. The staged native
LLVM executable contains static copies of both mlibc and
`libmoto_rt_cabi.a`. Rebuilding only the VDSO and mlibc sources is therefore
insufficient: the shim archive must be rebuilt and installed, and native LLVM
must then be relinked. Before that relink the stale shim dispatched through an
older runtime-vtable layout, so `moto_rt_fstat(0)` returned `-17`; after the
relink, the existing LLVM sources worked unchanged. This was a stale-artifact
failure, not a second LLVM defect.

The implementation also fixed a Lorry harness error discovered while
validating the result: both the native self-build and repository-integration
harnesses used the run script's default image, which is the deliberately
Lorry-free main image. They now build or verify, name, and record
`motor-os-dev.img` explicitly.

## Implementation outcome and follow-on findings

The `fstat` design solved the native linker failure it targeted. Linux-hosted
Lorry and curl compile for both Linux and Motor OS, captured non-PTY native
Clang works, native rustc links through `/bin/cc`, and Lorry can build itself
inside Motor OS. The final image reports FIFO for captured stdio, character
device for terminals, and socket for both VDSO and mlibc pseudo-sockets. No
LLVM source exception, forced PTY, `/dev/null` substitution, retry, or timeout
change was needed.

Two later failures initially looked like continuations of the linker problem
but were independent OS defects exposed only after native compilation advanced
farther:

1. **Native rustc could loop in directory iteration.** `ReadDir` prefetched the
   next Motor directory ID. If parallel compiler work removed that entry before
   the next lookup, `rt.vdso::readdir` returned an error without advancing its
   cursor. Rustc deliberately discards individual directory-entry errors, so
   it requested the same dead ID forever. The millions of matched wait/wake
   calls observed in the stuck process were completed filesystem RPCs, not an
   `rt::io_runtime` lost-wakeup race. The fix consumes the cursor before I/O,
   returns the lookup error once, and leaves the iterator exhausted. A
   deterministic systest removes the prefetched entry and asserts one error
   followed by EOF.
2. **The second native generation exposed a frame-slab full-boundary race.**
   Allocation claimed a bitmap bit before incrementing `used`. Preemption
   between the two at a full slab let another CPU observe all bits occupied
   while the counter still promised capacity, ending in `slab alloc looping
   (1)`. Allocation now reserves counter capacity before claiming a bit; free
   clears the bit before publishing returned capacity. The frame-churn systest
   repeatedly crosses that boundary under concurrency.
3. **curl exposed two TCP teardown gaps.** Process exit could destroy a
   per-process moto-io channel before its asynchronous driver delivered queued
   close records. Joining and draining live and recently retired channel
   runtimes fixes that lifetime boundary. Separately, a full graceful close
   could send FIN with an empty receive queue and then silently absorb later
   peer data because its receive half was already marked closed. With no
   reader, the peer filled the abandoned window and curl waited for sys-io's
   exact 60-second default linger. sys-io now resets on data in that state
   only for a full lingering close; `shutdown(Read)` retains its intentional
   half-close behavior. Process-exit and post-FIN-write systests cover both
   paths, and the selected 10-case curl gate fell from 61.57 s to 4.09 s.

These fixes do not broaden the `fstat` design. They are recorded here to keep
the causal chain explicit: descriptor metadata fixed the silent linker exit;
the directory cursor fixed the subsequent rustc nontermination; slab
reservation fixed the later second-generation kernel panic; and TCP teardown
fixed the successful curl gate's one-minute exit delay.

Post-fix validation completed locally on 2026-08-09 using the then-current,
since-retired multi-profile Lorry matrix. It included repeated native
self-builds, Red/Rush/curl downstream campaigns, both Motor image profiles,
second generations, isolated registry-cache campaigns, and the selected curl
cases (4.09 s after the TCP fix). It also included:

- one post-TCP-fix debug and one release `src/tests/full-test.sh` pass;
- direct release dev-image `lorry --help`, `curl --help`, `cc --help`, and
  `rustc --version` smokes; and
- `make -j16 BUILD=release dev.img` with the relinked native toolchain.

The workspace remains uncommitted at the user's request. The broader repeated
repository-gate counts in section 12.5 remain the pre-commit standard; the
targeted repeated native passes above specifically establish that the former
intermittent rustc hang is gone.

## 0. Decision summary

Implement `fstat` as an operation on every live Motor runtime descriptor, not
as a filesystem-only operation and not as a Clang exception.

The design has three coordinated parts:

1. Extend the existing `moto_rt::fs::FileAttr::file_type` value space with
   character-device, FIFO, socket, and anonymous-descriptor types. This changes
   neither the `FileAttr` layout nor its version.
2. Make every `rt.vdso::posix::PosixFile` implementation provide descriptor
   metadata. Give each non-filesystem open description a nonzero, per-process
   identity that is retained by `dup` and is not retained when an fd slot is
   closed and reused.
3. Teach Motor's mlibc port to translate the new types to `S_IFCHR`, `S_IFIFO`,
   and `S_IFSOCK`, and to synthesize `S_IFSOCK` for mlibc's own pre-materialized
   pseudo-socket descriptors.

The immediate result is that Clang can `fstat` the ordinary pipes rustc uses to
capture linker output. The larger result is a consistent rule: `EBADF` means
the descriptor is not live; it no longer means “this is a live descriptor kind
that the filesystem metadata path does not understand.”

Do not add `/dev/null`, restore the old process-wide terminal flag, force a PTY,
or patch Clang to ignore the error. Those approaches either discard compiler
diagnostics or reintroduce incorrect descriptor semantics.

No LLVM source change is required.

## 1. Problem statement

At the inspected baseline, Motor-native rustc failed while linking the
`crc32fast` build script:

```text
error: linking with `cc` failed: exit code: 1
error: rustc failed with status -1
```

There is no linker diagnostic because Clang exits before parsing its options.
Its driver entry calls `llvm::sys::Process::FixupStandardFileDescriptors()`.
That routine calls `fstat` on descriptors 0, 1, and 2. Rustc starts the linker
with stdout and stderr captured, so those descriptors are ordinary Motor stdio
pipes rather than terminal endpoints or motor-fs files.

The current path is:

```text
rustc
  -> std::process::Command(stdout=pipe, stderr=pipe)
  -> /bin/cc
  -> llvm clang
  -> FixupStandardFileDescriptors
  -> mlibc fstat(0/1/2)
  -> moto_rt_fstat
  -> moto_rt::fs::get_file_attr
  -> rt.vdso::rt_fs::get_file_attr
  -> downcast PosixFile to rt_fs::File
  -> E_BAD_HANDLE for SelfStdio
  -> EBADF
  -> LLVM assumes the fd is closed and tries open("/dev/null")
  -> /dev/null does not exist
  -> silent exit 1
```

The old branch appeared to work because two terminal-detection bugs masked this
gap. `russhd` marked even non-PTY sessions as terminals, and terminal status was
a process-wide inherited environment value. The linker therefore inherited a
false terminal claim for its captured pipes. mlibc's terminal-only fallback
synthesized a successful character-device `stat` for them.

Main corrected both bugs in `7ebbc5f2` (`russhd: track PTY geometry (size)`)
and `ebd3e0f1` (`moto-rt, vdso: fix is_terminal`). Non-PTY SSH is now
non-terminal, and terminal status is immutable per-descriptor metadata. That
exposed a residual explicitly recorded in
`docs/porting-libc/porting-libc-appendix-j.md`: terminal fds could `fstat`, but
piped standard fds could not.

This is not limited to rustc. The same VDSO downcast currently rejects live
`ChildStdio`, socket, poll-registry, child-process, and directory-stream
descriptors. The libc porting notes separately record the socket and directory
cases as known gaps.

## 2. Goals

The implementation must provide all of the following:

- `fstat(fd)` succeeds for every live descriptor in the VDSO descriptor table.
- A closed, never-allocated, negative, or otherwise invalid fd returns
  `E_BAD_HANDLE` at the Motor API and `EBADF` through mlibc.
- Non-terminal stdio pipes report FIFO, terminal-backed stdio reports character
  device, and null-backed stdio reports character device but remains
  non-terminal.
- TCP listeners, TCP streams, and UDP sockets report socket.
- `ReadDir` reports the metadata and identity of its motor-fs directory.
- Poll registries and child-process handles return valid anonymous-descriptor
  metadata rather than pretending to be files or returning `EBADF`.
- `dup` preserves object identity and metadata; closing and reusing the numeric
  fd does not preserve the old object's identity.
- Existing regular-file and directory metadata, timestamps, sizes,
  permissions, and motor-fs inode identity remain unchanged.
- The installed, old mlibc/Clang binary can start on the new VDSO, avoiding a
  bootstrap cycle.
- Rebuilt mlibc reports correct POSIX type bits for the new descriptor kinds.
- A failing compiler invocation still emits diagnostics through its captured
  stderr. Success must not depend on replacing stdout or stderr with a null
  stream.
- The normal main image and its full test continue to have no Lorry dependency.
- The exact Lorry native-self build that exposed the problem passes after the
  system fix.

## 3. Non-goals

This work does not:

- add a `/dev` filesystem or a pathname-addressable `/dev/null`;
- add general anonymous `pipe()` support to mlibc;
- implement Unix-domain sockets, `socketpair`, fd passing, or kernel PTYs;
- redesign mlibc's pseudo-socket table;
- add `dup` support for mlibc pseudo-sockets;
- make `lseek`, `fsync`, or every other filesystem-shaped operation meaningful
  on all descriptor kinds;
- change terminal detection or the terminal launch hint;
- change LLVM's `FixupStandardFileDescriptors`;
- promise cross-process inode equality for the two endpoints of a Motor stdio
  relay;
- fix the existing lifetime semantics of a motor-fs file unlinked while still
  open; or
- treat `FileAttr` mode bits as an authorization mechanism.

The distinction in the last item is important. Synthetic descriptors cannot be
opened by path, so their reported `st_mode` permissions are descriptive only.
Actual access remains controlled by possession of the descriptor and by its
object implementation.

## 4. Required invariants

### 4.1 Liveness

For the VDSO descriptor table:

```text
live fd     => get_file_attr returns metadata or a real backing-object error
invalid fd  => get_file_attr returns E_BAD_HANDLE
```

An unsupported live kind must never be represented as `E_BAD_HANDLE`. Adding a
new `PosixFile` implementation must require an explicit metadata decision at
compile time.

### 4.2 Identity

Within a process:

- two fds produced by `duplicate` for the same open description have the same
  synthetic identity;
- independently created synthetic objects have different identities while
  both are live;
- a newly created object in a reused numeric fd slot receives a new identity;
- identity zero means unknown and is never assigned to a synthetic object; and
- no address or kernel-handle value is exposed as an inode number.

The last rule avoids leaking process addresses and avoids relying on local
`SysHandle` encodings as stable public identity.

Motor implements inherited stdio by creating a new relay segment for the
child, not by installing the same descriptor object in another process. A
per-process identity for each segment therefore describes the objects the VDSO
actually exposes. This patch guarantees identity across `dup` in one process,
not across a spawn boundary.

### 4.3 Terminal and file type are independent

`is_terminal(fd)` continues to answer whether the peer provides terminal
behavior. `fstat(fd)` answers the POSIX object category.

- terminal `SelfStdio`: character device and `is_terminal == true`;
- null `SelfStdio`: character device and `is_terminal == false`;
- ordinary `SelfStdio`: FIFO and `is_terminal == false`;
- parent-side `ChildStdio`: FIFO and `is_terminal == false`.

No code may infer terminal status merely from `S_IFCHR`.

### 4.4 No hidden I/O for synthetic metadata

`fstat` on stdio, sockets, process handles, and poll registries is a descriptor
table lookup plus construction of a small value. It performs no IPC, network
operation, allocation, sleep, or filesystem query. Regular files and
`ReadDir` retain their existing motor-fs metadata query.

## 5. Metadata ABI

### 5.1 Extend values, not layout

Keep `moto_rt::fs::FileAttr` at version 2 and 96 bytes. Add values to the
existing `u8 file_type` namespace:

| Value | Rust constant | C constant | Meaning |
|---:|---|---|---|
| 0 | `FILETYPE_UNKNOWN` | `MOTO_FILETYPE_UNKNOWN` | unset or unknown; never emitted for a live implemented object |
| 1 | `FILETYPE_FILE` | `MOTO_FILETYPE_FILE` | motor-fs regular file; existing value |
| 2 | `FILETYPE_DIRECTORY` | `MOTO_FILETYPE_DIRECTORY` | motor-fs directory; existing value |
| 3 | `FILETYPE_CHARACTER_DEVICE` | `MOTO_FILETYPE_CHARACTER_DEVICE` | terminal- or null-like stream |
| 4 | `FILETYPE_FIFO` | `MOTO_FILETYPE_FIFO` | anonymous stdio pipe endpoint |
| 5 | `FILETYPE_SOCKET` | `MOTO_FILETYPE_SOCKET` | network socket |
| 6 | `FILETYPE_ANONYMOUS` | `MOTO_FILETYPE_ANONYMOUS` | valid non-POSIX object such as poll registry or process handle |

Adding numeric values is ABI-compatible: offsets, alignment, total size, and
the vtable entry all remain unchanged. Version 1 callers also receive
`file_type`, size, permissions, and timestamps because those fields predate
the v2 `entry_id`; they merely lack synthetic identity.

Do not add a new vtable function and do not grow `FileAttr` for this change.

### 5.2 Generalize `entry_id`

Update the field documentation without changing the field:

- for motor-fs objects, `entry_id` remains the full motor-fs entry ID;
- for synthetic VDSO objects, the low 64 bits hold the nonzero per-process
  open-description ID and the high 64 bits are zero;
- zero remains “identity unknown.”

mlibc continues to use only the low 64 bits for `st_ino`. The device namespace
separates motor-fs identities from synthetic identities.

### 5.3 Synthetic values

VDSO-generated synthetic `FileAttr` values are:

```text
version    = FileAttr::VERSION
size       = 0
perm       = 0
file_type  = descriptor-specific value
created    = 0
modified   = 0
accessed   = 0
entry_id   = nonzero open-description ID
```

`perm == 0` is deliberate: Motor's three permission bits describe motor-fs
path access and do not encode an open descriptor's read/write mode. mlibc sets
advisory private mode bits for unnameable synthetic objects as described below.

### 5.4 Runtime version

This extension does not require an RT ABI version bump. It changes neither the
vtable nor a structure layout, preserves values 1 and 2 for every filesystem
object, and only returns the added values for descriptor queries that currently
fail. The old mlibc translator embedded in the staged native LLVM is known to
treat every non-directory value as a regular file, which provides the bounded
bootstrap compatibility described in section 9.1. Do not generalize that fact
into a promise about arbitrary consumers of previously unassigned values.

There is an adjacent pre-existing inconsistency to resolve separately before
implementation: `moto_rt.h` currently defines `MOTO_RT_VERSION` as 16, while
`moto_rt::RT_VERSION` and `moto_rt_version()` are 17. Correcting that macro to
17 is recommended as a small prerequisite patch, but it is not part of the
`fstat` semantic change and must not be described as an ABI 18 bump.

## 6. VDSO descriptor identity

### 6.1 Replace placeholder entries

Change the descriptor table from a vector of `Arc<dyn PosixFile>` containing a
sentinel `Placeholder` to a vector of optional entries:

```text
DescriptorEntry
  object: Arc<dyn PosixFile>
  object_id: NonZeroU64

Descriptors
  entries: Vec<Option<DescriptorEntry>>
  freelist: Vec<RtFd>
  next_object_id: AtomicU64
```

This makes a free slot structurally absent. It prevents future generic
descriptor operations from accidentally treating `Placeholder` as a live
object merely because `get_file(fd)` returned `Some`.

The refactor must preserve the current lock discipline:

- reserve a free slot under the descriptor/freelist locks;
- install one complete entry before returning its fd;
- clone the entry while holding the table lock, then operate on the cloned
  `Arc` after dropping the lock;
- on close, take the entry and put the numeric fd on the freelist; and
- keep the existing `Arc::ptr_eq` last-close scan for the object kinds that opt
  into it.

No callback may run while the descriptor table lock is held.

### 6.2 Allocate IDs at open-description creation

`push_file(new_object)` allocates one relaxed-atomic ID, reserving zero. The
practical wrap boundary is unreachable; nevertheless, wrap to zero must fail
loudly rather than issue a duplicate live identity.

`posix_duplicate(fd)` clones the existing `DescriptorEntry` into a new slot.
It does not call the new-object path and therefore retains `object_id`.

The extra relaxed atomic operation occurs only when a descriptor object is
created. It adds no new boot task, filesystem operation, or network round trip.
The three initial stdio objects consume the first three IDs during the VDSO's
existing stdio initialization.

### 6.3 Accessors

Keep `get_file(fd)` for existing callers, implemented as a projection of the
entry. Add one crate-private accessor returning both the object and ID for
`get_file_attr` and `duplicate`.

Do not expose synthetic IDs through a new public API. They are observable only
through the existing metadata/`fstat` interfaces.

## 7. Per-kind VDSO behavior

Add a required method to `PosixFile`, conceptually:

```rust
fn descriptor_attr(&self, object_id: NonZeroU64)
    -> Result<moto_rt::fs::FileAttr, moto_rt::ErrorCode>;
```

It has no default implementation. This is intentional: a future descriptor
kind must choose its `fstat` semantics before it compiles.

Use one small helper for allocation-free synthetic attributes. Filesystem
objects override the helper with their real metadata query.

| `PosixKind` | `FileAttr.file_type` | Identity source | Notes |
|---|---|---|---|
| `ChildProcess` | `ANONYMOUS` | descriptor entry | analogous to an anonymous process/event handle; no standard `S_IF*` category |
| `ChildStdio` | `FIFO` | descriptor entry | provider-side endpoint is still an ordinary pipe, never a terminal |
| `File` | existing file/directory type | motor-fs entry ID | current metadata query and all fields unchanged |
| `PollRegistry` | `ANONYMOUS` | descriptor entry | analogous to Linux anonymous-inode polling objects |
| `ReadDir` | `DIRECTORY` | motor-fs entry ID | query metadata using the stored directory entry ID |
| `SelfStdio`, terminal | `CHARACTER_DEVICE` | descriptor entry | `is_terminal` remains true |
| `SelfStdio`, null | `CHARACTER_DEVICE` | descriptor entry | `is_terminal` remains false |
| `SelfStdio`, ordinary | `FIFO` | descriptor entry | includes non-PTY SSH and rustc-captured linker streams |
| `TcpListener` | `SOCKET` | descriptor entry | no network query |
| `TcpStream` | `SOCKET` | descriptor entry | no network query |
| `UdpSocket` | `SOCKET` | descriptor entry | no network query |

### 7.1 Preserve null-stream origin

`SelfStdio` currently remembers the terminal bit but not whether its
`StdioPipe::new_empty()` came from `STDIO_NULL`. Extend construction to retain
an immutable `null` bit derived from `StdioData.pipe_addr == 0`.

Assert that a null endpoint is not terminal. This patch must leave the current
empty-pipe I/O behavior unchanged; it makes only the endpoint's origin and
metadata explicit. In particular, the metadata test must not be used to change
or bless the return values of reads and writes on `Stdio::null()`.

Inspection found an adjacent pre-existing issue: `StdioPipe::new_empty()` is
always constructed with `is_reader == false`; its blocking write returns
`Ok(0)`, while a blocking read returns `E_INVALID_ARGUMENT` rather than EOF.
Those are not conventional `/dev/null` semantics. Fixing them is independent
of the native-linker failure and is excluded pending the review question in
section 17.

Do not infer null from a failed handle lookup at `fstat` time. Origin metadata
must be established once during stdio construction, as terminal metadata is.

### 7.2 Route `get_file_attr` polymorphically

Replace `rt_fs::get_file_attr`'s downcast-to-`File` with:

1. resolve the complete descriptor entry;
2. return `E_BAD_HANDLE` only if no live entry exists;
3. call the object's required `descriptor_attr` method; and
4. write the result with the existing version-aware `write_file_attr` helper.

This keeps compatibility with v1 callers and makes the single VDSO entry work
for every descriptor kind.

### 7.3 Files and directory streams

`File::descriptor_attr` performs exactly the current
`AsyncFsClient::metadata(file.entry_id)` query.

`ReadDir::descriptor_attr` performs the same query for `dir_id`. This resolves
the metadata half of the documented directory-fd gap. Do not claim that it
implements all of `fdopendir`, `rewinddir`, or directory-relative lookup; those
have separate open/seek semantics.

If a backing motor-fs metadata query returns a real error, propagate that error.
Do not convert it to `E_BAD_HANDLE` and do not synthesize filesystem metadata.

## 8. mlibc translation

The Motor mlibc port is statically linked into the native LLVM multicall, so
the source change belongs in the sibling mlibc repository and the final LLVM
binary must be relinked.

### 8.1 Translate all declared types

Refactor `attr_to_stat` to validate `file_type` and return an errno on an
unknown value. Preserve regular file and directory behavior exactly.

Use the following mapping for VDSO attributes:

| Motor type | `st_dev` | `st_ino` | `st_mode` type | Other fixed fields |
|---|---:|---:|---|---|
| file | 1 | motor-fs block number + 1 | `S_IFREG` plus existing mapped permissions | current size, blocks, timestamps |
| directory | 1 | motor-fs block number + 1 | `S_IFDIR` plus existing mapped permissions/traverse bit | current size/timestamps behavior |
| character device | 2 | synthetic object ID | `S_IFCHR | 0600` | size/blocks/timestamps zero, nlink 1 |
| FIFO | 2 | synthetic object ID | `S_IFIFO | 0600` | size/blocks/timestamps zero, nlink 1 |
| socket | 2 | synthetic object ID | `S_IFSOCK | 0600` | size/blocks/timestamps zero, nlink 1 |
| anonymous | 2 | synthetic object ID | `0600`, with no `S_IFMT` bits | size/blocks/timestamps zero, nlink 1 |

`st_blksize` remains 4096 for consistency with the existing translation.
`st_rdev`, uid, and gid remain zero. Synthetic permissions are advisory and
private because these objects are unnameable; they are not derived from
Motor's path permission bits.

Use `st_dev == 2` as one VDSO-synthetic namespace. IDs are globally unique
among live synthetic entries in the process, so different kinds do not need
different device numbers.

An unknown future Motor `file_type` should return `EIO` rather than silently
claiming `S_IFREG`. That is an ABI incompatibility/corruption signal, not an
invalid fd.

### 8.2 Remove the terminal-only fallback

Once `moto_rt_fstat` returns a character-device `FileAttr` for terminals,
delete mlibc's error-path special case that calls `moto_rt_is_terminal` and
synthesizes `S_IFCHR | 0620`.

There must be one metadata source. Keeping both paths would allow their device,
inode, and mode values to diverge and could hide a future VDSO regression.
`moto_rt_is_terminal` remains in use for `isatty`; only its role in `fstat` is
removed.

Changing the advisory terminal mode from the old fallback's 0620 to the common
synthetic mode 0600 is deliberate. Motor has no uid/gid permission model for
these unnameable endpoints, and terminal capability is expressed by
`is_terminal`, not group mode bits.

### 8.3 Handle mlibc pseudo-sockets before the VDSO

Fresh BSD sockets returned by Motor mlibc live in mlibc's pseudo-fd table at
`MOTOR_PSEUDO_FD_BASE`; the VDSO cannot see them until bind/connect/listen
materializes a real Motor socket. `fstat(socket(...))` must nevertheless return
`S_IFSOCK` without materializing the socket.

Add a narrow helper beside `motor_sock_close`, conceptually:

```text
motor_sock_fstat(fd, stat*)
  -1       fd is not in the pseudo-socket namespace; ask the VDSO
   0       live pseudo-socket; stat filled as S_IFSOCK
   errno   pseudo namespace but dead/invalid slot
```

The helper holds the pseudo-socket lock only long enough to validate and read
the slot. It performs no bind, connect, allocation, or I/O. Its identity is the
live table slot plus one in a separate `st_dev == 3` namespace. Slot identity
may be reused after close, just as a filesystem inode number may be reused
after deletion.

Intercept both direct fd-stat and `AT_EMPTY_PATH` fd-stat forms. Path-based
`stat` continues directly to the VDSO. A materialized pseudo-socket retains its
pseudo identity because that is the application-visible open description; an
accepted socket, which mlibc exposes as a real VDSO fd, uses the VDSO socket
metadata instead.

Do not call `motor_sock_realfd` from `fstat`: that helper auto-binds UDP and
would make a metadata query mutate socket state.

## 9. Bootstrap and compatibility

The rollout must avoid requiring the broken native linker to build its own fix.

### 9.1 New VDSO with old mlibc

The currently staged mlibc translation treats every non-directory type as a
regular file. Therefore, when the new VDSO returns FIFO metadata to the old
native LLVM binary:

- `fstat` returns success;
- old mlibc temporarily reports `S_IFREG` for the pipe;
- Clang's standard-fd startup check succeeds; and
- the compiler can run and emit output through the unchanged pipe.

This transitional type lie is already the old mlibc behavior for unknown
values, but it is bounded to the bootstrap image. It is preferable to a new
VDSO entry or layout because it lets the existing cross-built native LLVM run
immediately. The final staged image must contain rebuilt mlibc and report the
correct types.

### 9.2 Rebuild order

Use the existing host-driven `src/build-motor-os.sh` stages:

1. build the updated Motor C-ABI shim/header from the host;
2. rebuild and install mlibc into the Motor sysroot;
3. relink the native LLVM multicall against the new static `libc.a`;
4. stage the updated header, archives, and multicall in
   `img_files/generated/llvm`;
5. rebuild/stage native rustc and the final shim as the script already does;
6. clear compiler-sensitive Cargo caches as the script already requires;
7. rebuild the OS image; and
8. build `dev.img` for the Lorry-specific gate.

The native LLVM link must be forced even if Ninja sees no LLVM source change,
because CMake's standard-library flags do not make the sysroot archives tracked
link dependencies. The existing script already removes
`build-motor-native/bin/llvm` for this reason; retain and verify that behavior.

Generated toolchain and image roots remain build artifacts and are not
committed.

### 9.3 No LLVM patch

Do not conditionalize `FixupStandardFileDescriptors` for Motor. It is a useful
conformance probe, and other native programs legitimately expect `fstat` on
stdio to work. The correct OS/libc metadata implementation fixes all such
programs at once.

## 10. Alternatives rejected

### 10.1 Add `/dev/null` only

Rejected. LLVM reaches `/dev/null` only after it has mistaken a live pipe for a
closed descriptor. Replacing captured stdout/stderr with a null device would
discard diagnostics and linker output. It would turn a visible failure into
silent incorrect behavior.

A pathname-addressable null device may be useful future work for general POSIX
compatibility, but it is neither necessary nor sufficient here.

### 10.2 Treat fd 0–2 as character devices unconditionally

Rejected. It would make non-terminal pipes look like terminals or character
devices, repeat the old process-wide mistake, and make genuinely invalid
standard descriptors impossible to detect. It also would not fix sockets,
directory streams, or descriptors above 2 produced by `dup`.

### 10.3 Broaden mlibc's terminal fallback to any stdio fd

Rejected. mlibc has no reliable way to distinguish a live non-file descriptor
from an invalid fd using the current failing API. The VDSO owns the descriptor
table and must answer liveness and kind.

### 10.4 Force `ssh -tt` in the test harness

Rejected. Rustc captures its linker child's stdout/stderr even when rustc itself
has a terminal. The nested linker pipes remain non-terminal. Forcing a PTY also
changes behavior under test and would regress binary-clean SSH use.

### 10.5 Restore inherited terminal environment state

Rejected. It breaks the descriptor-specific terminal design in `docs/tui.md`,
causes redirected and piped descendants to report false terminal status, and
reopens an already fixed correctness issue.

### 10.6 Return regular-file metadata for every live descriptor

Rejected as the final design. It is enough to get Clang past startup, but it
breaks `S_ISFIFO`, `S_ISSOCK`, same-object detection, and future software that
branches on descriptor type. It is tolerated only as the behavior of the old
mlibc binary during the bootstrap transition.

### 10.7 Add a new `fd_kind` VDSO call

Rejected. `FileAttr` already contains a versioned type and identity carrier,
and `fs_get_file_attr` is already the native and C `fstat` path. A second query
would create two sources of truth and require more ABI/version choreography.

### 10.8 Use pointer or handle values as inode numbers

Rejected. Pointers leak address information; `SysHandle` values are local
implementation details and are not a documented stable identity. A small
per-process counter is simpler and safer.

## 11. Implementation patches

Keep implementation changes reviewable and do not combine them with unrelated
Lorry fixes.

### Patch 0: resolve the header version mismatch separately

Subject to explicit review, change `MOTO_RT_VERSION` in `moto_rt.h` from 16 to
17. Add `src/sys/lib/moto-rt-cabi/build.rs`, using only the host standard
library, to read the anchored version declarations in `moto_rt.h` and
`../moto-rt/src/lib.rs`, parse their integer values, and fail clearly if they
differ or either declaration is missing. Emit `cargo:rerun-if-changed` for both
files. Do not generate the public header, add a build dependency, or call this
ABI 18.

The public-C fixture added in Patch 4 also asserts that the linked
`moto_rt_version()` equals its compiled `MOTO_RT_VERSION`. The build check
guards the sources; the runtime check guards the installed header and archive.

### Patch 1: descriptor-table identity refactor

Files expected:

- `src/sys/lib/rt.vdso/src/posix.rs`

Replace placeholder entries with optional `DescriptorEntry` values and add
new-object versus duplicate insertion paths. Preserve all existing public
behavior in this patch; metadata still uses the filesystem-only path. Exercise
open, duplicate, close, last-close, freelist reuse, and invalid descriptors
through existing tests, adding focused tests if those transitions are not
already covered.

This isolates the highest-risk lifetime/locking change from the metadata
semantics. It must fit the normal small-patch preference and pass the existing
systest suite before the next patch.

### Patch 2: VDSO descriptor metadata and focused system tests

Files expected:

- `src/sys/lib/moto-rt/src/fs.rs`
- `src/sys/lib/moto-rt-cabi/moto_rt.h`
- `src/sys/lib/rt.vdso/src/posix.rs`
- `src/sys/lib/rt.vdso/src/rt_fs.rs`
- `src/sys/lib/rt.vdso/src/proc_fd.rs`
- `src/sys/lib/rt.vdso/src/runtime.rs`
- `src/sys/lib/rt.vdso/src/net/rt_tcp.rs`
- `src/sys/lib/rt.vdso/src/net/rt_udp.rs`
- `src/sys/lib/rt.vdso/src/stdio.rs`
- `src/sys/tests/systest/src/` test dispatch and a focused metadata module

Work:

1. add type constants and generalize `entry_id` documentation;
2. require and implement `descriptor_attr` for every current kind;
3. retain null origin in `SelfStdio`;
4. make `rt_fs::get_file_attr` polymorphic; and
5. add the direct Motor API regression matrix in systest.

The required-trait edit is compile-atomic: do not split it by adding a
permissive default that would temporarily restore the “unknown live kind is
EBADF” failure mode.

This patch alone should make the old staged `cc --version` and native rustc
link path start working, although old mlibc reports new kinds as regular files.

### Patch 3: mlibc type translation and pseudo-socket metadata

In the sibling mlibc repository:

- update the Motor `Stat` translation for all declared types;
- remove the terminal-only fallback;
- add the no-side-effect pseudo-socket stat helper;
- reject unknown future types with `EIO`; and
- add any host-buildable helper tests available in that repository.

Keep the pseudo-socket change in the same mlibc patch because otherwise the
new contract would still return `EBADF` for a standard libc `socket()` result.

No LLVM source file changes.

### Patch 4: native acceptance fixture and documentation

Add a small tracked `src/sys/tests/native-fstat.c` fixture and have
`src/build-motor-os.sh` copy it beside the existing native toolchain sample
sources. The fixture must test mlibc's public `fstat`, not call Motor APIs
directly. The sole direct-shim call is the Patch 0 version-consistency
assertion, if that adjacent fix is approved.

Wire a short native-toolchain section into `src/tests/full-test.sh` against the
already running main-image VM. It must compile the fixture through `/bin/cc`
over non-PTY SSH, run it in both non-PTY and forced-PTY modes, and verify that
an intentionally invalid `cc` invocation returns a visible diagnostic.

Update the known-gap records in:

- `docs/porting-libc/porting-libc-appendix-e.md`;
- `docs/porting-libc/porting-libc-appendix-g.md`;
- `docs/porting-libc/porting-libc-appendix-h.md`;
- `docs/porting-libc/porting-libc-appendix-j.md`; and
- `docs/build-llvm.md` if its verification commands change.

Be precise: mark piped stdio, real sockets, pseudo-sockets, and `ReadDir`
metadata resolved, but do not claim unrelated `fdopendir`, directory seek, or
`/dev/null` support.

## 12. Test design

### 12.1 Direct Motor/VDSO tests

Add a focused systest group, runnable by itself and transitively by the normal
full suite. It should cover:

| Case | Expected result |
|---|---|
| current non-PTY stdin/stdout/stderr | success, `FIFO`, distinct nonzero identities |
| child with explicitly piped stdio | parent `ChildStdio` and child `SelfStdio` report `FIFO` |
| child spawned with terminal hint | child streams report `CHARACTER_DEVICE` and terminal |
| child spawned with `Stdio::null` | child stream reports `CHARACTER_DEVICE` and non-terminal; I/O behavior is not changed or asserted |
| regular file | existing type, size, permission, timestamp, and entry ID behavior |
| `ReadDir` | `DIRECTORY` and underlying directory entry ID |
| UDP socket | `SOCKET` without sending or binding beyond constructor requirements |
| TCP stream/listener where a loopback pair is already available | `SOCKET` |
| poll registry | `ANONYMOUS` |
| live child-process fd | `ANONYMOUS` |
| `duplicate(fd)` | same type and `entry_id` as source |
| two independently created synthetic objects | different nonzero `entry_id`s |
| closed fd | `E_BAD_HANDLE` |
| reused numeric fd | new identity, never the closed object's identity |
| negative and very large fd | `E_BAD_HANDLE`, no panic |

Tests must not use sleeps, retries, the Internet, or timing assumptions.
Existing loopback helpers may be reused for socket construction.

If obtaining every internal descriptor kind from public systest APIs would
require a test-only production API, rely on the required trait method for
compile-time coverage and test the publicly constructible representatives. Do
not add a permanent descriptor-construction backdoor solely for tests.

Test a null descriptor one stream at a time. Report the result over another
piped stream, or encode it in the helper's exit status, so the test does not
depend on I/O through the null descriptor it is examining.

### 12.2 C/mlibc fixture

The C fixture should have two modes.

Non-PTY mode asserts:

- `fstat(0)`, `fstat(1)`, and `fstat(2)` succeed;
- all three are `S_ISFIFO`;
- `isatty` remains false;
- their inode values are nonzero;
- `fstat(-1)` fails with `EBADF`;
- a fresh, unmaterialized TCP pseudo-socket is `S_ISSOCK`;
- a fresh UDP pseudo-socket is `S_ISSOCK`, after which an explicit
  `bind(loopback, port 0)` still succeeds, proving `fstat` did not auto-bind it;
  and
- closing a pseudo-socket makes its later `fstat` fail with `EBADF`.

Forced-PTY mode asserts that standard descriptors are `S_ISCHR` and
`isatty` is true. It must not assume exact permission bits beyond the design's
type contract unless the test is specifically guarding the chosen 0600 mode.

The fixture prints one unambiguous final `PASS` line and returns nonzero at the
first failed invariant.

### 12.3 Native compiler regressions

Against a non-PTY SSH session:

1. `/bin/cc --version` exits zero and prints the version.
2. `/bin/cc` compiles and links the C fixture while its output is captured.
3. The compiled fixture passes.
4. `/bin/cc --definitely-invalid-motor-test-option` exits nonzero and its
   captured output contains a Clang error. This proves stdout/stderr were not
   replaced with a null stream.
5. Native rustc compiles and links the existing tiny Rust sample through the
   default `/bin/cc`, and the resulting executable runs.

The full suite may use the C compile as its short recurring regression. The
native-rustc sample is appropriate for the focused implementation gate if its
runtime would materially lengthen every normal full test; the direct captured
`cc` test already exercises the failing descriptor shape. Record the measured
cost before deciding whether to make native rustc recurring.

### 12.4 Lorry regression

After rebuilding the dev image and without a PTY:

```sh
cd src/bin/lorry
./tests/test-native.sh
```

The first native link was the original regression and remains its focused
guard. The release checks must retain the existing Linux-to-Motor versus
Motor-native byte identity assertions. Do not weaken, retry, or extend the
harness timeout.

Before final handoff, run `./tests/test-all.sh` if no independent failure
remains.

### 12.5 Repository gates

Because the implementation changes a shared system library, VDSO, C shim,
image toolchain, and repository test harness, the broad root gate applies:

1. `cargo +nightly fmt` for all changed Rust code;
2. no new compiler or clippy warnings;
3. `make -j$(nproc)`;
4. `make -j$(nproc) BUILD=release`;
5. three clean `src/tests/full-test.sh` debug passes;
6. three clean `src/tests/full-test.sh --release` passes;
7. `make -j$(nproc) BUILD=release dev.img`;
8. the bounded Lorry suite above; and
9. simple non-PTY `/bin/cc --help`, native `rustc` sample, `lorry --help`, and
   `curl --help` VM smokes.

Do not add retries, ignored errors, relaxed assertions, or longer timeouts.

## 13. Failure diagnostics and observability

The acceptance harness must preserve the command, exit status, stdout, and
stderr for a failed native compiler invocation. A recurrence of the original
silent exit should report at least:

- whether the VM session was PTY or non-PTY;
- `fstat` type results for descriptors 0, 1, and 2 from the C fixture;
- `/bin/cc --version` status and output; and
- the native rustc/cc command that failed.

Do not add permanent logging to every `fstat`; it is a hot compatibility API
and successful calls need no log output. The test fixture is the diagnostic
probe.

## 14. Security and performance review

### Security

- No pointer or raw handle is exposed through `st_ino`.
- Invalid fds still fail; the fix does not turn arbitrary integers into live
  descriptors.
- Pseudo-socket stat validates table liveness under its existing lock.
- Metadata queries do not materialize, connect, bind, or otherwise mutate a
  socket.
- File permissions remain sourced from motor-fs; synthetic mode bits do not
  grant access.
- No environment variable is reintroduced as live terminal state.

### Performance and boot time

- One relaxed atomic increment is added per newly created descriptor object,
  not per I/O operation.
- `dup` performs no increment.
- Synthetic `fstat` is allocation-free and does no IPC.
- Regular file `fstat` keeps its existing metadata query cost.
- No new boot task or scan is introduced; stdio initialization performs only
  the three counter increments associated with its existing three inserts.

Measure neither throughput nor boot latency unless implementation deviates
from this shape. Any added IPC, filesystem lookup for synthetic objects, or
boot-time enumeration requires renewed review.

## 15. Risks and mitigations

| Risk | Mitigation |
|---|---|
| old mlibc treats new values as regular files | bounded bootstrap behavior; final image must rebuild/relink mlibc and LLVM; C fixture asserts final types |
| descriptor-table refactor changes close/reuse behavior | retain lock order and last-close scan; add close/reuse and duplicate identity tests |
| a future `PosixFile` silently lacks metadata | required trait method with no default |
| null stdio is confused with an ordinary empty pipe | retain immutable null origin at construction and test it separately |
| pseudo-socket `fstat` auto-binds UDP | dedicated non-mutating table helper; never call `motor_sock_realfd` |
| synthetic objects collide with motor-fs inode identities | distinct `st_dev` namespaces |
| native compiler appears fixed by losing stderr | intentional invalid-option test requires visible diagnostic |
| stale static `libc.a` remains embedded in LLVM | force native LLVM relink and inspect/stage the resulting binary |
| docs overclaim fdopendir or `/dev/null` | update only the resolved metadata gaps and retain explicit non-goals |

## 16. Completion criteria

The work is complete only when all statements below are true:

- The VDSO returns metadata for every current live `PosixKind` and returns
  `E_BAD_HANDLE` only for invalid descriptor entries.
- The descriptor table has no live placeholder sentinel.
- Synthetic identity is nonzero, stable across `dup`, distinct for concurrent
  independent objects, and refreshed on fd reuse.
- New and v1 `FileAttr` callers are memory-safe without an ABI layout change.
- Final mlibc reports FIFO for captured stdio, character device for terminal
  and null stdio, and socket for both real and pseudo sockets.
- A pseudo-socket metadata query has no bind/connect side effect.
- The terminal-only mlibc `fstat` fallback is removed.
- Non-PTY `cc --version`, captured successful compilation, and captured
  failing compilation with diagnostics all behave correctly.
- Native rustc links a program through `/bin/cc`.
- Lorry self-builds natively in debug and release, including the release
  identity check and second generation.
- Main debug/release builds and the required repeated full suites pass.
- The main full suite remains independent of Lorry, curl, and gears.
- No implementation depends on `/dev/null`, a PTY, terminal-environment
  inheritance, retries, or timeout changes.

## 17. Resolved review questions

The user approved implementation on 2026-08-09.

1. The stale C-header version was corrected to 17 and mechanically guarded,
   without an ABI 18 bump.
2. The nonstandard `StdioPipe::new_empty()` read/write behavior remains out of
   scope. This change records null origin only so `fstat` can distinguish it
   from an ordinary pipe.

The implementation did not require any further semantic departure from this
design.
