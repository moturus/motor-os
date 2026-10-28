# WebAssembly on Motor OS

The developer image (`make dev.img BUILD=release`, producing
`motor-os-dev.qcow2`) includes Javy 9.1.0, Wasmi 1.1.0 and full and runtime-only
Wasmtime 50.0.0. Javy also uses v50 Wizer through its Wasmi backend. Javy compiles
JavaScript into a WebAssembly module containing the QuickJS runtime.
Wasmi interprets that module using the Motor OS port's WASI
Preview 1 support. Wasmtime compiles and executes native code in the same
process. Its runtime-only build loads compatible precompiled artifacts without
linking a compiler.

## Installed files

| Path | Contents |
| --- | --- |
| `/devtools/bin/javy` | JavaScript-to-WebAssembly compiler. |
| `/devtools/bin/wasmi` | WebAssembly interpreter and command runner. |
| `/devtools/javy/plugins/default.wasm` | Default QuickJS plugin for explicit plugin selection and dynamic modules; also embedded in Javy. |
| `/devtools/javy/sources.txt`, `SHA256SUMS` | Build provenance, source revisions, and staged-file checksums. |
| `/devtools/bin/wasmtime` | Native Wasmtime `run`, `serve` and `compile` commands with Cranelift. |
| `/devtools/bin/wasmtime-rt` | Runtime-only Wasmtime: precompiled native execution with WASI. |
| `/devtools/wasmtime/sources.txt`, `SHA256SUMS` | Wasmtime build provenance and checksums. |
| `/devtools/src/wasm/` | `hello.js` and a README with compile/run instructions. |
| `/devtools/www/wasm.html` | This guide in the image's HTML documentation. |

The smaller `wasm.img` also includes the four tools and their data
directories. The test inputs (the TypeScript workload, the Linux identity
digests, two custom Javy plugins and the precompiled Wasmtime fixtures) are
not installed;
`src/tests/test-wasm.sh` uploads them to `/none/wasm-tests` on every VM boot
during tests. The low-RAM qualification keeps these fixtures and retained
outputs on disk; the tools' None-role `TMPDIR` still uses memfs at `/none/tmp`.

Both Wasmtime CLIs run as role None (`MOTOR_OS_CAPS=0`, `0x100`, `0x200` or
`0x300`). Raw `run` needs no filesystem-write capability. `compile` needs
`0x200` to write its output. Loading a compiled artifact needs
`--allow-precompiled`; only load trusted artifacts from a matching build and
configuration. Native Motor artifacts are specific to Motor, and are not
interchangeable with Linux artifacts. Explicit `--target pulley64` selects
Pulley in either CLI.

Wasmtime and Wasmi use sparse lazy mappings for linear memory: only the pages
a guest touches use RAM. Wasmtime reserves the declared maximum up to the
addressable range: 4 GiB for memory32 and the kernel's 1 TiB allocation limit
for memory64. Growth within that reservation does not move or copy memory.
Wasmi retains its 4 GiB per-memory capacity. When RAM runs out, Motor OS
kills whichever process has a page fault refused (there is no OOM killer, see
[OOM handling](oom-handling.md)): the guest's runtime or another process. `-W
max-memory-size` and `-W max-memories` bound a Wasmtime guest as upstream.
Store limits use upstream defaults and explicit `-W max-instances`,
`-W max-tables` and `-W max-table-elements` overrides, with no Motor-only caps.
`-W timeout=DURATION` interrupts a guest compiled with epoch interruption.
Native code uses explicit bounds/trap checks because Motor has no Unix signal
handlers. The example and HTML documentation are part of `dev.img`.

Both Wasmtime CLIs run asynchronous calls, such as each `serve` request, on fiber
stacks that are lazy guarded mappings: a stack uses RAM only for the pages it
touches, and, as on Linux, their number is not limited. `serve` behaves as
upstream: up to 1,000 concurrent requests and connections by default
(`--max-concurrent-requests`, `--max-concurrent-connections`), no default
request deadline, no header-read or idle timeout, and exit on any accept
error. A request deadline needs `-W timeout` and an artifact compiled with
epoch interruption: a server with a timeout refuses artifacts compiled
without epochs, and a server without one refuses artifacts compiled with
them.

Outgoing HTTP and guest sockets use independent WASI grants. `run -S http`
enables HTTP imports; `serve` enables them automatically, including outgoing
requests. `-S inherit-network`, `tcp`, `udp` and `allow-ip-name-lookup` control
guest socket access. Turning those socket options off leaves outgoing HTTP
available when HTTP is enabled. Both paths require the process's `CAP_NET`
(`MOTOR_OS_CAPS=0x100`, optionally combined with filesystem write access).

WASI p3 remains experimental and is enabled by the build's
`component-model-async` feature, as upstream. `-S p3=n` disables its imports.

## Differences from Wasmtime on Linux

The tools are built from Motor OS branches of their upstream repositories:
`moturus/wasmtime` branch `motor-50.0.0`, `moturus/javy` branch `motor-9.1.0`
and `moturus/wasmi` branch `motor-1.1.0`. The main tree pins the Javy and
Wasmtime revisions in `src/build-scripts/external-sources.sh`; each fork's
`MOTOR.md` describes its port. The ports keep upstream behavior and defaults
wherever Motor's APIs allow: store limits, p3 enablement, HTTP concurrency and
deadlines, the TCP write budget and artifact versioning are all upstream's.
What differs is forced by the platform:

- Native code lives in executable mappings the runtime owns. The kernel maps
  fresh pages twice into the calling process, once read-execute and once
  read-write; Wasmtime copies the compiled code through the writable alias,
  unmaps it, and keeps the executable alias until the module is dropped. No
  mapping is ever writable and executable at once, and there is no in-place
  protection change, so Wasmtime's code-editing hook (`unpublish`) reports an
  error; the installed CLIs do not use it. Freshly compiled and deserialized
  code take the same path.
- Traps are explicit checks compiled into the native code, since Motor OS has
  no signal handlers. Module data is copied into linear memory at
  instantiation, with dense data segments coalesced at compile time, instead of
  mapping a copy-on-write image of the module.
- Linear memories and fiber stacks are the lazy mappings described above. A
  reservation never moves, so growth stays within the declared maximum or the
  address limit.
- WASI directory handles name paths below a preopen rather than open directory
  objects: a renamed directory is not followed, and a replacement under the
  same name is reached. Open files keep their native object. There are no
  symlinks, hard links or settable timestamps, and a guest writing to a
  standard output whose reader has gone does not see `EPIPE`.
- Sockets use sys-io directly. TCP keepalive is always on, with fixed 20 s
  probes and 15 retries: disabling it is reported as unsupported, and timing
  changes are accepted but read back as the fixed values. A TCP socket cannot
  bind a wildcard address to an ephemeral port or connect after an explicit
  bind, a wildcard UDP bind selects one local address, UDP has no buffer-size
  options, sending to a closed UDP receiver reports no error, and an accepted
  socket may report a larger buffer than its listener requested because sys-io
  rings only grow.
- Outgoing TLS trusts the system bundle `/system/cfg/ssl/ca-certificates.crt`
  instead of roots compiled into the binary. Clocks and randomness use Motor
  APIs.

## Run the example

In the developer VM's shell:

```sh
cd /devtools/src/wasm
MOTOR_OS_CAPS=0x200 /devtools/bin/javy build hello.js -o /none/tmp/hello.wasm
MOTOR_OS_CAPS=0 /devtools/bin/wasmi /none/tmp/hello.wasm
```

The same Wasm can run directly with Wasmtime, or be compiled once and loaded
by either Wasmtime CLI:

```sh
MOTOR_OS_CAPS=0 /devtools/bin/wasmtime run /none/tmp/hello.wasm
MOTOR_OS_CAPS=0x200 /devtools/bin/wasmtime compile /none/tmp/hello.wasm -o /none/tmp/hello.cwasm
MOTOR_OS_CAPS=0 /devtools/bin/wasmtime-rt run --allow-precompiled /none/tmp/hello.cwasm
```

`wasmtime serve handler.wasm` likewise compiles a WASI HTTP component and
serves it directly. There is no packaging step or separate runtime executable
to generate.

Expected output:

```text
Hello from WebAssembly on Motor OS!
{"squares":[1,4,9,16],"total":30}
```

The masks launch the tools with role None: `0x200` grants Javy filesystem
write access for its output, while Wasmi needs no capabilities for this example.
`/none/tmp` is writable by role None. The default plugin is embedded, and the
example runs offline. Edit `hello.js` and repeat the commands to try changes.

See [Building Motor OS](build.md) for image construction and the focused
installed-tool checks, and [capabilities](caps.md) for the masks.
