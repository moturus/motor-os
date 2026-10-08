# WebAssembly on Motor OS

The developer image (`make dev.img BUILD=release`, producing
`motor-os-dev.qcow2`) includes Javy 9.1.0, Wasmi 1.1.0 and a runtime-only
Wasmtime 48.0.1. Javy compiles JavaScript into a WebAssembly module containing
the QuickJS runtime. Wasmi interprets that module using the Motor port's WASI
Preview 1 support. The runtime-only Wasmtime executes precompiled Pulley
artifacts; it contains no compiler, and on-Motor compilation is not installed
yet.

## Installed files

| Path | Contents |
| --- | --- |
| `/devtools/bin/javy` | JavaScript-to-WebAssembly compiler. |
| `/devtools/bin/wasmi` | WebAssembly interpreter and command runner. |
| `/devtools/cfg/javy/plugin.wasm` | Default QuickJS plugin for explicit plugin selection and dynamic modules; also embedded in Javy. |
| `/devtools/cfg/javy/typescript-workload.js` | TypeScript 5.9.3 plus a transpilation test workload. |
| `/devtools/cfg/javy/typescript-LICENSE.txt`, `typescript-NOTICES.txt` | License and third-party notices for the bundled TypeScript code. |
| `/devtools/cfg/javy/sources.txt`, `SHA256SUMS` | Build provenance, source revisions, and staged-file checksums. |
| `/devtools/bin/wasmtime-rt` | Runtime-only Wasmtime: precompiled Pulley execution with WASI. |
| `/devtools/cfg/wasmtime/sources.txt`, `SHA256SUMS` | Wasmtime build provenance and checksums. |
| `/devtools/cfg/wasmtime/fixtures/` | Test modules and components precompiled for this runtime, including the TypeScript workload. |
| `/devtools/src/wasm/` | `hello.js` and a README with compile/run instructions. |
| `/devtools/www/wasm.html` | This guide in the image's HTML documentation. |

The smaller `wasm.img` also includes the three tools and their configuration
directories.

`wasmtime-rt` runs as role None (`MOTOR_OS_CAPS=0`, `0x100`, `0x200` or
`0x300`) and needs `--allow-precompiled`. Each linear memory is limited to
96 MiB, and a process to four memories reserving 128 MiB in total; `-W
max-memory-size` and `-W max-memories` can only lower these. A store defaults
to 64 instances, 16 tables and 32,768 table elements, which `-W max-instances`,
`-W max-tables` and `-W max-table-elements` override. `-W timeout=DURATION`
interrupts a guest compiled with epoch interruption. The example and HTML documentation are part of `dev.img`.

## Run the example

In the developer VM's shell:

```sh
cd /devtools/src/wasm
MOTOR_OS_CAPS=0x200 /devtools/bin/javy build hello.js -o /user/tmp/hello.wasm
MOTOR_OS_CAPS=0 /devtools/bin/wasmi /user/tmp/hello.wasm
```

Expected output:

```text
Hello from WebAssembly on Motor OS!
{"squares":[1,4,9,16],"total":30}
```

The masks launch the tools with role None: `0x200` grants Javy filesystem
write access for its output, while Wasmi needs no capabilities for this example.
`/user/tmp` is writable by role None. The default plugin is embedded, and the
example runs offline. Edit `hello.js` and repeat the commands to try changes.

See [Building Motor OS](build.md) for image construction and the focused
installed-tool checks, and [capabilities](caps.md) for the masks.
