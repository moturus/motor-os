# WebAssembly on Motor OS

The developer image (`make dev.img BUILD=release`, producing
`motor-os-dev.qcow2`) includes Javy 9.1.0 and Wasmi 1.1.0. Javy compiles
JavaScript into a WebAssembly module containing the QuickJS runtime. Wasmi
interprets that module using the Motor port's WASI Preview 1 support.

## Installed files

| Path | Contents |
| --- | --- |
| `/devtools/bin/javy` | JavaScript-to-WebAssembly compiler. |
| `/devtools/bin/wasmi` | WebAssembly interpreter and command runner. |
| `/devtools/cfg/javy/plugin.wasm` | Default QuickJS plugin for explicit plugin selection and dynamic modules; also embedded in Javy. |
| `/devtools/cfg/javy/typescript-workload.js` | TypeScript 5.9.3 plus a transpilation test workload. |
| `/devtools/cfg/javy/typescript-LICENSE.txt`, `typescript-NOTICES.txt` | License and third-party notices for the bundled TypeScript code. |
| `/devtools/cfg/javy/sources.txt`, `SHA256SUMS` | Build provenance, source revisions, and staged-file checksums. |
| `/devtools/src/wasm/` | `hello.js` and a README with compile/run instructions. |
| `/devtools/www/wasm.html` | This guide in the image's HTML documentation. |

The smaller `wasm.img` also includes the two tools and their configuration
directory. The example and HTML documentation are part of `dev.img`.

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
