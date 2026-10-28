# JavaScript to WebAssembly

`hello.js` squares four numbers and prints their sum. Compile it with Javy,
then execute the resulting WebAssembly module with Wasmi or Wasmtime. All of
these tools are installed on the Motor OS developer image; no downloads are
needed.

Run these commands in the VM's shell:

```sh
cd /devtools/src/wasm
MOTOR_OS_CAPS=0x200 /devtools/bin/javy build hello.js -o /none/tmp/hello.wasm
MOTOR_OS_CAPS=0 /devtools/bin/wasmi /none/tmp/hello.wasm
```

The same module runs natively with Wasmtime, or can be compiled once and
loaded by either Wasmtime CLI:

```sh
MOTOR_OS_CAPS=0 /devtools/bin/wasmtime run /none/tmp/hello.wasm
MOTOR_OS_CAPS=0x200 /devtools/bin/wasmtime compile /none/tmp/hello.wasm -o /none/tmp/hello.cwasm
MOTOR_OS_CAPS=0 /devtools/bin/wasmtime-rt run --allow-precompiled /none/tmp/hello.cwasm
```

Expected output of each run:

```text
Hello from WebAssembly on Motor OS!
{"squares":[1,4,9,16],"total":30}
```

The capability masks launch the tools with role None. `0x200` grants
filesystem write access for an output file; running a module needs no
capabilities for this example. `/none/tmp` is writable by role None. Javy
embeds the default QuickJS plugin, so no plugin argument is needed.

Edit `hello.js` and repeat the commands to compile and run your changes.
See `/devtools/www/wasm.html` for the installed tools and support files.
