# JavaScript to WebAssembly

`hello.js` squares four numbers and prints their sum. Compile it with Javy,
then execute the resulting WebAssembly module with Wasmi or Wasmtime. All of
these tools are installed on the Motor OS developer image; no downloads are
needed.

Run these commands in the VM's shell:

```sh
cd /devtools/src/wasm
/devtools/bin/javy build hello.js -o "$TMPDIR/hello.wasm"
/devtools/bin/wasmi "$TMPDIR/hello.wasm"
```

The same module runs natively with Wasmtime, or can be compiled once and
loaded by either Wasmtime CLI:

```sh
/devtools/bin/wasmtime run "$TMPDIR/hello.wasm"
/devtools/bin/wasmtime compile "$TMPDIR/hello.wasm" -o "$TMPDIR/hello.cwasm"
/devtools/bin/wasmtime-rt run --allow-precompiled "$TMPDIR/hello.cwasm"
```

Expected output of each run:

```text
Hello from WebAssembly on Motor OS!
{"squares":[1,4,9,16],"total":30}
```

All workflows run as None, Interactive or System. These commands inherit the
shell's role and use its writable `TMPDIR`. Writing output requires
`CAP_FS_WRITE`; running this example needs no capabilities. To explicitly
select None, use `MOTOR_OS_CAPS=0x200` for compilation, `MOTOR_OS_CAPS=0` for
execution, and `/none/tmp/hello.wasm` and `/none/tmp/hello.cwasm` for the output
paths. Javy embeds the default QuickJS plugin, so no plugin argument is needed.

Edit `hello.js` and repeat the commands to compile and run your changes.
See `/devtools/www/wasm.html` for the installed tools and support files.
