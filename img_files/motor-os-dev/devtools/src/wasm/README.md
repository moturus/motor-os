# JavaScript to WebAssembly

`hello.js` squares four numbers and prints their sum. Compile it with Javy,
then execute the resulting WebAssembly module with Wasmi. Both tools are
installed on the Motor OS developer image; no downloads are needed.

Run these commands in the VM's shell:

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

The capability masks launch the tools with role None. `0x200` grants Javy
filesystem write access for its output; Wasmi needs no capabilities for this
example. `/user/tmp` is writable by role None. Javy embeds the default QuickJS
plugin, so no plugin argument is needed.

Edit `hello.js` and repeat the two commands to compile and run your changes.
See `/devtools/www/wasm.html` for the installed tools and support files.
