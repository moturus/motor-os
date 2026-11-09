#!/system/bin/rush
set -eu
work=/user/tmp/quickjs-smoke
mkdir -p "$work"
cd "$work"
qjs --version
cc -O2 /devtools/tests/quickjs-qsort.c -o qsort-check
./qsort-check
cc -O2 /devtools/tests/quickjs-libc-process.c -o libc-process
./libc-process
qjs /devtools/tests/quickjs-exepath.js /devtools/bin/qjs
/devtools/bin/qjs /devtools/tests/quickjs-exepath.js /devtools/bin/qjs
(cd /devtools/bin && ./qjs /devtools/tests/quickjs-exepath.js /devtools/bin/qjs)
cc /devtools/tests/quickjs-exepath-buffer.c -o exepath-buffer
./exepath-buffer
qjsc -e -m -o exepath-native.c /devtools/tests/quickjs-exepath.js
cc -I/devtools/quickjs/include exepath-native.c /devtools/quickjs/lib/libqjs.a -o exepath-native
./exepath-native "$work/exepath-native"
cp /devtools/tests/quickjs-exepath.js standalone-source.js
qjs --compile standalone-source.js --out standalone-app
qjs -c standalone-source.js -o standalone-app
rm standalone-source.js
./standalone-app "$work/standalone-app"
mv standalone-app 'standalone moved'
./'standalone moved' "$work/standalone moved"
qjs /devtools/tests/quickjs-smoke.js
qjs /devtools/tests/quickjs-process.js
qjsc -e -m -o process.c /devtools/tests/quickjs-process.js
cc -I/devtools/quickjs/include process.c /devtools/quickjs/lib/libqjs.a -o process
./process
qjs /devtools/tests/quickjs-workers.js
rustc --edition=2024 /devtools/tests/quickjs-http.rs -o quickjs-http
qjs /devtools/tests/quickjs-shell-net.js
qjsc -e -m -o shell-net.c /devtools/tests/quickjs-shell-net.js
cc -I/devtools/quickjs/include shell-net.c /devtools/quickjs/lib/libqjs.a -o shell-net
./shell-net
qjsc -e -m -o smoke.c /devtools/tests/quickjs-smoke.js
cc -I/devtools/quickjs/include smoke.c /devtools/quickjs/lib/libqjs.a -o smoke
./smoke
qjsc -b -m -o smoke.bin /devtools/tests/quickjs-smoke.js
test -s smoke.bin
printf 'print(40 + 2); std.exit(0)\n' | qjs > repl.txt
rg '^42$' repl.txt
printf 'quickjs native compilation: PASS\n'
