# QuickJS on Motor OS

The developer image includes QuickJS-NG 0.18.0, built natively for Motor OS.
The JavaScript engine is upstream code. Only its platform layer,
`quickjs-libc.c`, and one helper in `cutils.h` carry Motor changes.
`os.platform` reports `motor`.

## Installed files

| Path | Contents |
| --- | --- |
| `/user/bin/dev/qjs` | The interpreter and REPL. It also creates standalone executables. |
| `/user/bin/dev/qjsc` | The compiler: JavaScript to C source or to bytecode. |
| `/user/lib/quickjs/include/` | `quickjs.h` and `quickjs-libc.h`. |
| `/user/lib/quickjs/lib/libqjs.a` | The engine with the `qjs:std`, `qjs:os` and `qjs:bjson` modules. |
| `/user/lib/quickjs/LICENSE` | QuickJS-NG's license. |
| `/devtools/tests/quickjs-*` | The smoke test and its fixtures. |
| `/user/lib/www/quickjs.html` | This guide in the image's HTML documentation. |

`libqjs.a` holds only QuickJS's C objects. The normal C toolchain supplies
mlibc and its runtime shim, so a program links only `libqjs.a` explicitly.

## Use

Run a script, or compile it to a native program:

```sh
qjs hello.js
qjsc -e -o hello.c hello.js
cc -I/user/lib/quickjs/include hello.c /user/lib/quickjs/lib/libqjs.a -o hello
./hello
```

`qjs` can also append bytecode to a copy of itself:

```sh
qjs --compile hello.js --out hello
./hello
```

## How Motor OS differs

Processes use mlibc's native spawn, because Motor OS has no `fork`.

- `os.exec` supports `cwd`, `env`, `file`, `usePath`, `block: false`, and
  `stdin`, `stdout` and `stderr` set to a regular file or to the parent's own
  stdio. Other descriptors cannot be passed to a child. `uid`, `gid` and
  `groups` are rejected, since Motor OS has roles instead of Unix IDs.
- `os.waitpid` waits for one child or for any child (`-1`), with `WNOHANG`.
  Each child is reaped once, across all Workers. A blocking `os.exec` throws if
  another Worker reaps its child first.
- `os.kill` supports signal 0, `SIGTERM` and `SIGKILL`, with Motor's
  permission checks. `SIGTERM` always terminates. Other signals to another
  process return `-ENOSYS`. There are no process groups.
- `std.popen` runs `/user/bin/rush -c` and returns a normal stream.
- `std.urlGet` runs `/user/bin/curl` with long options. HTTP is tested over
  loopback. HTTPS uses curl's normal certificate checks, but has not been
  tested end to end.
- Workers use pthreads. They wait through the runtime's poll and wake calls
  instead of pipes.
- `os.exePath()` returns an absolute path, also after a `chdir`.

Not available:

- `os.pipe` returns null. `os.dup` and `os.dup2` return `-ENOSYS`.
- `os.symlink` and `os.readlink` fail, because Motor OS has no links.
  `os.lstat` works.
- Native `.so` modules cannot be loaded.
- `os.ttySetRaw` and `os.ttyGetWinSize` are missing. The REPL assumes 80
  columns.
- `os.cputime` reports zero, and `os.utimes` is not implemented.
- In the REPL, end of input and pasted multiline text are unreliable. Use a
  script file or `qjs -e` for bulk input.

Large regular expressions over wide Unicode ranges are much slower than on
Linux. The cause is mlibc's handling of allocations above 32 KiB; see
[future work](plans/future-work.md).

## Build

`src/build-motor-os.sh` builds QuickJS with the Motor clang and mlibc that
`rust-toolchain.toml` names. There is no fork. Instead:

1. `fetch_quickjs` clones upstream tag `v0.18.0` into
   `external-sources/quickjs-0.18.0`, and checks that it is commit `d7215b0`
   and clean.
2. `build_quickjs` copies that source to `build/assembly/build/quickjs/src` and
   applies `src/build-scripts/quickjs-0.18.0-motor.patch` with
   `git apply --check` and `git apply`.
3. It compiles with `-O2`, whatever the OS build profile. Upstream checks in
   its generated sources, so no host QuickJS or CMake is needed.
4. It stages the overlay at `build/assembly/images/quickjs`, which
   `make dev.img` puts into the image.

To change the patch, apply it to a checkout of the tag, edit, and write the
result back with `git diff > src/build-scripts/quickjs-0.18.0-motor.patch`. To
move to a new QuickJS release, rebase the patch onto the new tag and update
`QUICKJS_VER` and `QUICKJS_REV` in `src/build-motor-os.sh`. Then update the
expected Test262 result below.

## Tests

- `/devtools/tests/quickjs-smoke.sh` runs from `src/tests/full-test.sh` when it
  tests the developer image. It covers the language and modules, `qjsc` and
  standalone builds, processes, Workers, `popen`, HTTP over loopback, and the
  mlibc calls the port relies on. It is the only test of that platform layer.
- `src/tests/test-quickjs-test262.sh` runs from `src/tests/full-test-dev.sh`
  with `--release`. It builds QuickJS's `run-test262` natively on a copy of
  the developer image and runs the full upstream configuration. It expects
  `Result: 40/82220 errors, 4802 excluded, 5736 skipped`, the same as Linux.
  Its value is in catching compiler and libc regressions.

The Test262 corpus is the `test262` submodule that the QuickJS tag pins.
The script fetches it once, before the VM boots, into
`external-sources/test262-<revision>`. The VM run uses no Internet. The suite
takes about 3.5 minutes on 4 vCPUs, against 35 seconds on the Linux host.
Almost all of the difference is the allocator issue above.

## Related changes

- mlibc (`motor-os-rustc`, from `a2527edc` to `2b86b98c`): spawn with file
  actions, wait for any child, `kill`, `popen` without `fork`, ESPIPE from
  `lseek` on streams, heapsort in `qsort`, execute bits in `open` and `fchmod`,
  and the executable-path call. See [libc](libc.md).
- The kernel marks a process as exited before it wakes its waiters, so
  `kill(pid, 0)` right after a reap reports ESRCH (`ab8e13b2`).
- Toolchain `x86_64-unknown-motor-1.99.1-2` carries these mlibc changes.
