# Testing Motor OS

Four runners in `src/tests/` cover the repository:

- `full-test.sh` is the main gate. It builds the images, runs host checks and
  native tests on Linux, installs the toolchain into a disposable copy of the
  standard image, runs the host/guest cross checks, then runs the native tests
  inside Motor OS as Interactive (`0x3ec`) and None (`0x3a4`).
- `core-test.sh` is a fast gate for core OS changes. It runs the `src/sys`
  part of `full-test.sh` and times each step.
- `full-native-test.sh` runs the native tests on the machine it runs on:
  `cargo test` and `lorry test` on Linux, `lorry test` on Motor OS. On
  Motor OS, `systest`, `mio-test` and `tokio-tests` run with `lorry run`
  instead: they are test programs, not test harnesses.
- `cross-test.sh` runs the host/guest checks against an image that already has
  the toolchain installed.

`stress-soak.sh` is a separate repository script and is not part of the gate.

## `full-test.sh`

```sh
src/tests/full-test.sh [--release | --all-debug] [--full] [--vmm chv|qemu|fc] [--cpus N] [--memory MIB]
```

| Option | Default | Effect |
| --- | --- | --- |
| (none) | | Builds and boots the release image; native tests run in debug (`cargo test`, `lorry test`). |
| `--release` | off | Native tests run in release (`cargo test --release`, `lorry test --release`). Also adds the QuickJS Test262 run, which is release-only. |
| `--all-debug` | off | Manual runs only (see below). Builds and boots the debug image, and runs host checks, cross checks and native tests in debug. Cannot be combined with `--release`. |
| `--full` | off | Adds the optional native Helix build. |
| `--vmm chv\|qemu\|fc` | `chv` | VMM for the gate's VMs. `qemu` skips System-console checks. `fc` skips toolchain installation, the native guest tests and the cross checks that need development tools. Each skip is named in the output. Boot-option checks run on every available VMM regardless. |
| `--cpus N` | `$MOTO_SMP`, else 4 | vCPUs per VM. |
| `--memory MIB` | `$MOTO_MEMORY_MIB`, else 8192 for debug tests or 4096 for release tests | Memory per VM, in MiB. |

`--vmm`, `--cpus` and `--memory` accept either `--option value` or
`--option=value`. A repeated option is an error.

Both standard modes use the release image because guest file operations,
including toolchain installation, take about ten times longer on a debug
image. The debug test profile defaults to 8 GiB so Lorry can compile its
binary and test harness together inside the guest.

```sh
src/tests/full-test.sh
src/tests/full-test.sh --release
```

The toolchain archive is always a release build, whatever the options.
Before building, the gate checks the installed rustc, Clang, and LLD build
identities against those recorded in the native release's Lorry executable.
It also compares the Motor target's Rust libraries and C startup object byte
for byte. The reference archive comes from `$MOTORH` (the checkout's parent
directory by default) and the channel in `rust-toolchain.toml`. On a mismatch,
select the Linux-host toolchain from the same release build.

### `--all-debug`

`--all-debug` is the gate as it was before the image became release-only: it
exercises debug builds of the kernel, sys-io, rt.vdso and the image's tools,
including their `debug_assertions` and integer overflow checks. Use it by
hand when a change needs those checks. Automated and CI runs must not use
it.

It is slower. With 4 vCPUs and 4 GiB, the toolchain installation check takes
about 13 minutes on the debug image and the upload of the native test inputs
about 7; on the release image they take 67 and 33 seconds. It also does not
pass at present: see "`full-test.sh --all-debug` does not pass" in
[plans/future-work.md](plans/future-work.md).

## `core-test.sh`

```sh
src/tests/core-test.sh [--release]
```

It uses the release image and Cloud Hypervisor, like the default
`full-test.sh`. `--release` runs the native tests in release. The gate:

- runs `cargo test` on Linux for the `src/sys` crates (no Lorry on Linux);
- boots the base image, and installs the toolchain into a copy of the
  standard image (no installer checks);
- runs the fresh-boot checks, then the whole `systest` sequence, then
  `mio-test` and `tokio-tests`, all as Interactive. `mio-test` and
  `tokio-tests` are built on the host in the native-test profile;
- runs `lorry test` inside Motor OS for the `src/sys` crates, as Interactive
  only;
- runs the System console and System OOM abort checks.

It leaves out `src/bin`, the toolchain and wasm tests, WireGuard, the other
cross checks, and the host checks. `full-test.sh` still runs everything.
At the end it prints the time of each step and of each crate.

## `full-native-test.sh`

```sh
src/tests/full-native-test.sh [--release] [--full | --core] [--list]
```

| Option | Effect |
| --- | --- |
| `--release` | Runs the tests with `--release`. |
| `--full` | Adds the optional native Helix build. |
| `--core` | Runs only the crates `core-test.sh` needs, and only `cargo test` on Linux. |
| `--list` | Prints the crates and arguments it would test, without running anything. |

`full-test.sh` runs it on Linux and inside Motor OS with the profile selected
above.

## `cross-test.sh`

```sh
src/tests/cross-test.sh [--release] --image IMAGE [--vmm chv|qemu|fc] [--cpus N] [--memory MIB]
src/tests/cross-test.sh --benchmark physical|plain|wireguard
```

| Option | Default | Effect |
| --- | --- | --- |
| `--release` | off | Builds and uses release artifacts instead of debug ones. |
| `--image IMAGE` | | Standard image with the toolchain installed. Required except with `--vmm fc` or `--benchmark`. |
| `--vmm chv\|qemu\|fc` | `chv` | VMM for the VMs. |
| `--cpus N` | `$MOTO_SMP`, else 4 | vCPUs per VM. |
| `--memory MIB` | `$MOTO_MEMORY_MIB`, else 1024 | Memory per VM, in MiB. |
| `--benchmark KIND` | | Runs the `physical`, `plain` or `wireguard` network benchmark instead of the checks; implies `--release`. |
