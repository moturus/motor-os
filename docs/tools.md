# Tools/commands available in Motor OS

## VM running helpers

After successfully [building Motor OS image](./build.md),
`$MOTORH/motor-os/vm_images/[debug|release]` directory will contain several data files
and several useful scripts:

- `motor-os-base.img` contains the minimal bootable system and user shell tools;
- `motor-os.qcow2` is the standard production image, adding networking, DNS, and
  regular user programs;
- `motor-os-dev.qcow2` adds native toolchains, sources, diagnostics, tests, and
  the bundled sample website;
- `create-tap.sh` creates the local `moto-tap` interface the VMs use for
  networking and the NAT rules that let them reach the Internet; the build runs
  the same steps, so it is needed only after a host reboot;
- `run-qemu.sh` and `run-chv.sh` run the image selected by `MOTO_IMAGE`; it
  defaults to `motor-os.qcow2`. QEMU and Cloud Hypervisor also accept the raw
  images. `run-fc.sh` requires a raw image and defaults to the base image.
  `make raw.img` (or `make raw.img BUILD=release`) explicitly builds
  `motor-os.img`, the standard image in raw format; ordinary `make` does not.

## Vsock test prerequisites

The vsock guest tests use local Unix-domain host peers, not host `AF_VSOCK`
or `/dev/vhost-vsock`. QEMU requires the pinned `vhost-device-vsock` backend:

```sh
cargo install --locked vhost-device-vsock --version 0.3.0
```

Install it during developer setup, not during tests. Put its binary on `PATH`
or set `VHOST_DEVICE_VSOCK` to its path. The harness checks the version and
fails on missing prerequisites; it does not download dependencies or skip
coverage. QEMU uses opt-in shared guest RAM (`MOTO_SHARED_MEM=1`), preserving
the runner's hugepage policy and any `MOTO_HUGEPAGES` override.

`src/tests/test-vsock.sh [--release] [--vmm qemu|chv|fc]` runs outgoing stream
tests on the selected VMM (QEMU by default), then the existing IP-disabled
Cloud Hypervisor discovery cases. The full standard suite calls this phase.
The selected Firecracker phase requests `raw.img`; developer-image tests
support QEMU and Cloud Hypervisor only. All phases share the VM lock and run
sequentially; each owns and reaps its VMM and any backend/peer processes.

## Tools available inside the Motor OS VM

This is how `top` looks like:

![top](top.png)

Motor OS boots into a unix-like shell [rush](https://github.com/moturus/rush).
The shell is somewhat barebones now (contributions are welcome!).

- `ls /system/bin` and `ls /user/bin` show the standard commands; the
  development image also places `/devtools/bin` on `PATH`;
- `free`, `kill`, `ping`, `printenv`, `ps`, `ss`, and `top` are worth mentioning;
- `ping [-c COUNT] [-i SECONDS] [-W SECONDS] [-s BYTES] DESTINATION` supports
  numeric IPv4 and IPv6 addresses, `localhost`, and DNS names;
- On the development image, `/devtools/tests/systest`,
  `/devtools/tests/mio-test`, and `/devtools/tests/tokio-tests` are useful to
  make sure everything is working as expected;
- `/system/logs` contains current and rotated service logs. Interactive
  sessions can list and read them, System-role strobe alone creates and rotates
  them, and None-role processes cannot traverse the directory. The unfiltered
  kernel stream is `/system/logs/kernel.log`; its previous 4 MiB generation is
  `kernel.log.prev`. Strobe applies the same size bound to every tag and removes
  the oldest `.prev` files when free space falls below 50 MiB. Runtime
  diagnostics go to the process's stderr first, including debug records when
  debug logging is configured; for these diagnostics, the kernel log is a
  capability-gated fallback when that write fails;
- `/devtools/bin/mdbg print-stacks $PID`, where `$PID` can be deduced by running `ps`, will
  (attempt) to extract stack traces for all threads in the process; the stack traces
  are addresses, so `addr2line` will need to be used with the binary
  (e.g. `$MOTORH/motor-os/build/obj/sys-io/x86_64-unknown-motor/debug/sys-io`);
  - stack traces reaching into the VDSO object will be marked as so, and can be symbolized
  using `addr2line` applied to `$MOTORH/motor-os/build/obj/vdso/x86_64-unknown-motor/debug/rt`.

![ps -H](ps.png)

For more details, see [https://motor-os.org](https://motor-os.org).
