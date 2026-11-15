# Milestone 5 test coverage inventory

This inventory accompanies [the approved image-layout plan](new-image-layout.md).
It records where existing coverage belongs before its old driver is removed.
The standard and base images contain no tests. The harness installs tools and
uploads test inputs only into disposable copies.
`src/tests` holds only the three runners and `stress-soak.sh`. Freestanding
fixture trees are removed as coverage becomes crate tests or runner setup;
this is not a relocation of the old fixture collection.

## Native harnesses

`full-native-test.sh` runs Cargo and Lorry on Linux, and Lorry on Motor.
WireGuard uses Cargo only on Linux: adding Lorry's unsupported Linux `cdylib`
output is explicitly outside the image-layout migration.
Each invocation uses the selected build profile and fails on the first error.
Motor checks newly exercised by this migration may be deferred only under the
user's continuation policy in [new-layout-followups.md](new-layout-followups.md).
That document records every exclusion and its retained Linux coverage.

| Harness | Linux | Motor | Existing variants retained |
| --- | --- | --- | --- |
| red, rmux, rush, russhd | yes | yes | Rush `dev-tty` on Linux |
| wg | Cargo only | yes | Independent upstream peer interoperability |
| curl, lorry, httpd-axum | yes | yes | Lorry ignored curl tests on every run |
| gix | yes | yes | Local transport and offline fixture checks |
| rnetbench | yes | yes | Stalled peers use loopback |
| sys-init config parser | yes | yes | Service startup remains a boot check |
| moto-rt, moto-sys, moto-sdk | yes | yes | SDK default and no-default-features |
| frusa | yes | deferred: NLF-004 | Existing allocator stress counts on Linux |
| memfs | yes | yes | Existing native coverage retained |
| motor-fs | yes | deferred: NLF-004 | `image-admin` on Linux; native system filesystem checks retained |
| netstack | yes | deferred: NLF-004 | Both Linux unit variants; native system and cross networking checks retained |
| systest | no | yes | Serial, existing order; role checks inside cases |
| sysbox | no | yes | Utility and former systest sysbox cases |
| mio-test, tokio-tests | no | yes | Existing native suites |
| rust-analyzer smoke | yes | yes | Protocol, resource, native and command-debug checks |
| wasm smoke helpers | yes | yes | Host/guest byte comparison stays cross-system |
| crossterm fork | yes | supported cases | `events`, `events,use-dev-tty` on Linux |

The Linux imager, independent upstream WireGuard peer, and packaging tools stay
in the host build gate. The peer's Cargo tests cover localhost behavior; its
upstream dependency declares a Linux dynamic library, which Lorry does not
support. Kernel and privileged service self-tests stay in their owning components
and run in Motor. Tests requiring System run from the System console, outside
Lorry.

## Existing drivers and their destinations

Paths in the first column are relative to the old `src/tests` directory unless
otherwise stated. A destination is complete only after its assertions have moved
and its component gate has passed.

| Existing coverage | Destination |
| --- | --- |
| `full-test-prepare.sh` | Preparation phase of `full-test.sh` |
| `full-test-dev.sh`, `test-dev-sources.sh` | Toolchain installation, snapshot upload, both native role runs |
| `test-build-base-networking.sh`, `test-external-sources.sh` | Host build checks |
| `test-make-driver.sh`, `test-kloader-image.sh` | Host build checks |
| `test-toolchain-archive.sh`, `test-toolchain-bootstrap.sh` | Host archive and bootstrap checks |
| `test-sdk-package.sh`, `test-net-contract.sh` | Host packaging and feature checks |
| `test-full-test-size.sh`, `test-vm-image-format.sh` | Host full-gate and launcher checks |
| `test-vm-console-filter.sh`, `test-vm-vsock-backend.sh` | Host launcher support checks |
| `test-rust-analyzer-size.sh`, `test-rust-analyzer-size-contract.sh` | Host analyzer size checks |
| `test-rustfmt-size.sh`, `test-rustfmt-size-contract.sh` | Host formatter size checks |
| `test-dev-path-locks.py` | Shell host check of locked local dependencies |
| `test-image-layout.sh` | Host image invariants, including exact roots and no shipped tests |
| `test-sys-lib-workspace.sh`, `test-dev-memory-contract.sh` | Remove with staged developer workspace; actual source and resource checks retained |
| `test-moto-ipc-sync.sh` and its Rust fixture | moto-sdk harness |
| `test-rmux-copy-status.sh` and its Rust fixture | rmux harness |
| `test-crossterm-host.sh` | Native Linux crossterm and Rush variants |
| `test-rush-script-caps.sh`, systest Rush precedence | Rush Motor integration tests |
| `test-stdio-errors.sh` and its Rust fixture | systest native harness |
| systest kernel-log boot latency | Fresh-image cross phase; unchanged release bound, latest boot preamble |
| `test-gix.sh` | gix native tests; local servers run on the same machine |
| `test-rust-analyzer.sh`, `test-rust-analyzer-native.sh`, `test-rust-analyzer-crates.sh` | Native analyzer harness and installed-tool checks |
| `test-rustfmt-native.sh` | Native installed-tool checks |
| `test-helix-lsp.sh`, `test-helix-lsp-ready.py` | Native Helix checks; readiness parser and its regressions in the analyzer Cargo crate |
| `test-wasm.sh`, `test-wasm-selection.sh`, `wasm-service-images.sh` | Native wasm checks; 256 MiB standard VM; cross byte comparison |
| `test-wasmtime-fetch.sh` | Host source preparation contract |
| `test-quickjs-test262.sh`, image QuickJS fixtures | Host input preparation and offline native checks |
| `test-native-toolchain-install.sh` | Standard-image archive installation and native installer acceptance |
| `test-unwind.sh` | Native compiler/unwind checks and host ELF checks |
| `test-boot-options.sh`, `test-candidate-vm.sh` | Cross boot, console, image and device checks |
| `test-system-tty.sh` | Standard image `--system-tty`, Cloud Hypervisor/Firecracker only |
| `test-block-mounts.sh` | Standard-image copies; QEMU DHCP read-only-root check retained |
| `test-oom-abort.sh` | Cross System-console failure observation |
| `test-vsock.sh`, `test-vsock-outgoing.sh` | Cross peer and no-IP standard-image copy |
| `test-udp-fragmentation.sh`, `test-wireguard.sh` | Cross network peers |
| `test-ssh-client.sh`, `test-ssh-client-host.sh` | Cross SSH client checks |
| `test-sftp.sh`, `test-ssh-config.sh`, `test-sshd-keys.sh` | Cross SSH/SFTP, config and credentials |
| `test-tui.sh`, `test-terminal-size.sh` | Cross terminal transport; application functional cases become native |
| `full-test-networking.sh` | Cross network checks; benchmark invocation retained with peers |
| `bench-wireguard.sh` | `cross-test.sh --benchmark physical\|plain\|wireguard` |
| `vm-*.sh`, `test-roots.sh`, `ssh-terminal-child.sh`, SSH keys and host probes | Cross harness functions and generated input; canonical launcher key in `src/vm_scripts` |
| `stress-soak.sh` | Unchanged, repository-only, outside this work's validation scope |

## Lorry coverage

All `src/bin/lorry/tests/*-contract.sh` product assertions become Rust tests in
the Lorry crate. Expected behavior is asserted directly; these tests do not run
Cargo. This includes dependency defaults, review and admission, Git patches,
rustflags and environment, metadata and target descriptions, check and clippy,
artifact locks, target directories, selected caches, analyzer/editor workspaces,
tree/resolution, workspace commands, build scripts and metadata, C++, profiles,
crate types, explicit and harness-free tests, freshness, pipelining, edit races,
sandbox scope, trust, required features, proc macros, compile-time dependencies,
registries, fetch and mixed-case names.

`stage2-differential.sh` becomes direct Rust assertions. The retained dependency
resolution oracles become Rust test data that generates temporary workspaces;
their comparison with Cargo is a host build check. cargo_metadata wire-schema
checks become a native harness with generated inputs.
`cargo-identity.sh` and the build comparison in `test-native.sh` become one cross
workspace generated by the cross runner, comparing host Cargo, host Lorry and
guest Lorry outputs. Motor role,
source-mode and child-process tests create and own their own fixtures.
`test-native-projects.sh` is replaced by ordinary native crate builds and the
named, ignored Helix build test selected by `--full`. Curl's ignored integration
tests retain their loopback TLS fixture in every native run on both systems.

## Final gate

The consolidated `full-test.sh` defaults to Cloud Hypervisor. The original plan
required three debug and three release passes before committing. The user's
validation instruction superseded that stopping point: make no commits
and stop after the first complete full-gate pass, recording its exact command in
[new-layout-followups.md](new-layout-followups.md). QEMU supplies the read-only-root
DHCP check. Firecracker names its development-tool skips; QEMU names its
System-console skips. No developer image gate remains.

The complete `src/tests/full-test.sh --release` gate passed on 2026-11-15,
including both Motor roles. The exact result, retained Linux coverage, and
Motor-only deferrals are recorded in the follow-up document. Work stopped at
that first complete pass without a commit.
The user subsequently authorized the eight-commit implementation series;
no tests were rerun while assembling it.
