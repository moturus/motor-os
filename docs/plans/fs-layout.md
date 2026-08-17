# Motor OS root filesystem layout

Status: proposed layout and autonomous implementation plan ready for final
review; no implementation work has started.

## Goals

Motor OS builds three cumulative filesystem images:

1. **Base** (`motor-os-base.img`) is the smallest useful system. It showcases
   Motor OS's size and efficiency while retaining the basic shell, remote
   access, and user tools.
2. **Standard/default** (`motor-os.img`) adds the software needed for a small
   production deployment, including web serving. It does not contain a native
   development toolchain.
3. **Dev/full** (`motor-os-dev.img`) adds everything needed to develop natively
   on Motor OS rather than cross-compiling from Linux.

The images remain strictly cumulative:

```text
base ⊂ standard/default ⊂ dev/full
```

The full image has exactly three top-level filesystem directories:

```text
/
├── devtools/   native compilers, build tools, tests, source, and web content
├── system/     operating-system services, tools, configuration, and data
└── user/       user-facing tools, configuration, and scratch space
```

Each top-level directory has its own `cfg` and `tmp` subdirectories. System
logs live in `/system/logs`. There are no top-level `/bin`, `/sys`, or `/www`
directories in the new layout.

## Ownership and purpose

`/system` contains the software and state needed to boot and operate Motor OS.
System service executables live in `/system/services`, while system-wide
command-line tools live in `/system/bin`. Service declarations and other system
configuration live in `/system/cfg`. The POSIX-like commands implemented by
Sysbox are exposed from `/system/bin`, alongside `ping`, Rush, curl, and
ripgrep.

`/user` is the stable home for user-facing programs and configuration. Red,
Rmux, Kibim, and the HTTP servers live under `/user/bin`. Per-user or
user-selected configuration belongs in `/user/cfg`, while `/user/tmp` is user
scratch space.

`/devtools` exists only in the dev image. It contains the native LLVM/C/C++ and
Rust toolchains, libc headers and libraries, Lorry, Gears, development
utilities, test programs, selected source trees, the bundled production
website, and tool-specific state. LLVM and libc material is grouped under
`/devtools/llvm`; there are no generic `/devtools/include` or `/devtools/lib`
directories. Development material currently mixed into `/bin`, `/sys`,
`/user/src`, and `/www` is collected here.

## Executable search path

The default executable search path is image-specific:

```text
base and standard: /system/bin:/user/bin
dev:               /system/bin:/user/bin:/devtools/bin
```

`/system/cfg/rush.cfg` must export the corresponding `PATH` for interactive
Rush sessions. The `path` setting in `/system/cfg/sshd.toml` must use the same
value so that programs launched through russhd see the same defaults. System
services are addressed from `/system/services` explicitly and are not added to
`PATH`.

`TMPDIR` is the standard environment variable for selecting a temporary-file
directory ([POSIX.1-2024 environment variables](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap08.html)).
Rush must set it to `/user/tmp` when it is absent. Motor's Rust and C/C++
runtime paths must honor it and use `/user/tmp` as their fallback. Directly
invoked Gears, Lorry, Lua, Mdbg, and LLVM programs inherit that ordinary
default and honor an explicit user value. The `cc`, `c++`, and `rustc`
launchers override it with `/devtools/tmp`; development-test harnesses do the
same for tests they upload to an image.

## Proposed directory and image matrix

The checkboxes indicate whether the directory exists in that image. Since the
images are cumulative, every base directory is also in standard and dev, and
every standard directory is also in dev. Within shared `bin` and `cfg`
directories, **B**, **S**, and **D** identify the first image containing a
file: base, standard, or dev respectively. The contents column describes the
full dev image.

| Directory in dev/full | Standard/default | Base | Contents in the full image | Current location |
|---|:---:|:---:|---|---|
| `/devtools` | ☐ | ☐ | Native development tools, supporting files, tests, source, and bundled web content. | Split across `/bin`, `/sys/tools`, `/sys/tests`, `/sys/mdbg`, `/user/src`, and `/www`. |
| `/devtools/bin` | ☐ | ☐ | **D launchers:** `c++`, `cc`, `rustc`, `www`.<br>**D direct executables:** `gears`, `lorry`, `lua`, `mdbg`. `rustc` launches the real compiler under `/devtools/rust/bin`; the compiler launchers set `TMPDIR=/devtools/tmp`. | `/bin/{c++,cc,gears,lorry,lua,www}`, `/sys/mdbg`, and `/sys/tools/rust/bin/rustc`. |
| `/devtools/cfg` | ☐ | ☐ | **D:** `llvm/x86_64-unknown-motor.cfg`, `lorry.toml`. | `/sys/cfg/llvm` and `/sys/tools/rust/cfg/lorry.toml`. |
| `/devtools/llvm` | ☐ | ☐ | Native LLVM/Clang and libc toolchain. | `/sys/tools/llvm`. |
| `/devtools/llvm/bin` | ☐ | ☐ | **D:** `llvm`. | `/sys/tools/llvm/bin/llvm`. |
| `/devtools/llvm/include` | ☐ | ☐ | libc, libc++, libunwind, C/C++, and Motor platform headers. | `/sys/tools/llvm/include`. |
| `/devtools/llvm/lib` | ☐ | ☐ | libc and C/C++ runtime libraries plus LLVM/Clang resources. | `/sys/tools/llvm/lib`. |
| `/devtools/rust` | ☐ | ☐ | Native Rust toolchain support and target sysroot. | `/sys/tools/rust`, with its executable, configuration, and Lorry state redistributed within `/devtools`. |
| `/devtools/rust/bin` | ☐ | ☐ | **D:** the real `rustc` executable. | `/sys/tools/rust/bin/rustc`. |
| `/devtools/rust/lib` | ☐ | ☐ | Rust target libraries used by the native compiler. | `/sys/tools/rust/lib`. |
| `/devtools/lorry` | ☐ | ☐ | Lorry's system registry configuration and vendored package cache. | `/sys/tools/rust/lorry` and part of `/sys/tools/rust/cfg`. |
| `/devtools/src` | ☐ | ☐ | C, C++, and Rust samples; materialized Red, curl, Lorry, and Gears source trees; and the supporting `moto-rt` and `moto-sys` sources needed for native builds. | `/sys/tools/llvm/src`, `/sys/tools/rust/src`, `/user/src/{red,curl,lorry}`, and Motor repository sources not currently packaged. |
| `/devtools/tests` | ☐ | ☐ | Motor system-test and benchmark executables: `crossbench`, `crossterm-smoke`, `mio-test`, `rnetbench`, `systest`, and `tokio-tests`; Gears test helpers and fixtures live below `/devtools/tests/gears`. | `/sys/tests`; `rnetbench` is also duplicated in `/bin`, while Gears helpers currently follow the main executable. |
| `/devtools/tmp` | ☐ | ☐ | Scratch space for native builds and development tools. | No dedicated directory; development currently shares `/sys/tmp`. |
| `/devtools/www` | ☐ | ☐ | The bundled production website and its static assets. | `/www`. |
| `/system` | ☑ | ☑ | Operating-system services, tools, configuration, logs, temporary files, and deployed system data. | Primarily `/sys`, plus system-owned files in `/bin`. |
| `/system/bin` | ☑ | ☑ | **B:** `rush`, `sysbox`.<br>**B Sysbox wrappers:** `cat`, `cp`, `date`, `df`, `echo`, `exit`, `find`, `free`, `kill`, `less`, `loop`, `ls`, `mkdir`, `mv`, `ping`, `printenv`, `ps`, `pstat`, `pwd`, `rm`, `rmdir`, `sh`, `sleep`, `ss`, `stats`, `time`, `top`, `uname`, `uptime`, `wc`.<br>**S:** `curl`, `rg`. | System tools and wrappers are currently in `/bin`. |
| `/system/cfg` | ☑ | ☑ | **B:** `rush.cfg`, `sshd.toml`, `ssl/{ca-certificates.crt,ssl-cert.pem,ssl-key.pem}`, `sys-init.cfg`, `sys-net.toml`, `sys-tty.cfg`.<br>**S:** `libc/{hosts,resolv.conf,services,shells}`. `rush.cfg` and `sshd.toml` carry the image-specific default `PATH`; Rush supplies the `/user/tmp` `TMPDIR` fallback. Base `sys-init.cfg` retains a commented DNS example. | `/sys/cfg`, except LLVM configuration moved to `/devtools/cfg` and Kibim configuration moved to `/user/cfg/kibim`. |
| `/system/logs` | ☑ | ☑ | System and service logs. | `/sys/logs`. |
| `/system/services` | ☑ | ☑ | **B:** `russhd`, `strobe`, `sys-init`, `sys-tty`.<br>**S:** `dns-resolver`. | Split between `/sys` and `/bin/russhd`. |
| `/system/tmp` | ☑ | ☑ | System and service scratch space. | `/sys/tmp`. |
| `/user` | ☑ | ☑ | User-facing programs, configuration, and scratch space. | `/user`, plus user programs currently installed in `/bin`. |
| `/user/bin` | ☑ | ☑ | **B:** `red`, `rmux`.<br>**S:** `httpd`, `httpd-axum`, `kibim`. | `/bin/{red,rmux,httpd,httpd-axum,kibim}`. |
| `/user/cfg` | ☑ | ☑ | **B:** `red.toml`, `rush.toml`, `rmux.toml.example`.<br>**S:** `kibim/config.ini.example`, `kibim/syntax.d/`.<br>**D:** `gears.toml.example`, `gears/openrouter.key.example`, `lorry.toml.example`, `lorry-redirect-sites.toml.example`. Files ending in `.example` are non-active templates for users to copy and edit. | `/user/cfg` and `/sys/cfg/kibim/syntax.d`; the additional examples are not currently shipped. |
| `/user/tmp` | ☑ | ☑ | User scratch space. | `/user/tmp`. |

## Image composition

The base image contains `/system` and `/user`. It includes the boot/runtime
services other than `dns-resolver`, Rush and the Sysbox command set, SSH access,
Red, Rmux, configuration, logs, and scoped temporary directories.

The standard image adds `dns-resolver`, the production HTTP client and servers,
ripgrep, and Kibim. It intentionally excludes compilers, development libraries,
source trees, test binaries, package caches, and the bundled production
website.

The dev image adds the complete `/devtools` tree, including the bundled
production website and the offline sources and package repository needed to
rebuild Lorry and Gears on Motor OS. It is the sole self-hosting seed; there is
no fourth or Lorry-specific image tier. Moving the currently bundled LLVM and
Rust toolchains out of the standard image is the main size reduction for the
production image. Curl moves in the other direction: from the current dev-only
image into the standard system toolset.

Static filesystem content is applied cumulatively. Standard applies an overlay
on top of base, and dev applies another overlay on top of standard; a file in a
larger image's overlay replaces the same destination from the smaller image.
This supplies the dev-specific Rush and russhd configuration without
duplicating the shared tree. The imager must also create every declared
directory explicitly, including empty `cfg`, `tmp`, and `logs` directories;
placeholder files are not the directory-creation mechanism in the new layout.

`src/build-motor-os.sh` is the one first-checkout build entry point. It absorbs
the current `src/build-dev.sh`, generates the standard libc overlay separately
from the dev-only LLVM overlay, constructs the toolchains, and then builds all
three images.

This document defines the intended layout and image membership. The autonomous
implementation order for the imager, build scripts, hard-coded paths, tests,
and documentation follows the audit below.

## Source audit and implementation catalog

This section records the checked-in paths that must change when the layout is
implemented. The audit covered `src/build-*.sh`, the `Makefile`, imager
manifests and tests, static image trees, Motor runtime and application source,
test harnesses, and the adjacent `mlibc`, `llvm-project`, and `rust` source
trees used by the build. It is an implementation catalog, not an implementation.

The following mapping is the common basis for the findings below:

| Current guest path | New guest path or rule |
|---|---|
| `/bin/<name>` | Split by ownership: `/system/bin`, `/user/bin`, or `/devtools/bin`. |
| `/sys/{strobe,sys-init,sys-tty,dns-resolver}` and `/bin/russhd` | `/system/services/<name>`; `dns-resolver` starts with the standard image. |
| `/sys/sysbox` and its `/bin` wrappers | `/system/bin/sysbox` and `/system/bin/<wrapper>`. |
| `/sys/cfg/libc` | `/system/cfg/libc`, beginning in the standard image. |
| `/sys/cfg/llvm` | `/devtools/cfg/llvm`. |
| `/sys/cfg/kibim` | `/user/cfg/kibim`. |
| Other `/sys/cfg` | `/system/cfg`. |
| `/sys/logs` | `/system/logs`. |
| `/sys/tools/llvm` | `/devtools/llvm`. |
| `/sys/tools/rust/bin/rustc` | Real compiler at `/devtools/rust/bin/rustc`, with a Rush launcher at `/devtools/bin/rustc`. |
| `/sys/tools/rust/lib` | `/devtools/rust/lib`. |
| `/sys/tools/rust/lorry` | `/devtools/lorry`. |
| `/sys/tests` and `/sys/mdbg` | `/devtools/tests` and `/devtools/bin/mdbg`. |
| `/sys/tools/{llvm,rust}/src` and `/user/src` | `/devtools/src`. |
| `/www` | `/devtools/www`. |
| `/sys/tmp` used by applications or explicit compiled output artifacts | `/user/tmp`. |
| `/sys/tmp` used privately by compiler launchers, development tests, or their intermediates | Their launchers/harnesses set `TMPDIR=/devtools/tmp`; directly invoked tools retain the ordinary `/user/tmp` fallback. |
| System-service private scratch | `/system/tmp`. |

### Build entry points and generated staging trees

| File or area | Finding and required change |
|---|---|
| `src/build-base.sh` | The final-build gate checks `motor-sysroot/sys/tools/llvm/lib/libc.a` and says the base image must wait for mlibc because DNS requires it. Base no longer contains `dns-resolver`, so remove that C-sysroot/DNS prerequisite and update the stage comments. The adjacent checkout name `motor-sysroot` remains a host path, but its guest-layout mirror changes to `devtools/llvm`. |
| `src/build-dev.sh` | Fold its work into `src/build-motor-os.sh`, update all callers and documentation, and retire this separate entry point. There must be only one first-checkout workflow capable of producing every image. |
| `src/build-motor-os.sh`: path constants | `TOOLS="sys/tools/llvm"`, `CFG_LLVM="sys/cfg/llvm"`, and `CFG_LIBC="sys/cfg/libc"` drive both the host cross-sysroot and staged image. Change them to `devtools/llvm`, `devtools/cfg/llvm`, and `system/cfg/libc`; update all associated comments, probes, cleanup paths, and required-output checks. |
| `src/build-motor-os.sh`: LLVM/mlibc stages | Meson install prefixes, `MLIBC_SYSCONFDIR`, LLVM CMake flags, clang's compiled-in config directory, header/library probes, CRT paths, and native-link commands all reproduce the old tree. The cross-sysroot must mirror `/devtools/llvm`, because clang prefixes those paths with `--sysroot`. |
| `src/build-motor-os.sh`: LLVM image stage | Move `llvm` to `/devtools/llvm/bin`, `cc`, `c++`, and `lua` to `/devtools/bin`, samples to `/devtools/src`, and the clang config to `/devtools/cfg/llvm`. Generate `img_files/generated/libc/system/cfg/libc` independently of the dev-only LLVM tree, including `hosts`, `resolv.conf`, `services`, and `shells`. The generated `cc` and `c++` scripts need `#!/system/bin/rush`, must force `TMPDIR=/devtools/tmp`, and must invoke `/devtools/llvm/bin/llvm`. Their resource-dir config must name `/devtools/llvm/lib/clang/<version>`. |
| `src/build-motor-os.sh`: Rust stage | All prerequisite checks and linker inputs currently name `sys/tools/llvm`; update them to the generated `/devtools/llvm` tree. Stage the real compiler at `/devtools/rust/bin/rustc`, its sibling libraries at `/devtools/rust/lib`, and a Rush launcher at `/devtools/bin/rustc`; also split source, configuration, and Lorry state into `/devtools/src`, `/devtools/cfg`, and `/devtools/lorry`. The launcher forces `TMPDIR=/devtools/tmp`. The rebuilt C-ABI shim must be copied into `/devtools/llvm/lib` in both the cross-sysroot and staged image. |
| `src/build-motor-os.sh`: ripgrep and examples | Stage ripgrep as `/system/bin/rg` in the standard generated content, not `/bin/rg` in dev-only content. Update the final usage examples so compilers and source come from `/devtools` and the requested `hello` output artifacts go to `/user/tmp`; compiler-private intermediates belong in `/devtools/tmp`. |
| `src/build-motor-os.sh`: final images | After constructing the native toolchains, build and report base, standard, and dev images. The standard image must not consume the staged toolchains even though the same top-level workflow builds them. |
| `src/bin/curl/build-motor.sh` | Its isolated source stage copies the bundled certificate through `img_files/motor-os/sys/cfg/ssl`; use the new `img_files` location under `system/cfg/ssl`. |
| Generated directories | `img_files/generated/llvm`, `img_files/generated/rustc`, and `img_files/generated/rg` currently reproduce `/bin` and `/sys/tools`. Their internal trees, stale-tree cleanup, executable checks, and every consumer must use `/devtools` or `/system/bin` as appropriate. Add the separately owned `img_files/generated/libc` standard overlay rather than nesting libc configuration in `generated/llvm`. |

The sibling checkout variables such as `$MOTORH/llvm-project`, `$MOTORH/mlibc`,
and `$MOTORH/rust` name Linux source directories and do not change. Only paths
inside the Motor cross-sysroot and generated image trees follow the guest
layout.

### Makefile image membership

The current dependency groups do not implement the proposed tiers:

- `sys` includes `dns-resolver`, and `base.img` depends on `sys`. Split the
  common boot services from the standard-only resolver so base does not build
  or package DNS.
- `user` currently includes Kibim, HTTP servers, Mdbg, all system tests and
  benchmarks, while `user-dev` is where curl currently enters. Regroup targets
  so base gets Rush, russhd, Red, Rmux, Sysbox, and the base services; standard
  adds DNS, curl, rg, Kibim, and the HTTP servers; dev adds Mdbg, tests,
  benchmarks, Gears, Lorry, and the native toolchains.
- `MOTOR_DNS_SDK` points inside
  `../motor-sysroot/sys/tools/llvm`; it must point inside the new
  `../motor-sysroot/devtools/llvm` mirror.
- The `main.img` and `dev.img` comments still describe curl, rg, and generated
  toolchains with their old tier membership and need to match the new groups.
- Give each image target only its own prerequisites and add an `images`
  aggregate. Keep the default `all` target on the standard image. Use 64 MiB,
  256 MiB, and 2048 MiB data partitions for base, standard, and dev
  respectively; the standard size leaves useful deployment scratch while
  making the toolchain removal visible in the image artifact.

Repository source paths such as `src/bin`, `src/sys`, and `src/sys/tests` in
Make recipes are source-tree names, not guest paths, and remain unchanged.

### Imager manifests and static filesystem content

| File or area | Finding and required change |
|---|---|
| `src/imager/motor-os-base.yaml` | Move Rush/Sysbox to `/system/bin`, Red/Rmux to `/user/bin`, and russhd/strobe/sys-init/sys-tty to `/system/services`. Remove `dns-resolver` completely. Point the static tree at content organized under `/system` and `/user`. |
| `src/imager/motor-os.yaml` | Put services only in `/system/services`; put HTTP servers and Kibim in `/user/bin`; keep rg and curl in `/system/bin`. Remove Mdbg, benchmarks, test executables, and the generated LLVM/Rust trees from standard. The standard manifest still includes `dns-resolver`. |
| `src/imager/motor-os-dev.yaml` | Apply all executable moves, add development programs below `/devtools/bin`, install tests below `/devtools/tests`, and copy buildable source to `/devtools/src/{red,curl,lorry,gears,moto-rt,moto-sys}`. Put Gears mock/test helpers below `/devtools/tests/gears`. Required generated executable paths must follow the new staging trees. |
| `src/imager/src/main.rs` | Manifest tests assert `/bin/{lorry,gears}`, old generated paths, and `/user/src`; update the assertions and source-directory unit-test fixtures. |
| Static image trees | Reorganize content into cumulative base, standard, and dev overlays, applied in that order; a later file overwrites the same destination from an earlier overlay. Move `bin`, `sys`, `user`, and `www` content into the proposed roots. The base tree currently contains the `www` launcher even though base has neither HTTP server nor site; remove it. The standard site and launcher move to dev-only `/devtools/www` and `/devtools/bin/www`. |
| Sysbox wrapper scripts | Every wrapper currently has `#!/bin/rush` and calls `/sys/sysbox`. Move the scripts to `/system/bin`, use `#!/system/bin/rush`, and call `/system/bin/sysbox`. The `sh` wrapper must exec `/system/bin/rush`. |
| `www` launcher | Move it to `/devtools/bin/www`; invoke `/user/bin/httpd` or `/user/bin/httpd-axum`, serve `/devtools/www`, and use certificates in `/system/cfg/ssl`. |
| Static configuration | Move `rush.cfg`, `sshd.toml`, `sys-init.cfg`, `sys-net.toml`, `sys-tty.cfg`, SSL files, and standard-only libc files under `/system/cfg`; move Kibim's syntax tree under `/user/cfg/kibim`. Update all commands and arguments in `sys-init.cfg` and `sys-tty.cfg` to `/system/services`, `/system/bin`, and `/system/cfg`. Keep the DNS line commented in base and enabled through the standard overlay. |
| Directory materialization | Add explicit directory declarations to the imager and create them before file copying. Manifests must declare every required `cfg` and `tmp` directory plus `/system/logs`; do not rely on placeholder files. Treat every listed overlay root as required, apply the list in order, and test that later roots replace earlier destinations. |

The libc configuration files are currently emitted inside the generated LLVM
static tree. `src/build-motor-os.sh` becomes their authoritative producer and
stages `/system/cfg/libc` in the separate `img_files/generated/libc` standard
overlay. This includes `hosts`, `resolv.conf`, `services`, and a `shells` file
listing `/system/bin/sh` and `/system/bin/rush`. Compiled libc programs such as
`dns-resolver` therefore do not depend on the native LLVM toolchain being
present. Base contains only pure Rust binaries and does not ship this subtree.
If dev ever needs different libc configuration, its later overlay replaces the
corresponding standard files.

`rush.cfg` and `sshd.toml` need image-specific content. Base and standard use
`/system/bin:/user/bin`; the dev overlay replaces those files with versions
that add `/devtools/bin`.
The test copy at `src/bin/russhd/tests/sshd.toml` also has `path = "/bin"` and
must follow the image under test.
Russhd's `local_session.rs` copies the configured `path` into the child
environment, while `rt.vdso` resolves bare executable names from that
environment; there is no separate runtime fallback to repair an incorrect
configuration.

### Runtime path constants

| Component | Hard-coded contract to change |
|---|---|
| `src/sys/sys-io/src/main.rs` | Starts `/sys/sys-init`; start `/system/services/sys-init`. |
| `src/sys/sys-init/src/main.rs` | Reads and reports `/sys/cfg/sys-init.cfg`; use `/system/cfg/sys-init.cfg`. |
| `src/sys/sys-tty/src/main.rs` | Reads `/sys/cfg/sys-tty.cfg`; use `/system/cfg/sys-tty.cfg`. |
| `src/sys/sys-io/src/runtime/net/{config,backlog,device,half_open}.rs` and `src/sys/sys-io/Cargo.toml` | Code and comments name `/sys/cfg/sys-net.toml`; use `/system/cfg/sys-net.toml`. |
| `src/sys/strobe/src/io_thread.rs` | Writes logs below `/sys/logs`; use `/system/logs`. |
| `src/bin/russhd/src/local_session.rs` | Motor's login shell is `/bin/rush`; use `/system/bin/rush`. Keep its configured `PATH` aligned with the image tier. |
| `src/bin/curl/src/tls.rs` | The default CA bundle and compile-time bundled test certificate use `/sys/cfg/ssl` and the matching old static-tree source path; move both to `/system/cfg/ssl`. |
| `src/bin/lorry/src/curl.rs` | The CA bundle is under `/sys/cfg/ssl` and Motor curl is `/bin/curl`; use `/system/cfg/ssl` and `/system/bin/curl`. |
| `src/bin/gears/src/net/{mod,curl,motor_curl}.rs` | Motor curl constants and documentation name `/bin/curl`; use `/system/bin/curl`. |
| `src/bin/gears/src/tools/toolchain.rs` | Motor Lorry is `/bin/lorry`; use `/devtools/bin/lorry`. |
| `src/bin/lorry/src/toolchain.rs` | Default rustc is `/sys/tools/rust/bin/rustc`; use the resolved new rustc location. |
| `src/bin/lorry/src/config.rs` | System Lorry configuration is `/sys/tools/rust/cfg/lorry.toml`; use `/devtools/cfg/lorry.toml`. User config remains `/user/cfg/lorry.toml`, and redirect policy remains `/user/cfg/lorry-redirect-sites.toml`. |
| `src/bin/lorry/bootstrap` | The tracked bootstrap tree no longer defines a separate minimal OS image; it installs the Stage 2 dependency seed into the generated native toolchain. Move its compiler, Lorry config/vendor, and staging paths to the new roots. Add Gears' locked dependency graph to `stage2-seed.toml` and its generated evidence so the dev image can rebuild both Lorry and Gears offline. Do not reintroduce a fourth image tier. |
| `src/bin/kibim/src/{config,syntax}.rs` | Read `/user/cfg/kibim/config.ini` and `/user/cfg/kibim/syntax.d`, replacing `/sys/cfg/kibim`. |
| `src/bin/rmux/src/sys/motor.rs` | Its Motor fallback for socket/lock state is `/sys/tmp`; use `/user/tmp`. |
| Rush source comments | Update examples that name `/sys/cfg/rush.cfg` and `/bin` after configuration and wrapper paths move. |

The image should provide non-active `.example` files for recognized paths that
have no currently shipped configuration: `/user/cfg/rmux.toml.example`,
`/user/cfg/gears.toml.example`,
`/user/cfg/gears/openrouter.key.example`,
`/user/cfg/lorry.toml.example`,
`/user/cfg/lorry-redirect-sites.toml.example`, and
`/user/cfg/kibim/config.ini.example`. Users explicitly copy and edit an
example to its active name; in particular, the API-key example must not
contain a real or syntactically accepted secret. Their first tier follows the
owning program: Rmux in base, Kibim in standard, and Gears/Lorry in dev. Red's
`/user/cfg/red.toml` and Rush's `/user/cfg/rush.toml` already fit the layout.

### Temporary-directory contracts

The agreed temp contract is: honor `TMPDIR` first; use `/user/tmp` when it is
unset for ordinary programs; and set it to `/devtools/tmp` in compiler
launchers and development-test harnesses. `TMPDIR` has this meaning in POSIX,
so Motor uses the existing portable convention rather than introducing
another variable. The current implementation differs in several places:

- `src/sys/lib/moto-rt/src/fs.rs` defines `TEMP_DIR` as `/sys/tmp`, and the
  adjacent Rust port's `library/std/src/sys/paths/motor.rs` returns that
  constant directly. It does not inspect `TMPDIR`. Change it to honor
  `TMPDIR`, with `/user/tmp` as the fallback. This affects Red saves, Rush
  scratch, Sysbox temporary work, tests using `std::env::temp_dir()`, and other
  compiled applications. Because this is a `moto-rt` change, it requires the
  separate review/vetting required for that component.
- Rmux independently honors `TMPDIR` and otherwise falls back to `/sys/tmp`;
  its fallback changes to `/user/tmp`.
- Lorry and Gears have many production `std::env::temp_dir()` call sites
  (admission/review/vendor/cache staging, registries, self-hosting, tool runs,
  VCS/filesystem/provider work, and trace output). As direct executables they
  use the ordinary runtime rule: honor `TMPDIR` and otherwise use `/user/tmp`.
  Lorry's explicit Motor test-extraction default remains below `/user/tmp`.
- Rush sets `TMPDIR=/user/tmp` only when it is absent, including for
  non-interactive sessions where an `ENV` startup file is not sourced. The
  `cc`, `c++`, and `rustc` launchers replace it with `/devtools/tmp` before
  starting the real tool. Gears, Lorry, Lua, Mdbg, and directly invoked LLVM
  deliberately retain the ordinary `/user/tmp` default.
- `src/sys/tests/systest/src/{file_locking,pressure}.rs` explicitly use
  `/sys/tmp`; development tests use `/devtools/tmp`. Harnesses running uploaded
  tests set `TMPDIR=/devtools/tmp`, and other Rust tests follow that override
  through the standard-library implementation.
- `/system/tmp` should be reserved for scratch owned by services. No audited
  general language-runtime default should point there.

The adjacent C/C++ toolchain has additional compiled-in defaults:

| Adjacent source | Finding and required change |
|---|---|
| `../mlibc/options/posix/include/bits/posix/posix_stdio.h` | Motor `P_tmpdir` is `/sys/tmp`; make its fallback `/user/tmp`. |
| `../mlibc/options/ansi/generic/stdio.cpp` | `tmpfile()` and `tmpnam()` hard-code `/tmp`; make Motor honor `TMPDIR` and fall back to `/user/tmp`. |
| `../mlibc/options/glibc/include/paths.h` | Under Motor, set `_PATH_DEFPATH` and `_PATH_STDPATH` to `/system/bin:/user/bin`, `_PATH_BSHELL` to `/system/bin/sh`, and temp-path macros to `/user/tmp`. Do not rewrite unrelated unsupported Unix compatibility macros. |
| `../mlibc/options/ansi/generic/stdlib.cpp` | Motor `system()` explicitly launches `/bin/rush`; use `/system/bin/rush`. |
| `../mlibc/options/posix/generic/unistd.cpp` | Under Motor, make `_CS_PATH` and `execvpe()`'s default search path `/system/bin:/user/bin`. Leave other platforms unchanged. |
| `../mlibc` shell consumers | Update active Motor shell literals used by `getusershell()`, `wordexp()`, and supported process helpers to `/system/bin/sh` or `/system/bin/rush` as appropriate. Do not rewrite inactive generic literals for other targets. |
| `../llvm-project/llvm/lib/Support/Unix/Path.inc` | No change is needed: it already honors the standard temp environment variables before falling back to mlibc's `P_tmpdir`, which becomes `/user/tmp`. |
| `../llvm-project/libcxx/src/filesystem/operations.cpp` | `temp_directory_path()` falls back to `/tmp`; Motor C++ applications should fall back to `/user/tmp`. |
| `../rust/library/std/src/process/tests.rs` | Non-Android shell tests currently select `/bin/sh`; add the Motor `/system/bin/sh` case when the adjacent Rust port is updated. |

mlibc's `MLIBC_SYSCONFDIR` consumers for hosts, resolver, services, protocols,
users/groups, timezone, shadow data, and shells move together when the build
macro becomes `/system/cfg/libc`. Update the explanatory comment in
`options/internal/include/mlibc/sysconfdir.hpp` as well. Other generic mlibc
compatibility macros and unsupported APIs that still advertise Unix `/bin`,
`/dev`, `/etc`, `/proc`, `/usr`, or `/var` paths are explicitly outside this
filesystem migration. Active Motor-specific paths, such as `system()`'s Rush
executable, still move because the old executable will no longer exist.

During local Rust-toolchain builds, temporarily repoint the adjacent Rust
standard library's `moto-rt` dependency to this checkout's
`src/sys/lib/moto-rt`. Restore the normal published/fork dependency and lock
state before handoff so no absolute sibling path is committed. Implement
`std::env::temp_dir()` in the Rust port by inspecting `TMPDIR` and falling back
to `/user/tmp`; it must not require a newly published `moto-rt` merely to test
the layout change.

### Rust toolchain layout decision

The proposed Rust split is incompatible with the current Motor rustc sysroot
discovery. In the adjacent Rust tree,
`compiler/rustc_session/src/filesearch.rs` obtains the Motor executable path,
walks up from the compiler, and expects the usual `$sysroot/bin/rustc` plus
`$sysroot/lib/rustlib` relationship. With `/devtools/bin/rustc` and
`/devtools/rust/lib`, rustc would infer `/devtools` and search the intentionally
absent `/devtools/lib`.

The selected design preserves rustc's conventional relative layout: install
the real compiler at `/devtools/rust/bin/rustc` beside
`/devtools/rust/lib`, and expose `/devtools/bin/rustc` as a Rush launcher.
The launcher also sets `TMPDIR=/devtools/tmp`. Motor does not require symlink
support for this arrangement.

The adjacent clang driver has the same kind of compiled-in layout contract:
`../llvm-project/clang/lib/Driver/ToolChains/Motor.cpp` names
`/sys/tools/llvm/{include,lib}` for headers, C++ headers, CRT, and library
search. All of those literals and their tests must become `/devtools/llvm`.

### Tests and verification scripts

No tests are to be run during this planning change. When implementation starts,
the following test contracts need updates:

| Test area | Required migration |
|---|---|
| `src/tests/full-test.sh` | Make this strictly the standard-image suite. Create `/devtools`, `/devtools/tests`, and `/devtools/tmp` in the running test VM through SFTP; upload `systest`, `mio-test`, and the other required test executables instead of packaging them; and run them from `/devtools/tests` with `TMPDIR=/devtools/tmp`. Standard still covers DNS, rg, production servers/tools, and its PATH. Remove native compiler checks from this entry point. |
| `src/tests/full-test-dev.sh` | Keep its dev-image override and add compiler, Gears, and Lorry coverage. Verify `/devtools/src`, the dev PATH addition, real and launcher toolchain locations, and `/devtools/tmp`. |
| `src/tests/full-test-networking.sh` | Move ping/stats/kill/Rush to `/system/bin` and DNS to `/system/services`. Upload any non-image test tools to their `/devtools` destinations before use and set `TMPDIR=/devtools/tmp`. Host `/tmp/*.log` redirections do not change. |
| `src/tests/stress-soak.sh` | Update system/user paths and upload Mdbg, tests, or other dev-only diagnostics needed by a standard-image run into `/devtools` rather than packaging them in standard. Move filesystem churn and transient root files to `/devtools/tmp`, with `TMPDIR` set accordingly. The bundled site remains available only when this script deliberately selects dev or uploads its fixture. |
| `src/tests/test-{tui,terminal-size,sftp}.sh` | Move Rmux to `/user/bin` and wrappers to `/system/bin`; create `/devtools/tests` and `/devtools/tmp`, upload required tests, and run them with `TMPDIR=/devtools/tmp`. The checked log moves to `/system/logs`, and the SFTP upload fixture moves to `/devtools/tmp`. |
| `src/bin/{rush,rmux}/tests/vm-console-check.py` | Update explicit Rush, Rmux, and Sysbox-wrapper paths, and set `TMPDIR=/devtools/tmp` for VM development tests. Linux-only `/bin/dash` conformance constants remain host paths. |
| `src/sys/tests/systest` | Move config/log/Sysbox/wrapper constants to `/system`; make all temporary paths honor `TMPDIR`, falling back to `/user/tmp`. Harnesses set `TMPDIR=/devtools/tmp` for development tests. Move `/foo`, `/bar`, `/hot`, `/systest-*`, `/stdio-*`, and other transient root files under that selected temp directory in preparation for later root permission enforcement. |
| Lorry native/bootstrap/integration scripts under `src/bin/lorry` and `src/tests/lorry-*` | Update generated sysroots, compilers, curl, CA bundle, Lorry config/vendor repository, wrapper commands, seed manifests, guest-layout assertions, and guest scratch paths. Preserve host workspaces below Linux `/tmp`. |
| Lorry and Gears unit fixtures | Update fixtures in the affected source modules that assert Motor defaults such as `/bin/lorry`, `/bin/curl`, `/bin/cc`, `/sys/tools`, or `/sys/cfg`. Do not rewrite host-only `/bin/true`, `/bin/sh`, and synthetic `/tmp` parser examples. |
| Curl and imager tests | Update the compile-time SSL fixture source under `img_files`, expected generated paths, manifest destinations, and source-copy fixtures. |

Tests may create the otherwise absent `/devtools` tree in a running base or
standard test VM; this does not make it packaged image content. The root will
be made read-only in a later filesystem-permissions project, so the migrated
tests must already avoid transient files directly under `/`.

Add explicit assertions for both configuration entry points: interactive Rush
and russhd sessions must see `/system/bin:/user/bin` on base/standard and the
same value plus `/devtools/bin` on dev. Also assert that base neither contains
nor starts `dns-resolver`, and that `/system/bin` contains no services.

### Documentation follow-up

Active build, usage, and porting-guide documentation containing guest paths
must be updated with the implementation. The audited set is:

- `docs/build-llvm.md`, `docs/build-motor-os.md`, `docs/build-rustc.md`,
  `docs/dns-mlibc.md`, and `docs/tools.md`;
- the libc-porting guides under `docs/porting-libc`, which remain in the
  repository and receive updated paths;
- active plans with path contracts: `docs/plans/aws-lc-rs-port.md`,
  `curl.md`, `less-paging.md`, `networking-remaining-steps.md`,
  `rust-analyzer.md`, and `toolchain.md`;
- Gears' proposal and step-by-step plans, Lorry's README/spec/curl
  interaction, and Rmux's design details.

`docs/dns-mlibc.md` likewise remains and receives updated paths. Current build
instructions, architecture statements, porting guides, and active plans must
all use the new layout.

### Hard-coded host paths that do not change

Not every `/bin`, `/sys`, or `/tmp` found by a textual search is a Motor guest
path. Keep these categories unchanged:

- Linux interpreters and utilities in build/test scripts (`/bin/bash`,
  `/bin/sh`, `/usr/bin/*`) and Linux-only test fixtures such as `/bin/true`;
- synthetic absolute paths used only to exercise parsers or lexical
  canonicalization, when the test is not asserting an installed Motor path;
- host checkout paths (`src/bin`, `src/sys`, `../llvm-project`, `../mlibc`,
  `../rust`, and the outer `../motor-sysroot` directory name);
- host VM plumbing and logs in `src/vm_scripts` and test harnesses, including
  `/tmp` sockets, lock files, QEMU logs, and `mktemp` workspaces;
- host devices and pseudo-filesystems such as `/dev/kvm` and `/proc`.

This distinction should be preserved in the implementation sweep so the root
filesystem migration does not rewrite Linux-host build infrastructure.

## Resolved review decisions

All three review answers are actionable once they are reconciled with the
current source tree:

1. The tracked Lorry bootstrap no longer has a minimal OS-image manifest. The
   dev/full image is therefore the one self-hosting seed. It contains the
   native toolchains, Lorry, Gears, their materialized source trees, the Motor
   runtime crates those sources need, and the locked offline dependency
   repository needed to build both programs. No fourth image or DNS exception
   is created.
2. Direct Gears, Lorry, Lua, Mdbg, and LLVM invocations use the simplest
   runtime behavior: honor `TMPDIR`, otherwise fall back to `/user/tmp` through
   Rust std, libc, or libc++. Only the `cc`, `c++`, and `rustc` launchers and
   development-test harnesses force `/devtools/tmp`.
3. `src/build-motor-os.sh` generates the authoritative standard libc
   configuration in `img_files/generated/libc/system/cfg/libc`. Standard and
   dev consume that required overlay; base does not. The script absorbs and
   replaces `src/build-dev.sh` and remains the required first-checkout build.

Approval of this plan also vets the narrowly scoped Motor changes to
`src/sys/lib/moto-rt` and the adjacent Rust standard library required to make
their public temporary-directory behavior match decision 2.

## Autonomous implementation plan

Implementation proceeds in the following order. Each source change is kept to
roughly 100–300 lines including focused tests wherever practical. No repository
is committed by the implementer. A failing check is diagnosed and fixed at its
source; retries, longer timeouts, ignored failures, and test weakening are not
acceptable migration techniques.

### 1. Record baselines and protect existing work

1. Record branch, upstream, status, and diff summaries for Motor OS and the
   sibling `mlibc`, `llvm-project`, `rust`, and `ripgrep` repositories.
2. Preserve the existing edit to this document and the existing untracked
   `../rust/bootstrap.toml.pre-rustc`; do not clean, reset, or overwrite any
   preexisting user change.
3. Run the current focused imager tests and one debug and one release
   `src/tests/full-test.sh` baseline. If a baseline fails, diagnose it before
   attributing a later failure to the migration. An unrelated non-test defect
   remains a stop condition under the repository guidelines.
4. Save a classified legacy-path inventory. Linux-host paths, source-tree
   names, VM plumbing, and synthetic parser fixtures stay unchanged; only
   Motor guest paths are migration targets.

### 2. Teach the imager the complete layout

1. Add a validated ordered list of explicit image directories to the YAML
   schema. Directory paths must be normalized absolute guest paths, and the
   imager creates them before installing files.
2. Make every listed static/generated overlay root required and apply roots in
   declaration order. Remove the separate optional/required ordering ambiguity.
   Add unit tests for missing roots, invalid directory declarations, empty
   directories, and later-overlay-wins behavior.
3. Declare the complete cumulative trees in each manifest. Base declares the
   `/system` and `/user` roots and their `bin`, `cfg`, `services`, `logs`, and
   `tmp` descendants. Standard additionally declares `/system/cfg/libc` and
   Kibim's user configuration tree. Dev additionally declares `/devtools` and
   its `bin`, `cfg/llvm`, `llvm/{bin,include,lib}`, `rust/{bin,lib}`, `lorry`,
   `src`, `tests/gears`, `tmp`, and `www` descendants.
4. Set overlay order exactly to base static; standard static and generated
   libc/rg; then dev static and generated LLVM/Rust content. Later tiers own
   intentional Rush and russhd overrides.
5. Rewrite manifest tests to assert tier membership, executable ownership,
   required generated files, explicit empty directories, service separation,
   and the absence of top-level `/bin`, `/sys`, and `/www`.

### 3. Reorganize static overlays and image membership

1. Move common static files into the base overlay, standard additions into the
   standard overlay, and dev-only additions into the dev overlay. Remove
   placeholder files that existed solely to materialize directories.
2. Move Sysbox and wrapper scripts to `/system/bin`, services to
   `/system/services`, user programs to `/user/bin`, configuration to its
   owning `cfg` tree, and the bundled site to `/devtools/www`. Rewrite script
   interpreters and absolute commands at the same time.
3. Supply base/standard Rush and russhd defaults with
   `PATH=/system/bin:/user/bin`; replace them in dev with the value ending in
   `/devtools/bin`. Keep DNS commented in base and enabled in standard.
4. Add safe, inactive configuration examples for Rmux, Kibim, Gears, and
   Lorry. The OpenRouter key example must be an obviously invalid placeholder.
5. Split Make prerequisites into base, standard additions, and dev additions;
   add an `images` aggregate while keeping `all` on standard. Set data
   partitions to 64 MiB base, 256 MiB standard, and 2048 MiB dev. Update
   `MOTOR_DNS_SDK` to the `/devtools/llvm` sysroot mirror.
6. Build the imager and all three manifest unit tests before continuing.

### 4. Migrate Motor runtime and application paths

1. Change service startup, system configuration, logging, shell, SSL, curl,
   Kibim, Lorry, Gears, Rmux, and toolchain constants using the catalog above.
   Update each component's existing unit fixtures in the same patch.
2. In Rush environment initialization, set `TMPDIR=/user/tmp` only when it is
   absent. This must cover interactive, console, and non-interactive russhd
   sessions without depending on an `ENV` startup file.
3. Change `moto_rt::fs::TEMP_DIR` to `/user/tmp`. Change the Rust standard
   library separately to inspect `TMPDIR`, so its behavior does not depend on
   publishing a new `moto-rt` release during this work.
4. Move Systest's explicit and root-level scratch files below its selected temp
   directory. Ordinary tests fall back to `/user/tmp`; development harnesses
   supply `/devtools/tmp`.
5. Format every Rust patch with `cargo +nightly fmt`, run the owning crate's
   focused tests, and verify no compiler or Clippy warning was introduced.

### 5. Update and test the adjacent C/C++ repositories

1. In `../mlibc`, guard Motor-specific changes for `P_tmpdir`, `tmpfile()`,
   `tmpnam()`, `system()`, `_CS_PATH`, `execvpe()`'s default search path,
   `paths.h`, active shell lookup, and `MLIBC_SYSCONFDIR`. Other targets and
   unsupported compatibility constants remain untouched.
2. Add native Motor C coverage for absent and explicit `TMPDIR`, `P_tmpdir`,
   `tmpfile()`/`tmpnam()`, `system()`, `_CS_PATH`, default executable search,
   and shell enumeration where the API is supported. Generate `shells` with
   `/system/bin/sh` and `/system/bin/rush` so the test is deterministic.
3. In `../llvm-project`, change Clang's Motor include, library, resource, and
   CRT roots to `/devtools/llvm`; add/update a Motor driver test that asserts
   the emitted search paths. Give libc++ filesystem's Motor temp fallback
   `/user/tmp` and test explicit environment precedence.
4. Do not add an LLVM-specific `/devtools/tmp` default: LLVM's existing
   environment checks plus mlibc's new `P_tmpdir` implement the resolved
   direct-tool rule.
5. Build and run the affected mlibc, Clang driver, and libc++ checks before a
   full toolchain build. Leave both sibling repositories dirty and uncommitted.

### 6. Update and test the adjacent Rust repository

1. In `../rust`, make Motor `std::env::temp_dir()` honor `TMPDIR` and fall back
   to `/user/tmp`; change Motor process tests to `/system/bin/sh`. Add focused
   absent/explicit environment coverage.
2. Keep the real compiler and library sysroot together at
   `/devtools/rust/{bin,lib}`. Do not change rustc sysroot discovery.
3. For the local toolchain build only, point `library/std`'s `moto-rt`
   dependency at this Motor checkout and update lock state deliberately. Do
   not use the existing failure-ignoring Cargo update commands in
   `src/build-motor-os.sh`; each required dependency update either succeeds or
   the build stops with its diagnostic.
4. Restore the published dependency declaration and corresponding lock state
   after successful local verification. The final Rust diff must contain no
   absolute local path.

### 7. Consolidate generation and first-checkout builds

1. Fold `src/build-dev.sh` into `src/build-motor-os.sh`, update callers, and
   retire the old script. Preserve `src/build-base.sh` as the focused base
   builder, but remove its obsolete mlibc/DNS gate.
2. Repoint every build input to the existing sibling checkouts for local work:
   `../mlibc`, `../llvm-project`, and `../rust`. Preserve their branches and
   dirty changes rather than cloning over them. Seed Rust's LLVM submodule
   from the sibling LLVM repository as the existing workflow intends, and
   restore its configured origin to the moturus fork after the local build.
3. Mirror the guest LLVM sysroot below `motor-sysroot/devtools/llvm`. Update
   Meson/CMake prefixes, `MLIBC_SYSCONFDIR`, Clang config/resource paths, CRT
   probes, C-ABI shim copies, stale-tree cleanup, and native linker commands.
4. Generate four independent roots: LLVM and Rust under `/devtools`, ripgrep
   under `/system/bin`, and libc configuration under `/system/cfg/libc`.
   Standard must require only rg/libc generated content; dev requires all four.
5. Generate `cc`, `c++`, and `rustc` Rush launchers that force
   `TMPDIR=/devtools/tmp`; keep LLVM, Lua, Mdbg, Lorry, and Gears as direct
   executables. Validate every expected generated executable before imaging.
6. End the unified workflow by building and reporting base, standard, and dev
   artifacts separately. A standard build must never consume the staged native
   toolchains merely because the workflow produced them earlier.

### 8. Make the dev image genuinely self-hosting

1. Extend the dev-source preparation step to materialize Red, curl, Lorry, and
   Gears plus `moto-rt` and `moto-sys` under `/devtools/src`; never copy host
   `target` directories.
2. In staged copies only, rewrite Motor target path dependencies to sibling
   paths such as `../moto-rt` and `../moto-sys`. Materialize the vendored
   crossterm patch for both Red and Gears. Canonical repository manifests keep
   their normal source dependencies.
3. Add Gears' lock graph to `src/bin/lorry/bootstrap/stage2-seed.toml`, update
   its package closure/count/evidence, and run the bootstrap Python tests.
   Every locked Lorry and Gears dependency must resolve from `/devtools/lorry`
   without Internet access.
4. Package Gears mock-provider/frame/measurement helpers and their fixtures
   below `/devtools/tests/gears`, not as production commands.
5. On Motor OS, use the packaged source and offline repository to build Red,
   curl, Lorry, and Gears. Then use the newly built Lorry to build Gears once
   more. This is the acceptance test for the self-hosting claim.

### 9. Separate standard and development test contracts

1. Keep `src/tests/full-test.sh` a standard-image test. Before creating any
   development test directory, assert that standard packages no `/devtools`
   tree or toolchain. Upload host-built test executables through SFTP into
   `/devtools/tests`, create `/devtools/tmp`, and run them with that `TMPDIR`.
2. Keep production DNS, curl, rg, HTTP, Kibim, Rush, russhd, Red, Rmux, and
   service tests in the standard suite. Test both interactive and SSH PATH
   values and assert that `/system/bin` contains no services.
3. Make `src/tests/full-test-dev.sh` add compiler/linker execution, C/C++/Rust
   temp-contract fixtures, dev PATH, source-layout, Gears, Lorry, and offline
   self-host coverage. Have it invoke the component Lorry and Gears test gates
   transitively.
4. Migrate networking, soak, TUI, terminal-size, SFTP, Rush/Rmux console,
   Systest, Lorry, Gears, Curl, and imager scripts using the catalog. Uploaded
   diagnostics live under `/devtools`; host `/tmp`, Linux `/bin`, and synthetic
   fixtures remain unchanged.
5. Ensure every new test is included in `src/tests/full-test.sh` or
   `src/tests/full-test-dev.sh` transitively. Do not add network access beyond
   the already approved Internet-facing DNS/ping integration checks.

### 10. Update documentation with the implementation

1. Update every document under `docs/porting-libc/`, including build flags,
   sysroot examples, configuration locations, shell/default-path behavior,
   temp behavior, and validation commands.
2. Update the active build/toolchain, DNS, tools, Lorry, Gears, Rmux, and plan
   documents listed in the audit. Historical source checkout names and Linux
   host commands stay unchanged; runnable Motor guest commands use the new
   paths.
3. Document the three image tiers, cumulative overlays, PATH/TMPDIR contracts,
   generated libc ownership, self-hosting contents, and the unified
   first-checkout command. Remove references to the retired Lorry image and
   `src/build-dev.sh`.
4. Run a final documentation and source search for old guest paths and classify
   every remaining match rather than applying an unreviewed global rewrite.

### 11. Final build and reliability gate

1. Run focused imager, Lorry (`src/bin/lorry/tests/test-all.sh`), Gears, Curl,
   Rush/Rmux, and affected adjacent-repository tests. Run formatting and
   warning/Clippy checks for all changed Rust components.
2. From clean generated output, run the unified build in debug and release and
   verify all three image artifacts, their configured sizes, and their
   manifest contents.
3. Because this touches core `src/sys` code, run
   `src/tests/full-test.sh` successfully three consecutive times in debug and
   three consecutive times with `--release`. A failure resets the consecutive
   count only after its root cause is fixed; it is never masked with a retry.
4. Run the complete dev-image suite at least once in debug and once in release,
   including native self-hosting. Confirm there are no new warnings and no
   measurable extra boot-time work; this migration adds only host-side image
   construction and path changes.

### 12. Restore fork dependencies and hand off uncommitted work

1. Remove all temporary local Cargo paths, submodule overrides, and build
   configuration. Restore dependency declarations and URLs to the moturus Git
   forks or their normal published versions. Do not remove the actual source
   edits in Motor OS or the sibling repositories.
2. Verify tracked diffs contain no `/home/posk`, sibling-relative dependency,
   generated build product, cache, or accidental lockfile change. Report any
   preserved preexisting untracked files separately.
3. Report final branch/upstream/status summaries and the exact repositories
   requiring publication. The expected set is Motor OS plus `../mlibc`,
   `../llvm-project`, and `../rust`; `../ripgrep` should remain unchanged.
4. The human publication order is: commit/push mlibc and LLVM, commit/push
   Rust (updating its LLVM gitlink only if the final Rust diff actually relies
   on the new LLVM commit), then rebuild/retest and commit Motor OS. The
   implementer makes none of these commits.
5. The handoff includes the successful command matrix and any remaining
   classified legacy-path matches. After dependencies are restored to remote
   forks, the human's final rebuild is intentionally the proof that all
   published references are complete.
