# Relocating the on-image toolchain directories

Goal: move the default locations away from the classic Unix `/usr` + `/etc`
into Motor's own `/sys` tree.

| What | Old | New |
| --- | --- | --- |
| clang/llvm headers + libs | `/usr/{include,lib}` | `/sys/tools/llvm/{include,lib}` |
| clang resource dir | `/usr/lib/clang/<N>` | `/sys/tools/llvm/lib/clang/<N>` |
| clang `<triple>.cfg` | `/etc` | `/sys/cfg/llvm` |
| mlibc config files | `/etc` | `/sys/cfg/libc` |

Two things are compiled into binaries (the clang driver paths and one cmake
default); everything else is just where files land in the sysroot and the image.

## Part A — LLVM / clang (`/usr` → `/sys/tools/llvm`, `/etc` → `/sys/cfg/llvm`)

1. **Clang driver source — `clang/lib/Driver/ToolChains/Motor.cpp`.** The four
   hardcoded `D.SysRoot + "/usr/..."` literals become `.../sys/tools/llvm/...`
   (keep the `D.SysRoot +` prefix — it's what makes host cross-builds resolve
   under `--sysroot`): crt1.o path, the `-L…/usr/lib`, the C include
   `…/usr/include`, and the C++ include `…/usr/include/c++/v1`. Best done as a
   single `MotorPrefix = "/sys/tools/llvm"` constant. **Requires rebuilding both
   stage-1 host clang and the stage-6 native `llvm` multicall** (paths are
   compiled in).

2. **Config-file discovery — one cmake flag (stage 6).** In the native build,
   `-DCLANG_CONFIG_FILE_SYSTEM_DIR=/etc` → `=/sys/cfg/llvm` (the compiled-in dir
   where the driver auto-loads `<triple>.cfg`). **Wipe `build-motor-native` and
   reconfigure** (cmake caches it). Host stage-1 doesn't set this — it finds the
   cfg next to the binary — so no host change for config discovery.

3. **Build-tree layout (the ripple)** — `build-llvm.md` + `build-llvm.sh`.
   Because host cross-compiles hit `--sysroot=$SYSROOT` and the driver now looks
   under `sys/tools/llvm`, the **staged host SYSROOT must adopt the new layout
   too**, not just the image. Every `$SYSROOT/usr/{include,lib}` →
   `$SYSROOT/sys/tools/llvm/{include,lib}`: mlibc meson `--prefix`, the
   cross-file `-isystem`, the C++-runtimes & Lua `-isystem`/`-L`/`crt1.o`
   recipes, the builtins sysroot copy.

4. **Image staging (stage 8).** `img_files/motor-os/` maps to image root and
   `/sys` already ships real content (e.g. `/sys/tmp`), so stage into the new
   tree: headers/libs/resource-dir → `img_files/motor-os/sys/tools/llvm/...`;
   config → `img_files/motor-os/sys/cfg/llvm/x86_64-unknown-motor.cfg` with its
   body updated to `-resource-dir /sys/tools/llvm/lib/clang/<N>`.

5. **Docs / verify text.** Update the prose and the "Verify in the VM" examples
   that reference `/usr/src/hello.*`, plus the memory note.

Net for Part A: **2 compiled-in edits** (Motor.cpp + the cmake flag, both
needing a driver rebuild) plus **path relocations** in the sysroot build and
image staging.

## Part B — mlibc config files (`/etc` → `/sys/cfg/libc`)

mlibc hardcodes classic `/etc/*` paths across upstream option layers (inventory
in appendix H.8). Repoint them with a single **compile-time prefix macro**
rather than a per-file patch:

- Introduce `MLIBC_SYSCONFDIR`, default `"/etc"` (an `#ifndef` fallback in a
  central internal header). Rewrite the hardcoded `"/etc/..."` string literals
  to `MLIBC_SYSCONFDIR "/..."` (C string concatenation) at the call sites, and
  in the `_PATH_*` / `MOUNTED` macro bodies.
- **Override for Motor** by adding `-DMLIBC_SYSCONFDIR="/sys/cfg/libc"` to the
  Motor meson **cross-file** `c_args`/`cpp_args` — the same injection point that
  already carries `-D_GNU_SOURCE`. This keeps the change Motor-contained; the
  shared meson.build is untouched.
- **Stage** the config files under `img_files/motor-os/sys/cfg/libc/` (today the
  only one is `img_files/motor-os/etc/resolv.conf`).

Functional call sites to route through the macro (from H.8 + a grep):
`resolv_conf.cpp` (`/etc/resolv.conf`), `lookup.cpp` (`/etc/hosts`, ×2),
`netdb.cpp` (`/etc/protocols`), `pwd.cpp` / `grp.cpp` (`/etc/passwd`,
`/etc/group`), `unistd.cpp` (`/etc/shells`), `time.cpp` (`/etc/localtime`, ×3),
`shadow.cpp` (`/etc/shadow`, `/etc/tcb/*`). The public `_PATH_*` macros
(`paths.h`, `netdb.h` `_PATH_SERVICES`, `resolv.h` `_PATH_RESCONF`, `fstab.h`,
`mntent.h` `MOUNTED`) are API surface nothing on Motor consumes yet — repoint
them for consistency or defer.

*Rejected alternative:* rewriting a leading `/etc/` → `/sys/cfg/libc/` inside the
Motor sysdep `open()` layer. It touches zero upstream files but is fragile and
surprising — it would also silently capture a program's own `/etc` access, not
just libc's config reads. Don't.

Part B needs only an **mlibc rebuild + restage** — no clang rebuild.

## Rebuild triggers at a glance

- Part A step 1 (Motor.cpp) → rebuild host clang **and** native `llvm`.
- Part A step 2 (cmake flag) → wipe + reconfigure `build-motor-native`.
- Part A steps 3–4 → rerun the affected build/stage steps (no compiled-in change).
- Part B → rebuild mlibc, restage its config files.
