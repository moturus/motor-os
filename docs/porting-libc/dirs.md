# Relocating the on-image toolchain directories

Motor's libc/toolchain port keeps the default locations out of the classic
Unix `/usr` + `/etc` trees and uses the ownership-based `/devtools` and
`/system` trees instead.

| What | Old | New |
| --- | --- | --- |
| clang/llvm headers + libs | `/usr/{include,lib}` | `/devtools/llvm/{include,lib}` |
| clang resource dir | `/usr/lib/clang/<N>` | `/devtools/llvm/lib/clang/<N>` |
| clang `<triple>.cfg` | `/etc` | `/devtools/cfg/llvm` |
| mlibc config files | `/etc` | `/system/cfg/libc` |

Two things are compiled into binaries (the clang driver paths and one cmake
default); everything else is just where files land in the sysroot and the image.

## Part A — LLVM / clang (`/usr` → `/devtools/llvm`, `/etc` → `/devtools/cfg/llvm`)

1. **Clang driver source — `clang/lib/Driver/ToolChains/Motor.cpp`.** The four
   hardcoded `D.SysRoot + "/usr/..."` literals become `.../devtools/llvm/...`
   (keep the `D.SysRoot +` prefix — it's what makes host cross-builds resolve
   under `--sysroot`): crt1.o path, the `-L…/usr/lib`, the C include
   `…/usr/include`, and the C++ include `…/usr/include/c++/v1`. Best done as a
   single `MotorPrefix = "/devtools/llvm"` constant. **Requires rebuilding both
   stage-1 host clang and the stage-6 native `llvm` multicall** (paths are
   compiled in).

2. **Config-file discovery — one cmake flag (stage 6).** In the native build,
   `-DCLANG_CONFIG_FILE_SYSTEM_DIR=/etc` → `=/devtools/cfg/llvm` (the compiled-in dir
   where the driver auto-loads `<triple>.cfg`). **Wipe `build-motor-native` and
   reconfigure** (cmake caches it). Host stage-1 doesn't set this — it finds the
   cfg next to the binary — so no host change for config discovery.

3. **Build-tree layout (the ripple)** — `build-llvm.md` + `build-llvm.sh`.
   Because host cross-compiles hit `--sysroot=$SYSROOT` and the driver now looks
   under `devtools/llvm`, the **staged host SYSROOT must adopt the new layout
   too**, not just the image. Every `$SYSROOT/usr/{include,lib}` →
   `$SYSROOT/devtools/llvm/{include,lib}`: mlibc meson `--prefix`, the
   cross-file `-isystem`, the C++-runtimes & Lua `-isystem`/`-L`/`crt1.o`
   recipes, the builtins sysroot copy.

4. **Image staging (stage 8).** Generated roots map to the image root. Stage
   headers, libraries, and the resource directory into
   `$MOTORH/assemblies/<assembly-key>/images/llvm/devtools/llvm/...`; stage the
   driver config into the `devtools/cfg/llvm/` subtree of that root with its
   body updated to `-resource-dir /devtools/llvm/lib/clang/<N>`.

5. **Docs / verify text.** Update the prose and the "Verify in the VM" examples
   to use `/devtools/src/hello.*`, plus the memory note.

Net for Part A: **2 compiled-in edits** (Motor.cpp + the cmake flag, both
needing a driver rebuild) plus **path relocations** in the sysroot build and
image staging.

## Part B — mlibc config files (`/etc` → `/system/cfg/libc`)

mlibc hardcodes classic `/etc/*` paths across upstream option layers (inventory
in appendix H.8). Repoint them with a single **compile-time prefix macro**
rather than a per-file patch:

- Introduce `MLIBC_SYSCONFDIR`, default `"/etc"` (an `#ifndef` fallback in a
  central internal header). Rewrite the hardcoded `"/etc/..."` string literals
  to `MLIBC_SYSCONFDIR "/..."` (C string concatenation) at the call sites, and
  in the `_PATH_*` / `MOUNTED` macro bodies.
- **Override for Motor** by adding `-DMLIBC_SYSCONFDIR="/system/cfg/libc"` to the
  Motor meson **cross-file** `c_args`/`cpp_args` — the same injection point that
  already carries `-D_GNU_SOURCE`. This keeps the change Motor-contained; the
  shared meson.build is untouched.
- **Stage** the config files under
  `$MOTORH/assemblies/<assembly-key>/images/libc/system/cfg/libc/`. This
  separate generated overlay is consumed by the standard image without
  pulling in the development-only LLVM tree.

Functional call sites to route through the macro (from H.8 + a grep):
`resolv_conf.cpp` (`/etc/resolv.conf`), `lookup.cpp` (`/etc/hosts`, ×2),
`netdb.cpp` (`/etc/protocols`), `pwd.cpp` / `grp.cpp` (`/etc/passwd`,
`/etc/group`), `unistd.cpp` (`/etc/shells`), `time.cpp` (`/etc/localtime`, ×3),
`shadow.cpp` (`/etc/shadow`, `/etc/tcb/*`). The public `_PATH_*` macros also use
the Motor layout. In particular, the Motor sysdep installs the standalone
`paths.h` even though Motor does not enable mlibc's broader glibc-compat option;
its default search path, shell, and temporary paths therefore agree with the
runtime defaults. Unrelated compatibility macros in `paths.h`, `netdb.h`,
`resolv.h`, `fstab.h`, and `mntent.h` remain upstream Unix declarations; the
active runtime readers, rather than those unsupported public constants, use
`MLIBC_SYSCONFDIR`.

*Rejected alternative:* rewriting a leading `/etc/` → `/system/cfg/libc/` inside the
Motor sysdep `open()` layer. It touches zero upstream files but is fragile and
surprising — it would also silently capture a program's own `/etc` access, not
just libc's config reads. Don't.

Part B needs only an **mlibc rebuild + restage** — no clang rebuild.

## Rebuild triggers at a glance

- Part A step 1 (Motor.cpp) → rebuild host clang **and** native `llvm`.
- Part A step 2 (cmake flag) → wipe + reconfigure `build-motor-native`.
- Part A steps 3–4 → rerun the affected build/stage steps (no compiled-in change).
- Part B → rebuild mlibc, restage its config files.
