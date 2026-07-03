# Appendix A — M0, step by step

> Part of the Motor OS libc porting guide — main: [porting-libc-by-fable.md](porting-libc-by-fable.md); appendices: [A: M0 toolchain](porting-libc-appendix-a.md) · [B: M1 shim](porting-libc-appendix-b.md) · [C: M2 mlibc](porting-libc-appendix-c.md) · [D: M3 stdio+malloc](porting-libc-appendix-d.md) · [E: M4 filesystem](porting-libc-appendix-e.md) · [F: M5 threads+TLS](porting-libc-appendix-f.md) · [G: M6 sockets](porting-libc-appendix-g.md)

> **Status: complete** (2026-07-01) — `m0` runs on Motor OS, exits 42.

Host layout assumed (verified on this machine): `/home/posk/motorh/{motor-os, rust,
mlibc}`; host tools `clang 18.1.3`, `cmake 3.28.3`, `ninja 1.11.1` — all sufficient to
build LLVM 21. mlibc plays no role in M0. Environment used throughout:

```bash
export MOTORH=/home/posk/motorh
export MOTOR=$MOTORH/motor-os          # or the agent-tree worktree
export LLVM_SRC=$MOTORH/llvm-project
export B=$LLVM_SRC/build/bin           # our patched toolchain
```

### A.1 Clone LLVM and start a `motor` branch

Pin a version and record it. A release tag (21.1.x or newer) or a recent `main` both
work — the port is currently built on `main` @ `6d1ca7202` (clang 23.0.0git); the
diffs below were validated against that:

```bash
cd $MOTORH
git clone https://github.com/llvm/llvm-project.git   # or --depth 1 --branch llvmorg-21.1.3
cd llvm-project
git switch -c motor    # from the commit you are pinning
```

Commit each patch below separately on the `motor` branch — this is the series that
eventually goes upstream (M10).

### A.2 Patch 1 — the `motor` OS in `llvm::Triple`

**`llvm/include/llvm/TargetParser/Triple.h`** — three edits.

(1) Append `Motor` as the last `OSType` enumerator and bump `LastOSType`. In 21.1.x the
enum ends with `Vulkan`; if your checkout differs, the rule is simply "append at the
end" (the numeric values are not ABI):

```diff
     Serenity,
     Vulkan, // Vulkan SPIR-V
-    LastOSType = Vulkan
+    Motor,  // Motor OS
+    LastOSType = Motor
   };
```

(2) Add a predicate next to the other `isOS*()` helpers:

```diff
+  /// Tests whether the OS is Motor OS.
+  bool isOSMotor() const { return getOS() == Triple::Motor; }
+
   /// Tests whether the OS is Fuchsia.
   bool isOSFuchsia() const { return getOS() == Triple::Fuchsia; }
```

(3) Make emulated TLS the target default — this is the load-bearing line of the whole
patch (see the main guide, §4):

```diff
   bool hasDefaultEmulatedTLS() const {
     return isAndroid() || isOSOpenBSD() || isWindowsCygwinEnvironment() ||
-           isOHOSFamily();
+           isOHOSFamily() || isOSMotor();
   }
```

**`llvm/lib/TargetParser/Triple.cpp`** — two switch entries (keep each list's existing
alphabetical order):

```diff
 static StringRef getOSTypeName(Triple::OSType Kind) {
   switch (Kind) {
   ...
   case Triple::Mesa3D: return "mesa3d";
+  case Triple::Motor: return "motor";
   case Triple::NaCl: return "nacl";
```

```diff
 static Triple::OSType parseOS(StringRef OSName) {
   return StringSwitch<Triple::OSType>(OSName)
     ...
     .StartsWith("mesa3d", Triple::Mesa3D)
+    .StartsWith("motor", Triple::Motor)
     .StartsWith("nacl", Triple::NaCl)
```

### A.3 Patch 2 — Clang target info (predefined macros)

**`clang/lib/Basic/Targets/OSTargets.h`** — add a `MotorTargetInfo` template near the
other small OS classes (e.g. right after `FuchsiaTargetInfo`):

```cpp
// Motor OS target
template <typename Target>
class LLVM_LIBRARY_VISIBILITY MotorTargetInfo : public OSTargetInfo<Target> {
protected:
  void getOSDefines(const LangOptions &Opts, const llvm::Triple &Triple,
                    MacroBuilder &Builder) const override {
    Builder.defineMacro("__motor__");
    Builder.defineMacro("__ELF__");
    if (Opts.POSIXThreads)
      Builder.defineMacro("_REENTRANT");
  }

public:
  MotorTargetInfo(const llvm::Triple &Triple, const TargetOptions &Opts)
      : OSTargetInfo<Target>(Triple, Opts) {}
};
```

**`clang/lib/Basic/Targets.cpp`** — in `AllocateTarget`, inside
`case llvm::Triple::x86_64:`'s `switch (os)`:

```diff
   case llvm::Triple::x86_64:
     ...
     switch (os) {
     ...
+    case llvm::Triple::Motor:
+      return std::make_unique<MotorTargetInfo<X86_64TargetInfo>>(Triple, Opts);
     case llvm::Triple::Linux: {
```

### A.3b Patch 3 — minimal Clang driver toolchain (required for M0)

> An earlier revision of this appendix claimed no driver patch was needed because the
> driver falls back to `Generic_ELF` for unknown-OS ELF triples. **Verified wrong at
> M0**: that fallback (via `Generic_GCC`) has no native link job — it invokes the host
> `/usr/bin/gcc` to link (`clang: error: linker (via gcc) command failed`) — and it
> defaults to non-PIC codegen (`-mrelocation-model static` in the `-v` cc1 line),
> which cannot produce a valid static-PIE. Both are fixed by this minimal toolchain.

New file **`clang/lib/Driver/ToolChains/Motor.h`**:

```cpp
//===--- Motor.h - Motor OS ToolChain -----------------------*- C++ -*-===//
#ifndef LLVM_CLANG_LIB_DRIVER_TOOLCHAINS_MOTOR_H
#define LLVM_CLANG_LIB_DRIVER_TOOLCHAINS_MOTOR_H

#include "Gnu.h"

namespace clang {
namespace driver {
namespace toolchains {

class LLVM_LIBRARY_VISIBILITY Motor : public Generic_ELF {
public:
  Motor(const Driver &D, const llvm::Triple &Triple,
        const llvm::opt::ArgList &Args)
      : Generic_ELF(D, Triple, Args) {}

  bool HasNativeLLVMSupport() const override { return true; }
  bool isPICDefault() const override { return true; }
  bool isPIEDefault(const llvm::opt::ArgList &Args) const override {
    return true;
  }
  bool isPICDefaultForced() const override { return false; }
  const char *getDefaultLinker() const override { return "ld.lld"; }
  RuntimeLibType GetDefaultRuntimeLibType() const override {
    return ToolChain::RLT_CompilerRT;
  }
  CXXStdlibType GetDefaultCXXStdlibType() const override {
    return ToolChain::CST_Libcxx;
  }

protected:
  Tool *buildLinker() const override;
};

} // namespace toolchains
} // namespace driver
} // namespace clang

#endif
```

New file **`clang/lib/Driver/ToolChains/Motor.cpp`**:

```cpp
#include "Motor.h"

using namespace clang::driver;
using namespace clang::driver::toolchains;

Tool *Motor::buildLinker() const {
  return new tools::gnutools::Linker(*this);
}
```

**`clang/lib/Driver/CMakeLists.txt`** — add `ToolChains/Motor.cpp` to the source list.

**`clang/lib/Driver/Driver.cpp`** — add `#include "ToolChains/Motor.h"` with the other
ToolChains includes, and in `Driver::getToolChain()`'s OS switch (near
`case llvm::Triple::Fuchsia:`):

```diff
+    case llvm::Triple::Motor:
+      TC = std::make_unique<toolchains::Motor>(*this, Target, Args);
+      break;
```

Notes: `gnutools::Linker` natively handles `-static-pie` (emits
`-static -pie --no-dynamic-linker -z text`) and `-nostdlib`;
`getDefaultLinker() = "ld.lld"` resolves to the lld built next to clang, so no
`-fuse-ld` is needed and the host gcc/ld are never touched. The PIC/PIE defaults make
`-fPIE` unnecessary on the compile side.

*(Workaround while iterating without this patch: compile with an explicit `-fPIE -c`,
then link the object directly with `$B/ld.lld -static -pie --no-dynamic-linker
-e motor_start -z noexecstack --pack-dyn-relocs=none m0.o -o m0`.)*

### A.4 Build clang + lld

```bash
cd $LLVM_SRC
cmake -S llvm -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_ASSERTIONS=ON \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_TARGETS_TO_BUILD=X86 \
  -DLLVM_INCLUDE_TESTS=OFF \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
ninja -C build clang lld llvm-readelf llvm-nm llvm-ar llvm-ranlib
# (llvm-ar/llvm-ranlib are needed by the B.6 builtins build's cmake checks)
```

(Tens of minutes to ~1.5 h depending on cores; `-DLLVM_CCACHE_BUILD=ON` if ccache is
installed. Assertions stay ON while we're developing against LLVM internals.)

### A.5 Per-target driver defaults: `x86_64-unknown-motor.cfg`

Clang automatically loads `<triple>.cfg` from, among other places, the directory the
binary resides in. Create `$B/x86_64-unknown-motor.cfg` (no `-fuse-ld` — the A.3b
toolchain already defaults to the adjacent `ld.lld`):

```
-static-pie
-nostdlib
-ffreestanding
-Wl,-e,motor_start
-Wl,--pack-dyn-relocs=none
-Wl,-z,noexecstack
```

(`-nostdlib`/`-ffreestanding` are M0-appropriate; at M2 this file evolves to add the
sysroot, crt0 and libraries instead.) Verify the wiring:

```bash
$B/clang --target=x86_64-unknown-motor -v -### /dev/null 2>&1 | grep -i 'configuration file'
$B/clang --target=x86_64-unknown-motor -dM -E - </dev/null | grep motor   # __motor__ 1

# Driver sanity (A.3b): the cc1 line must show `-mrelocation-model pic -pic-level 2
# -pic-is-pie` (NOT `-mrelocation-model static`), and the link step must invoke
# $B/ld.lld directly — if you see /usr/bin/gcc, the A.3b patch is missing:
$B/clang --target=x86_64-unknown-motor -O2 -### /tmp/x.c 2>&1 | tail -2

# The critical ABI check — emulated TLS by default, no PT_TLS machinery:
printf '_Thread_local int x; int f(void){ return x; }\n' > /tmp/tls.c
$B/clang --target=x86_64-unknown-motor -O2 -S -o - /tmp/tls.c
#   expect: a call to __emutls_get_address and an __emutls_v.x object;
#   there must be NO .tdata/.tbss sections and no %fs-relative loads.
```

### A.6 The M0 test program

`m0.c` — freestanding, no libc, no compiler-rt; it initializes the VDSO vtable, writes
one line to stdout, and exits 42. The constants mirror
`src/sys/lib/moto-rt/src/lib.rs` (`RT_VERSION = 16`, vtable at
`RT_VDSO_VTABLE_VADDR = 0x21FE_FFFF_F000`, one 8-byte `AtomicU64` slot per field in
declaration order); re-derive them if `RtVdsoVtable` changes:

```c
#include <stdint.h>

#define RT_VERSION           16
#define VTABLE               0x21FEFFFFF000ULL
#define SLOT_VDSO_ENTRY      0   /* fn(u64)                         */
#define SLOT_PROC_EXIT       23  /* fn(i32) -> !                    */
#define SLOT_FS_WRITE        42  /* fn(i32, *const u8, usize) -> i64 */

static uint64_t slot(int i) { return *(volatile uint64_t *)(VTABLE + 8u * (unsigned)i); }

static const char msg[] = "M0: hello from C on Motor OS\n";
/* A global pointer forces one R_X86_64_RELATIVE entry, deliberately
 * exercising the loader's relocation path (rt.vdso/src/load.rs). */
static const char *const msg_ptr = msg;

void motor_start(void) {
    ((void (*)(uint64_t))slot(SLOT_VDSO_ENTRY))(RT_VERSION);          /* must be first */
    ((int64_t (*)(int32_t, const char *, uint64_t))slot(SLOT_FS_WRITE))(
        1, msg_ptr, sizeof msg - 1);
    ((void (*)(int32_t))slot(SLOT_PROC_EXIT))(42);
    __builtin_trap();
}
```

Build (the config file supplies everything else):

```bash
$B/clang --target=x86_64-unknown-motor -O2 m0.c -o m0
```

### A.7 The reloc audit (the actual point of M0)

The loader handles exactly `R_AMD64_RELATIVE`, rejects `PT_TLS`, and knows nothing of
`DT_RELR` or ifuncs (`rt.vdso/src/load.rs:217-260`). Audit before booting:

```bash
$B/llvm-readelf -h m0     # Type: DYN (PIE); Machine: X86-64
$B/llvm-readelf -l m0     # program headers: no INTERP, no TLS segment
$B/llvm-readelf -r m0     # relocations: R_X86_64_RELATIVE only (≥1, from msg_ptr)
$B/llvm-readelf -d m0     # dynamic section: no RELR/RELRSZ/RELRENT tags
$B/llvm-nm m0 | grep -w motor_start   # address must equal the ELF entry point (-h)
```

Any other relocation type here means a flag is wrong — fix the `.cfg`, don't patch the
loader.

### A.8 Run it on Motor OS

The imager copies the `static_dirs` tree `img_files/motor-os/` verbatim into the
image root (`src/imager/motor-os.yaml`), so test binaries go there — do **not** edit
the imager's yaml:

1. `cp m0 $MOTOR/img_files/motor-os/bin/` → lands at `/bin/m0` in the image.
2. `cd $MOTOR && make img` (or plain `make` on the first run).
3. `cd vm_images/debug && ./run-qemu.sh`.
4. In the rush shell: `m0`. Expected output, verbatim:

   ```
   M0: hello from C on Motor OS
   [m0] exited with status 42
   ```

   (rush prints the bracketed line for any nonzero exit — `src/bin/rush/src/exec.rs:163`
   — so exit code 42 is directly visible.)

### A.9 M0 exit criteria

- [ ] LLVM `motor` branch with the three commits from A.2/A.3/A.3b, pinned commit
      recorded.
- [ ] `__motor__` defined; `_Thread_local` compiles to `__emutls_get_address` with no
      flags passed (A.5).
- [ ] `m0` passes the readelf audit (A.7).
- [ ] `m0` runs on Motor: prints the line, exits 42 (A.8).
- [ ] One paragraph noting anything lld emitted that surprised the loader (goes into
      the driver-toolchain work at ~M8).
