#!/usr/bin/env bash

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT_DIR/src/build-motor-os.sh"
temporary="$(mktemp -d)"
trap 'status=$?; if [ "$status" -ne 0 ] && [ -f "$temporary/build.log" ]; then
  cat "$temporary/build.log" >&2
fi; rm -rf "$temporary"' EXIT

LLVM="$temporary/llvm"
B="$temporary/bin"
SYSROOT="$temporary/sysroot"
CXX_BUILD="$temporary/build"
TOOLS=devtools/llvm
mkdir -p "$LLVM/runtimes" "$B" "$SYSROOT/motor-cxx-test"
ln -s "$(command -v clang)" "$B/clang"
ln -s "$(command -v clang++)" "$B/clang++"
printf '#define MOTOR_SYSROOT_TEST 123\n' > "$SYSROOT/motor-cxx-test/sysroot-test.h"

# Both languages must resolve a sysroot-relative include through real CMake
# compiler invocations; the ordinary explicit Motor include path cannot help.
cat > "$LLVM/runtimes/check.c" <<'EOF'
#include <sysroot-test.h>
int motor_c_test(void) { return MOTOR_SYSROOT_TEST; }
EOF
cat > "$LLVM/runtimes/check.cpp" <<'EOF'
#include <sysroot-test.h>
int motor_cxx_test() { return MOTOR_SYSROOT_TEST; }
EOF
cat > "$LLVM/runtimes/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.20)
project(MotorRuntimeSysroot C CXX)
foreach(runtime unwind cxxabi cxx)
  add_library(${runtime} STATIC check.c check.cpp)
  target_compile_options(${runtime} PRIVATE "SHELL:-isystem =/motor-cxx-test")
  install(TARGETS ${runtime} ARCHIVE DESTINATION lib COMPONENT ${runtime})
  add_custom_target(install-${runtime}
    COMMAND "${CMAKE_COMMAND}" --install "${CMAKE_BINARY_DIR}" --component ${runtime})
endforeach()
set_target_properties(cxxabi PROPERTIES OUTPUT_NAME "c++abi")
set_target_properties(cxx PROPERTIES OUTPUT_NAME "c++")
EOF

build_cxx_runtimes > "$temporary/build.log" 2>&1

echo "test-toolchain-cxx-sysroot PASS"
