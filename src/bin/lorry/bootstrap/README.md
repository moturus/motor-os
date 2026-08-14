# Stage 2 OS-packaging seed

This directory contains host-side packaging utilities. The Lorry executable
does not call them. `src/build-motor-os.sh` uses the installer to place a
verified system dependency repository and `lorry.toml` into the generated
Motor toolchain image. That preinstalled state lets the development image
rebuild Lorry and curl offline; it is not required when Lorry is supplied
another valid configuration and repositories.

`stage2-seed.toml` freezes the packaging input: 44 crates.io objects and the
pinned Motor `cc 1.4.0` and `ring 0.17.14` Git trees. It also contains 16
lock-only packages used only when a validation test explicitly requests a
Cargo oracle view. Oracle-only packages never enter the installed Lorry
repository, its fingerprint, generated policy, or the Motor image seed.

## Packaging tools

`seed_system_repository.py` creates and verifies a Lorry-format repository on
the host:

```sh
./seed_system_repository.py \
  --manifest stage2-seed.toml \
  --destination /absolute/path/to/vendor \
  --cache /absolute/path/to/download-cache \
  --mode full
```

An online invocation may populate the checksum-pinned download cache. After
that, `--offline` reproduces the same repository without network access.
`--mode minimal` installs only patched Git objects and exists for the
fresh-repository validation lane; it is not a normal image profile.

`install_stage2_seed.py` is the OS-build wrapper. Its defaults generate a
canonical repository below `build/lorry/stage2/`, independently copy and
re-verify it in the Linux host and generated Motor image locations, and write
the corresponding configurations. These default paths are packaging layout,
not paths interpreted by the Lorry executable.

A missing Linux configuration is created. An existing configuration is never
merged or overwritten and must already name the expected system repository
and native tools. The generated Motor configuration is build-owned and is
replaced atomically. `--host-c-compiler` and `--host-archiver` select explicit
absolute host tools.

The scripts require Python 3.11 or newer and its standard library. The seeder
also invokes the host `git` executable with an argument vector to acquire and
attest pinned Git objects. It never invokes Cargo, rustup, rustc, a shell
command string, or downloaded code.

## Validation-only facilities

`install_stage2_seed.py --cargo-oracle-view PATH` materializes a disposable
Cargo directory-source view for compatibility tests. Cargo oracles compare
Lorry with independently run Cargo versions; they are not Lorry inputs or
fallback implementations. The option is not used for normal OS packaging.

The dedicated minimal Motor image builder, its YAML, VM-profile selection, and
layout assertions live in `../tests/bootstrap/`. They are test harness code,
not bootstrap packaging or product behavior.

Production packaging unit tests remain colocated in `bootstrap/tests/`:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

They cover source-tree digest vectors, manifest identities, safe extraction,
malicious archives and Git trees, interruption/corruption behavior, offline
reproduction, repository copying, and configuration ownership. Repository
integration drivers run these tests together with the separate validation
fixture tests under `../tests/bootstrap/`.
