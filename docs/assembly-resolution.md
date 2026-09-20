# Resolving the toolchain assembly

Motor OS separates the host Rust toolchain from the native assembly. The host
toolchain is keyed by the Rust and LLVM sources it is built from and by its
build configuration. An assembly adds the matching C/C++ sysroot, native
tools, libc configuration, and image overlays.

Ordinary builds use the one complete assembly whose key follows from the
selected Rust toolchain and the declared assembly inputs. Nothing is chosen
and nothing is stored: there is no selection state in the checkout.

## How the assembly is found

`src/build-motor-os.sh` installs the toolchain and its assembly side by side
under one development root:

```text
$MOTORH/toolchains/<rustup name>/
$MOTORH/assemblies/<assembly key>/
```

`src/resolve-toolchain-assembly.sh` reads the toolchain key from the stamp in
the selected rustc sysroot, derives the assembly key from that key and the
declared values, and looks for that directory beside the toolchain. Later
`make`, standard-image, development-image, and full-test invocations all go
through it, so they need neither `MOTORH` nor any earlier selection. Managed
and authoring toolchains have different keys and therefore different
assemblies.

## Commands

```sh
# Print the validated image-overlay root. This is what build scripts use.
src/resolve-toolchain-assembly.sh --resolve

# Validate the assembly and print its key, source state, and producer commit.
src/resolve-toolchain-assembly.sh --show
```

## Validation

Resolution is offline and read-only. Before a root is returned, the script:

- reads the toolchain key from the selected rustc sysroot stamp;
- derives the expected assembly key from the declared values;
- rejects producer locks and rejection markers;
- requires a regular, read-only root manifest and identical manifests in all
  four toolchain overlays;
- verifies the required sysroot and native outputs; and
- compares every recorded output digest.

It never fetches source, creates a managed checkout, modifies an assembly, or
falls back to an unkeyed staging location. Add-on overlays (Lua, ripgrep,
Helix) are no part of this validation.

## Image configuration

Tracked static image inputs remain repository-relative entries in
`static_dirs`. Assembly inputs use two separate YAML fields:

```yaml
assembly_dirs:
  - "libc"
  - "rg"
assembly_required_executables:
  - "rg/system/bin/rg"
```

These values must be normalized relative paths beneath the validated assembly
image root. A configuration containing assembly inputs fails immediately when
no root was resolved. Base images contain no assembly inputs and therefore do
not need an assembly.

Make resolves the assembly before removing an existing standard or development
VM image. Lorry and Curl derive their cross sysroot from the same root, so all
consumers in a parallel image build use one assembly.

## Troubleshooting

`no assembly <key> exists for toolchain <key>` means that this toolchain has
no assembly for the currently declared inputs: either none was built on this
host, or a declared assembly input (the mlibc commit or the native
configuration) changed since. Run `src/build-motor-os.sh`. It derives the
key, creates or reuses that exact assembly, and validates it. Older keyed
assemblies are retained for other checkouts and for diagnosis.
