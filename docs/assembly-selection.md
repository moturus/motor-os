# Selecting a toolchain assembly

Motor OS separates the host Rust toolchain from the native runtime assembly.
The host toolchain is keyed by its Rust, LLVM, Cargo, bootstrap, and lockfile
inputs. An assembly adds the matching C/C++ sysroot, native tools, local Motor
runtime, libc configuration, and image overlays.

Ordinary builds must use one complete assembly whose key matches both the
selected Rust toolchain and the current runtime sources. The selection is
persistent host state; it is not a repository input and is never committed.

## Automatic selection

`src/build-motor-os.sh` pins the exact assembly after producing or validating
it. Later `make`, standard-image, development-image, and full-test invocations
resolve that pin automatically.

If no pin exists, the resolver examines:

```text
${MOTORH:-<checkout parent>}/assemblies/
```

One completed assembly for the selected compiler is selected and pinned. If
several are present, an interactive invocation lists them in key order and
asks which one to use. A noninteractive invocation, including CI, stops after
listing the candidates and prints the explicit selection command. It never
chooses the newest directory by timestamp.

Selection does not weaken compatibility checks. A chosen assembly must match
the selected compiler key, the current Motor runtime-tree identity, the
declared mlibc revision, and the native configuration digest. Selecting an old
or unrelated key reports the mismatch instead of building with it.

## Commands

The selector is both the user interface and the machine interface used by
Make:

```sh
# Show every completed assembly for the selected compiler.
src/select-toolchain-assembly.sh --list

# Show and validate the current pin.
src/select-toolchain-assembly.sh --show

# Select by key or canonical absolute assembly root.
src/select-toolchain-assembly.sh --pin ASSEMBLY_KEY
src/select-toolchain-assembly.sh --pin /absolute/path/to/assemblies/ASSEMBLY_KEY

# Remove the pin for the selected compiler.
src/select-toolchain-assembly.sh --clear

# Print the validated image-overlay root. This is intended for build scripts.
src/select-toolchain-assembly.sh --resolve
```

`--pin` changes persistent state only after validating the candidate. Pins are
separate for each selected compiler key, so managed and authoring toolchains do
not replace one another's selection.

## Local state

Pins live beneath the ignored checkout-local directory:

```text
.motor-os/assembly-pins/<toolchain-key>
```

The record contains a schema, compiler key, assembly key, and canonical
absolute root. It is written privately and atomically while holding a
checkout-local lock. Symlinked state, malformed records, noncanonical paths,
and inconsistent keys are rejected.

Checkout-local state prevents separate branches or clones under one
development root from silently sharing a selection. `make clean` preserves the
pin. Removing ignored files removes it; the next build performs discovery
again. With a custom development root, keep `MOTORH` set until the build has
created the pin. The absolute root in an existing pin remains sufficient for
later builds.

## Consumer validation

Resolution is offline and read-only with respect to assemblies. Before a root
is returned, the selector:

- reads the compiler key from the selected rustc sysroot stamp;
- recomputes the current runtime content and selected lockfile identity;
- derives the expected assembly key using the canonical key implementation;
- rejects producer locks and rejection markers;
- requires a regular, read-only root manifest and identical manifests in all
  four image overlays;
- verifies the required sysroot and native outputs; and
- compares every recorded output digest.

The resolver never fetches source, creates a managed checkout, modifies an
assembly, or falls back to an unkeyed staging location.

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
no root was selected. Base images contain no assembly inputs and therefore do
not require a selection.

Make resolves an assembly before removing an existing standard or development
VM image. Lorry and Curl derive their cross sysroot from the same root, so all
consumers in a parallel image build use one pinned assembly.

## Troubleshooting

An incompatible-pin error normally means one of the runtime inputs changed
after the assembly was built. Inspect the current state and candidates:

```sh
src/select-toolchain-assembly.sh --show
src/select-toolchain-assembly.sh --list
```

If no compatible assembly exists, run `src/build-motor-os.sh`. It derives a new
content key, creates or reuses that exact assembly, validates it, and updates
the pin. Older keyed assemblies are retained for other checkouts and for
diagnosis.

If a pin names a moved or deleted development root, clear it and either select
the relocated absolute root or run discovery again:

```sh
src/select-toolchain-assembly.sh --clear
src/select-toolchain-assembly.sh --pin /new/absolute/root/assemblies/ASSEMBLY_KEY
```
