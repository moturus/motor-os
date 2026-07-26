# Stage 2 system seed

`stage2-seed.toml` freezes the reviewed Stage 2 bootstrap set: 45 unique
crates.io objects and the pinned Motor `ring 0.17.14` Git tree.

`seed_system_repository.py` is the low-level host-only seeder. It requires
explicit manifest, destination, and mode arguments:

```sh
./seed_system_repository.py \
  --manifest stage2-seed.toml \
  --destination /absolute/path/to/vendor \
  --cache /absolute/path/to/download-cache \
  --mode full
```

Use `--mode minimal` for the `ring`-only fresh-fetch acceptance seed. Once the
cache has been populated, `--offline` must reproduce the same repository
without network access.

`install_stage2_seed.py` is the normal build wrapper. Its defaults generate a
canonical repository below `build/lorry/stage2/`, independently copy and
re-verify it in the Linux host and Motor image locations, and install the
corresponding configurations. A missing Linux configuration is created. An
existing one is never merged or overwritten and must already name the expected
system repository and native tools. By default the installer resolves Cargo's
host-compatible `clang` compiler and `ar` archiver once, canonicalizes their
absolute paths, and records them in the Linux configuration. Clang keeps the
current native compilation inside the one declared compiler executable; GCC
requires undeclared helper processes. Use `--host-c-compiler` and
`--host-archiver` to select another absolute pair. The generated Motor
configuration is build-owned and is replaced atomically.

Pass an unused absolute path with `--cargo-oracle-view` to materialize Cargo's
directory-source representation of the verified registry objects plus the
pinned `ring` source. The generated `.cargo/config.toml` forces Cargo's
target-specific compiler, compiler flags, archiver, and archiver flags to the
same values as Lorry's generated Linux configuration. It makes that view usable
for host-side bootstrap-oracle checks; it is not the repository format consumed
by Lorry itself.

Both scripts use Python 3.11 or newer and only its standard library, except
that the seeder invokes the host `git` executable with an argument vector to
acquire and attest the pinned Git object. They never invoke Cargo, rustup,
rustc, a shell command string, or downloaded code.

Run the fixture suite with:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The suite covers fixed source-tree digest vectors, closed manifest identities,
safe registry extraction, malicious archives and Git trees, interruption and
corruption behavior, offline reproduction, repository copying, and
configuration ownership.
